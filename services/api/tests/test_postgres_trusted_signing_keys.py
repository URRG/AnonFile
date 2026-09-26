"""M47 immutable trusted Ed25519 public-key registry tests."""
from __future__ import annotations

import base64
import copy
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
from queue import Empty, Queue
import secrets
import time
from types import SimpleNamespace

import pytest

from app.postgres_trusted_signing_keys import (
    PostgresTrustedSigningKeyAuthority,
    PostgresTrustedSigningKeyError,
    TrustedSigningKey,
)

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def public_key() -> str:
    return "ed25519pub:v1:" + base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


TENANT = opaque("tenantref:v1:")
OTHER = opaque("tenantref:v1:")


class Database:
    def __init__(self) -> None:
        self.keys, self.fences, self.now = {}, {}, NOW


class Connection:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.keys, self.fences = copy.deepcopy(database.keys), copy.deepcopy(database.fences)
        self.autocommit, self.closed, self.rolled_back = True, False, False
        self.info = SimpleNamespace(transaction_status=SimpleNamespace(name="IDLE"))

    def cursor(self):
        return Cursor(self)

    def commit(self) -> None:
        self.database.keys, self.database.fences = self.keys, self.fences
        self.info.transaction_status = SimpleNamespace(name="IDLE")

    def rollback(self) -> None:
        self.rolled_back = True
        self.info.transaction_status = SimpleNamespace(name="IDLE")

    def close(self) -> None:
        self.closed = True


class Cursor:
    def __init__(self, connection: Connection) -> None:
        self.connection, self._row, self.rowcount = connection, None, -1

    def fetchone(self):
        return self._row

    def execute(self, sql: str, params=()) -> None:
        query = " ".join(sql.split())
        self._row, self.rowcount = None, -1
        if query in {"BEGIN", "COMMIT", "ROLLBACK"}:
            self.connection.info.transaction_status = SimpleNamespace(
                name="INTRANS" if query == "BEGIN" else "IDLE")
        elif query == "SHOW transaction_isolation":
            self._row = ("read committed",)
        elif query == "SELECT date_trunc('second', clock_timestamp())":
            self._row = (self.connection.database.now,)
        elif query.startswith("INSERT INTO anonflow_trusted_signing_keys"):
            tenant, actor, key, role, pub, before, expiry = params
            if key not in {stored[2] for stored in self.connection.keys.values()}:
                self.connection.keys[(tenant, key)] = tuple(params)
                self._row, self.rowcount = (key,), 1
        elif query.startswith("SELECT tenant_ref,actor_ref,key_ref,role,public_key,not_before,expires_at"):
            self._row = self.connection.keys.get(tuple(params))
        elif query.startswith("SELECT generation,state,event_ref,changed_at"):
            values = [value for (tenant, key, _), value in self.connection.fences.items()
                      if (tenant, key) == tuple(params)]
            self._row = max(values, key=lambda value: value[0]) if values else None
        elif query.startswith("INSERT INTO anonflow_trusted_signing_key_fences"):
            if len(params) == 3:
                tenant, key, changed = params
                generation, state, event = 0, "ACTIVE", None
            else:
                tenant, key, generation, event, changed = params
                state = "REVOKED"
            marker = (tenant, key, generation)
            if marker not in self.connection.fences:
                self.connection.fences[marker] = (generation, state, event, changed)
                self.rowcount = 1
        else:
            raise AssertionError(query)


def authority(database: Database) -> PostgresTrustedSigningKeyAuthority:
    return PostgresTrustedSigningKeyAuthority(lambda: Connection(database))


def key_kwargs():
    return dict(tenant_ref=TENANT, actor_ref=opaque("actorref:v1:"), key_ref=opaque("signingkeyref:v1:"),
                role="SERVICE_ISSUER", public_key=public_key(), not_before=NOW - timedelta(minutes=1),
                expires_at=NOW + timedelta(minutes=5))


def key(**changes) -> TrustedSigningKey:
    values = key_kwargs()
    values.update(changes)
    return TrustedSigningKey(**values)


def test_creation_is_exact_idempotent_and_rejects_cross_tenant_actor_role_and_public_key_replay():
    database, service, item = Database(), None, key()
    service = authority(database)
    assert service.create(item).state == "ACTIVE"
    assert service.create(item).key == item
    for changed in ({"tenant_ref": OTHER}, {"actor_ref": opaque("actorref:v1:")},
                    {"role": "PRIVACY_REVIEWER"}, {"public_key": public_key()}):
        with pytest.raises(PostgresTrustedSigningKeyError):
            service.create(key(key_ref=item.key_ref, **changed))


@pytest.mark.parametrize("role", ("PRIVACY_REVIEWER", "RELEASE_AUTHORIZER", "SERVICE_ISSUER"))
def test_exact_roles_are_accepted(role):
    assert key(role=role).role == role


@pytest.mark.parametrize("bad", ("ed25519pub:v1:bad", "ed25519pub:v1:" + "A" * 42 + "B",
                                  "ed25519pub:v1:" + secrets.token_urlsafe(32)[:-1] + "!"))
def test_public_key_must_be_canonical_32_byte_ed25519_encoding(bad):
    with pytest.raises(PostgresTrustedSigningKeyError):
        key(public_key=bad)


def test_lock_active_rejects_idle_cursor_and_role_actor_generation_or_validity_drift():
    database, service, item = Database(), None, key()
    service = authority(database)
    service.create(item)
    with pytest.raises(PostgresTrustedSigningKeyError):
        service.lock_active(Connection(database).cursor(), tenant_ref=TENANT, actor_ref=item.actor_ref,
                            key_ref=item.key_ref, role=item.role, expected_generation=0,
                            expected_public_key=item.public_key)
    connection, cursor = Connection(database), None
    cursor = connection.cursor(); cursor.execute("BEGIN")
    assert service.lock_active(cursor, tenant_ref=TENANT, actor_ref=item.actor_ref, key_ref=item.key_ref,
                               role=item.role, expected_generation=0, expected_public_key=item.public_key).state == "ACTIVE"
    with pytest.raises(PostgresTrustedSigningKeyError):
        service.lock_active(cursor, tenant_ref=TENANT, actor_ref=opaque("actorref:v1:"), key_ref=item.key_ref,
                            role=item.role, expected_generation=0, expected_public_key=item.public_key)
    with pytest.raises(PostgresTrustedSigningKeyError):
        service.lock_active(cursor, tenant_ref=TENANT, actor_ref=item.actor_ref, key_ref=item.key_ref,
                            role="PRIVACY_REVIEWER", expected_generation=0, expected_public_key=item.public_key)
    database.now = item.expires_at
    with pytest.raises(PostgresTrustedSigningKeyError):
        service.lock_active(cursor, tenant_ref=TENANT, actor_ref=item.actor_ref, key_ref=item.key_ref,
                            role=item.role, expected_generation=0, expected_public_key=item.public_key)


def test_revocation_is_terminal_idempotent_and_fences_all_future_reads():
    database, service, item = Database(), None, key()
    service = authority(database); service.create(item)
    event = opaque("signingkeyfence:v1:")
    revoked = service.revoke(tenant_ref=TENANT, actor_ref=item.actor_ref, key_ref=item.key_ref,
                              role=item.role, expected_generation=0, event_ref=event)
    assert revoked.state == "REVOKED"
    assert service.revoke(tenant_ref=TENANT, actor_ref=item.actor_ref, key_ref=item.key_ref,
                          role=item.role, expected_generation=0, event_ref=event) == revoked
    with pytest.raises(PostgresTrustedSigningKeyError):
        service.fence(tenant_ref=TENANT, actor_ref=item.actor_ref, key_ref=item.key_ref, role=item.role,
                      expected_generation=0, expected_public_key=item.public_key)


@pytest.fixture
def postgres_authority():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "014_m47_trusted_signing_keys.sql"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(migration.read_text(encoding="utf-8"))
        connection.execute(migration.read_text(encoding="utf-8"))
    return dsn, psycopg, PostgresTrustedSigningKeyAuthority(lambda: psycopg.connect(dsn, autocommit=True))


def test_postgres_adversarial_tenant_role_actor_replay_and_revoke_race(postgres_authority):
    dsn, psycopg, service = postgres_authority
    item = key(not_before=datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=1),
               expires_at=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5))
    assert service.create(item).generation == 0
    with pytest.raises(PostgresTrustedSigningKeyError):
        service.create(key(tenant_ref=OTHER, key_ref=item.key_ref))
    with pytest.raises(PostgresTrustedSigningKeyError):
        service.fence(tenant_ref=TENANT, actor_ref=opaque("actorref:v1:"), key_ref=item.key_ref,
                      role=item.role, expected_generation=0, expected_public_key=item.public_key)
    with pytest.raises(PostgresTrustedSigningKeyError):
        service.fence(tenant_ref=TENANT, actor_ref=item.actor_ref, key_ref=item.key_ref,
                      role="RELEASE_AUTHORIZER", expected_generation=0, expected_public_key=item.public_key)
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(PostgresTrustedSigningKeyError):
            service.lock_active(connection.cursor(), tenant_ref=TENANT, actor_ref=item.actor_ref,
                                key_ref=item.key_ref, role=item.role, expected_generation=0,
                                expected_public_key=item.public_key)
    events = (opaque("signingkeyfence:v1:"), opaque("signingkeyfence:v1:"))
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(service.revoke, tenant_ref=TENANT, actor_ref=item.actor_ref,
                                   key_ref=item.key_ref, role=item.role, expected_generation=0, event_ref=event)
                   for event in events]
        outcomes = []
        for future in futures:
            try: outcomes.append(future.result(timeout=5))
            except PostgresTrustedSigningKeyError: outcomes.append("REJECTED")
    revoked = [outcome for outcome in outcomes if outcome != "REJECTED"]
    assert [outcome.state for outcome in revoked].count("REVOKED") == outcomes.count("REJECTED") == 1
    assert revoked[0].changed_at.microsecond == 0


def test_postgres_active_reader_waits_for_committed_revocation_then_rejects(postgres_authority):
    dsn, psycopg, service = postgres_authority
    now = datetime.now(UTC).replace(microsecond=0)
    item = key(not_before=now - timedelta(seconds=1), expires_at=now + timedelta(minutes=5))
    service.create(item)
    with psycopg.connect(dsn, autocommit=True) as blocker:
        cursor = blocker.cursor(); cursor.execute("BEGIN")
        cursor.execute("SELECT key_ref FROM anonflow_trusted_signing_keys WHERE tenant_ref=%s AND key_ref=%s FOR UPDATE",
                       (item.tenant_ref, item.key_ref))
        cursor.execute("INSERT INTO anonflow_trusted_signing_key_fences "
                       "(tenant_ref,key_ref,generation,state,event_ref) VALUES (%s,%s,1,'REVOKED',%s)",
                       (item.tenant_ref, item.key_ref, opaque("signingkeyfence:v1:")))
        pids: Queue[int] = Queue()
        def connect():
            connection = psycopg.connect(dsn, autocommit=True)
            pids.put(connection.execute("SELECT pg_backend_pid()").fetchone()[0])
            return connection
        racing = PostgresTrustedSigningKeyAuthority(connect)
        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(racing.fence, tenant_ref=item.tenant_ref, actor_ref=item.actor_ref,
                                     key_ref=item.key_ref, role=item.role, expected_generation=0,
                                     expected_public_key=item.public_key)
            try: pid = pids.get(timeout=3)
            except Empty: pytest.fail("reader did not connect")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", (pid,))
                if cursor.fetchone() == ("Lock",): break
                time.sleep(.02)
            else: pytest.fail("reader did not wait for stable key lock")
            cursor.execute("COMMIT")
            with pytest.raises(PostgresTrustedSigningKeyError): result.result(timeout=5)
