from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import secrets

import pytest

from app.postgres_candidate_custody import (CandidateCustodyIntent,
                                            PostgresCandidateCustodyAuthority,
                                            PostgresCandidateCustodyError)

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def digest() -> str:
    return "sha256:" + secrets.token_hex(32)


TENANT = opaque("tenantref:v1:")
OTHER = opaque("tenantref:v1:")


class Database:
    def __init__(self):
        self.intents, self.fences, self.now = {}, {}, NOW


class Connection:
    def __init__(self, database):
        self.database = database
        self.intents, self.fences = copy.deepcopy(database.intents), copy.deepcopy(database.fences)
        self.autocommit, self.closed, self.rolled_back = True, False, False
    def cursor(self):
        return Cursor(self)

    def commit(self):
        self.database.intents = self.intents
        self.database.fences = self.fences

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class Cursor:
    def __init__(self, connection):
        self.connection = connection
        self._row = None
        self.rowcount = -1

    def fetchone(self):
        return self._row

    def execute(self, sql, params=()):
        query = " ".join(sql.split())
        self._row = None
        self.rowcount = -1
        if query in {"BEGIN", "COMMIT", "ROLLBACK"}:
            return
        if query == "SHOW transaction_isolation":
            self._row = ("read committed",)
            return
        if query == "SELECT date_trunc('second', clock_timestamp())":
            self._row = (self.connection.database.now,)
            return
        if query.startswith("INSERT INTO anonflow_candidate_custody_intents"):
            key = params[0], params[1]
            if params[1] not in {value[1] for value in self.connection.intents.values()}:
                self.connection.intents[key] = tuple(params)
                self._row = (params[1],)
                self.rowcount = 1
            return
        if query.startswith("SELECT tenant_ref,custody_ref,artifact_digest"):
            self._row = self.connection.intents.get(tuple(params))
            return
        if query.startswith("SELECT generation,state,event_ref,changed_at"):
            values = [value for (tenant, ref, _), value in self.connection.fences.items() if (tenant, ref) == tuple(params)]
            self._row = max(values, key=lambda value: value[0]) if values else None
            return
        if query.startswith("INSERT INTO anonflow_candidate_custody_fences"):
            if len(params) == 3:
                tenant, ref, changed = params
                generation, state, event = 0, "PENDING_UPLOAD", None
            else:
                tenant, ref, generation, state, event, changed = params
            key = tenant, ref, generation
            if key not in self.connection.fences:
                self.connection.fences[key] = (generation, state, event, changed)
                self.rowcount = 1
            return
        raise AssertionError(query)


def authority(database):
    return PostgresCandidateCustodyAuthority(lambda: Connection(database))


def intent_kwargs():
    return dict(tenant_ref=TENANT, custody_ref=opaque("custodyref:v1:"), artifact_digest=digest(), run_digest=digest(),
                policy_digest=digest(), schema_digest=digest(), provenance_digest=digest(), byte_count=11,
                expires_at=NOW + timedelta(minutes=5))


def intent(**changes):
    values = intent_kwargs()
    values.update(changes)
    return CandidateCustodyIntent(**values)


def test_intent_is_canonical_exact_replay_and_tenant_fenced():
    store = Database()
    item = intent()
    service = authority(store)
    assert service.create(item).state == "PENDING_UPLOAD"
    assert service.create(item).intent == item
    with pytest.raises(PostgresCandidateCustodyError): service.create(intent(custody_ref=item.custody_ref, artifact_digest=digest()))
    with pytest.raises(PostgresCandidateCustodyError): service.create(intent(tenant_ref=OTHER, custody_ref=item.custody_ref))


@pytest.mark.parametrize("change", ({"byte_count": 0}, {"byte_count": True}, {"artifact_digest": "sha256:bad"}))
def test_bad_metadata_fails_before_database_mutation(change):
    with pytest.raises(PostgresCandidateCustodyError):
        CandidateCustodyIntent(**{**intent_kwargs(), **change})


def test_expired_create_rolls_back_without_a_partial_intent():
    store = Database()
    item = intent(expires_at=NOW)
    with pytest.raises(PostgresCandidateCustodyError):
        authority(store).create(item)
    assert store.intents == {}
    assert store.fences == {}


def test_expiry_and_terminal_fence_are_fail_closed_and_idempotent():
    store = Database()
    item = intent()
    service = authority(store)
    service.create(item)
    store.now = item.expires_at
    with pytest.raises(PostgresCandidateCustodyError):
        service.fence(tenant_ref=TENANT, custody_ref=item.custody_ref, expected_generation=0, expected_intent_digest=item.intent_digest)
    terminal = service.terminal(tenant_ref=TENANT, custody_ref=item.custody_ref, expected_generation=0,
                                state="EXPIRED", event_ref=opaque("custodyfence:v1:"))
    assert service.terminal(tenant_ref=TENANT, custody_ref=item.custody_ref, expected_generation=0,
                            state="EXPIRED", event_ref=terminal.event_ref) == terminal
    with pytest.raises(PostgresCandidateCustodyError):
        service.terminal(tenant_ref=TENANT, custody_ref=item.custody_ref, expected_generation=0,
                         state="REVOKED", event_ref=opaque("custodyfence:v1:"))


@pytest.fixture
def postgres_authority():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "012_m45b1_candidate_custody.sql"
    with psycopg.connect(dsn, autocommit=True) as connection:
        # Applying twice is required because deployment migration runners may
        # retry after process interruption.
        connection.execute(migration.read_text(encoding="utf-8"))
        connection.execute(migration.read_text(encoding="utf-8"))
    return dsn, psycopg, PostgresCandidateCustodyAuthority(
        lambda: psycopg.connect(dsn, autocommit=True))


def test_postgres_replay_and_terminal_race_are_serialized(postgres_authority):
    _, _, service = postgres_authority
    item = intent(expires_at=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5))
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(service.create, item) for _ in range(2)]
        results = [future.result(timeout=5) for future in futures]
    assert results[0] == results[1]
    event_one = opaque("custodyfence:v1:")
    event_two = opaque("custodyfence:v1:")
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [
            executor.submit(service.terminal, tenant_ref=TENANT, custody_ref=item.custody_ref,
                            expected_generation=0, state="QUARANTINED", event_ref=event_one),
            executor.submit(service.terminal, tenant_ref=TENANT, custody_ref=item.custody_ref,
                            expected_generation=0, state="REVOKED", event_ref=event_two),
        ]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result(timeout=5).state)
            except PostgresCandidateCustodyError:
                outcomes.append("REJECTED")
    assert outcomes.count("REJECTED") == 1
    assert len(set(outcomes) & {"QUARANTINED", "REVOKED"}) == 1


def test_postgres_tenant_collision_replay_lock_and_expiry_are_fail_closed(postgres_authority):
    _, _, service = postgres_authority
    item = intent(expires_at=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5))
    service.create(item)
    with pytest.raises(PostgresCandidateCustodyError):
        service.create(intent(tenant_ref=OTHER, custody_ref=item.custody_ref))
    with pytest.raises(PostgresCandidateCustodyError):
        service.create(intent(custody_ref=item.custody_ref, artifact_digest=digest()))
    with pytest.raises(PostgresCandidateCustodyError):
        service.fence(tenant_ref=OTHER, custody_ref=item.custody_ref,
                      expected_generation=0, expected_intent_digest=item.intent_digest)

    expired = intent(expires_at=datetime.now(UTC).replace(microsecond=0) - timedelta(seconds=1))
    with pytest.raises(PostgresCandidateCustodyError):
        service.create(expired)

    # Expiry fencing is exercised by a row whose clock-valid creation is
    # advanced past its deadline. Direct SQL is used only to avoid a test sleep.
    expiring = intent(expires_at=datetime.now(UTC).replace(microsecond=0) + timedelta(seconds=1))
    service.create(expiring)
    import time
    time.sleep(1.1)
    with pytest.raises(PostgresCandidateCustodyError):
        service.fence(tenant_ref=TENANT, custody_ref=expiring.custody_ref,
                      expected_generation=0, expected_intent_digest=expiring.intent_digest)
    result = service.terminal(tenant_ref=TENANT, custody_ref=expiring.custody_ref,
                              expected_generation=0, state="EXPIRED",
                              event_ref=opaque("custodyfence:v1:"))
    assert result.state == "EXPIRED"
