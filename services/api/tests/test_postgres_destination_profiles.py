"""M45a2 destination-profile ledger tests, including a live PostgreSQL fence race."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
from queue import Empty, Queue
import secrets
import time

import pytest

from app.postgres_destination_profiles import (DestinationProfile,
                                               PostgresDestinationProfileAuthority,
                                               PostgresDestinationProfileError)

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def digest() -> str:
    return "sha256:" + secrets.token_hex(32)


TENANT = opaque("tenantref:v1:")
OTHER = opaque("tenantref:v1:")


class Database:
    def __init__(self) -> None:
        self.identities = {}
        self.profiles = {}
        self.fences = {}
        self.now = NOW
        self.advance_after_fence = False


class Connection:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.identities = copy.deepcopy(database.identities)
        self.profiles = copy.deepcopy(database.profiles)
        self.fences = copy.deepcopy(database.fences)
        self.autocommit = True
        self.closed = self.rolled_back = False

    def cursor(self) -> "Cursor":
        return Cursor(self)

    def commit(self) -> None:
        self.database.identities = self.identities
        self.database.profiles = self.profiles
        self.database.fences = self.fences

    def rollback(self) -> None:
        self.rolled_back = True

    def close(self) -> None:
        self.closed = True


class Cursor:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self._row = None
        self.rowcount = -1

    def fetchone(self):
        return self._row
    def execute(self, sql: str, params=()) -> None:
        query = " ".join(sql.split())
        self._row, self.rowcount = None, -1
        if query in {"BEGIN", "COMMIT", "ROLLBACK"}:
            return
        if query == "SHOW transaction_isolation":
            self._row = ("read committed",)
            return
        if query == "SELECT date_trunc('second', clock_timestamp())":
            self._row = (self.connection.database.now,)
            return
        if query.startswith("INSERT INTO anonflow_destination_identities"):
            tenant, ref = params
            if ref not in self.connection.identities:
                self.connection.identities[ref] = tenant; self._row = (ref,); self.rowcount = 1
            return
        if query.startswith("SELECT tenant_ref,destination_ref FROM anonflow_destination_identities"):
            ref, = params; tenant = self.connection.identities.get(ref)
            self._row = None if tenant is None else (tenant, ref); return
        if query.startswith("INSERT INTO anonflow_destination_profiles"):
            tenant, ref, version, profile_digest, not_before, expires_at = params
            key = tenant, ref, version
            if key not in self.connection.profiles:
                self.connection.profiles[key] = (tenant, ref, version, profile_digest, not_before, expires_at)
                self._row = (version,); self.rowcount = 1
            return
        if query.startswith("SELECT tenant_ref,destination_ref,version,profile_digest,not_before,expires_at") and "ORDER BY version DESC" in query:
            tenant, ref = params
            options = [value for (item_tenant, item_ref, _), value in self.connection.profiles.items()
                       if (item_tenant, item_ref) == (tenant, ref)]
            self._row = max(options, key=lambda value: value[2]) if options else None; return
        if query.startswith("SELECT tenant_ref,destination_ref,version,profile_digest,not_before,expires_at"):
            self._row = self.connection.profiles.get(tuple(params)); return
        if query.startswith("SELECT generation,state,event_ref,changed_at"):
            tenant, ref, version = params
            values = [value for (a,b,c,_), value in self.connection.fences.items() if (a,b,c) == (tenant,ref,version)]
            self._row = max(values, key=lambda value: value[0]) if values else None; return
        if query.startswith("INSERT INTO anonflow_destination_profile_fences"):
            if len(params) == 4:
                tenant, ref, version, changed = params; generation, state, event = 0, "ACTIVE", None
            else:
                tenant, ref, version, generation, state, event, changed = params
            key = tenant, ref, version, generation
            if key not in self.connection.fences:
                self.connection.fences[key] = (generation, state, event, changed); self.rowcount = 1
                if generation == 0 and self.connection.database.advance_after_fence:
                    self.connection.database.now = self.connection.profiles[(tenant,ref,version)][5]
            return
        raise AssertionError(query)


def adapter(database: Database):
    connections = []
    def connect():
        connection = Connection(database); connections.append(connection); return connection
    return PostgresDestinationProfileAuthority(connect), connections


def profile(**changes) -> DestinationProfile:
    values = dict(tenant_ref=TENANT, destination_ref=opaque("destinationref:v1:"), version=1,
                  profile_digest=digest(), not_before=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=5))
    values.update(changes)
    return DestinationProfile(**values)


def test_create_is_exact_idempotent_and_cannot_cross_tenant_destination_owner():
    authority, connections = adapter(Database())
    item = profile()
    assert authority.create(item).generation == 0
    assert authority.create(item).profile == item
    assert authority.fence(tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                           expected_generation=0, expected_profile_digest=item.profile_digest).profile == item
    with pytest.raises(PostgresDestinationProfileError):
        authority.create(profile(tenant_ref=OTHER, destination_ref=item.destination_ref))
    with pytest.raises(PostgresDestinationProfileError):
        authority.create(profile(destination_ref=item.destination_ref, profile_digest=digest()))
    assert all(item.closed for item in connections)


def test_active_window_digest_and_terminal_fence_fail_closed():
    database = Database(); authority, _ = adapter(database); item = profile(); authority.create(item)
    with pytest.raises(PostgresDestinationProfileError):
        authority.fence(tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                        expected_generation=0, expected_profile_digest=digest())
    database.now = item.expires_at
    with pytest.raises(PostgresDestinationProfileError):
        authority.fence(tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                        expected_generation=0, expected_profile_digest=item.profile_digest)
    terminal = authority.terminal(tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                                  expected_generation=0, state="REVOKED", event_ref=opaque("destinationfence:v1:"))
    assert terminal.state == "REVOKED"
    assert authority.terminal(tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                              expected_generation=0, state="REVOKED", event_ref=terminal.event_ref) == terminal


def test_rotation_requires_exact_next_version_and_deactivates_old_profile_before_use():
    authority, _ = adapter(Database())
    item = profile()
    authority.create(item)
    successor = profile(destination_ref=item.destination_ref, version=2)
    with pytest.raises(PostgresDestinationProfileError):
        authority.create(successor)
    deactivated = authority.terminal(tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                                     expected_generation=0, state="DEACTIVATED",
                                     event_ref=opaque("destinationfence:v1:"))
    assert deactivated.state == "DEACTIVATED"
    assert authority.create(successor).generation == 0
    with pytest.raises(PostgresDestinationProfileError):
        authority.fence(tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                        expected_generation=0, expected_profile_digest=item.profile_digest)
    assert authority.fence(tenant_ref=TENANT, destination_ref=item.destination_ref, version=2,
                           expected_generation=0, expected_profile_digest=successor.profile_digest).profile == successor
    # A duplicate historical provision request is an exact replay only; it
    # reports the deactivated history and cannot make v1 usable again.
    assert authority.create(item) == deactivated
    with pytest.raises(PostgresDestinationProfileError):
        authority.create(profile(destination_ref=item.destination_ref, version=4))
    authority.terminal(tenant_ref=TENANT, destination_ref=successor.destination_ref, version=2,
                       expected_generation=0, state="REVOKED", event_ref=opaque("destinationfence:v1:"))
    with pytest.raises(PostgresDestinationProfileError):
        authority.create(profile(destination_ref=item.destination_ref, version=3))


def test_lock_active_requires_read_committed_and_stable_profile_lock():
    database = Database()
    authority, _ = adapter(database)
    item = profile()
    authority.create(item)
    connection = Connection(database)
    cursor = connection.cursor()
    cursor.execute("BEGIN")
    assert authority.lock_active(cursor, tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                                 expected_generation=0, expected_profile_digest=item.profile_digest).generation == 0
    database.now = item.expires_at
    with pytest.raises(PostgresDestinationProfileError):
        authority.lock_active(cursor, tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                              expected_generation=0, expected_profile_digest=item.profile_digest)


@pytest.fixture
def postgres_authority():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "010_m45a2_destination_profiles.sql"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(migration.read_text(encoding="utf-8"))
    return dsn, psycopg, PostgresDestinationProfileAuthority(
        lambda: psycopg.connect(dsn, autocommit=True))


def test_postgres_destination_profile_fence_race_observes_terminal_generation(postgres_authority):
    dsn, psycopg, authority = postgres_authority
    item = profile(expires_at=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5))
    authority.create(item)
    with psycopg.connect(dsn, autocommit=True) as repeatable:
        cursor = repeatable.cursor()
        cursor.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        with pytest.raises(PostgresDestinationProfileError):
            authority.lock_active(cursor, tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                                  expected_generation=0, expected_profile_digest=item.profile_digest)
        cursor.execute("ROLLBACK")
    event = opaque("destinationfence:v1:")
    with psycopg.connect(dsn, autocommit=True) as blocker:
        cursor = blocker.cursor()
        cursor.execute("BEGIN")
        cursor.execute(
            "SELECT version FROM anonflow_destination_profiles WHERE tenant_ref=%s "
            "AND destination_ref=%s AND version=%s FOR UPDATE",
            (TENANT, item.destination_ref, 1))
        cursor.execute(
            "INSERT INTO anonflow_destination_profile_fences "
            "(tenant_ref,destination_ref,version,generation,state,event_ref) "
            "VALUES (%s,%s,%s,1,'REVOKED',%s)",
            (TENANT, item.destination_ref, 1, event))
        pids: Queue[int] = Queue()

        def connect():
            connection = psycopg.connect(dsn, autocommit=True)
            with connection.cursor() as worker:
                worker.execute("SELECT pg_backend_pid()")
                pids.put(worker.fetchone()[0])
            return connection

        racing = PostgresDestinationProfileAuthority(connect)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(racing.fence, tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                                     expected_generation=0, expected_profile_digest=item.profile_digest)
            try:
                pid = pids.get(timeout=3)
            except Empty:
                cursor.execute("ROLLBACK")
                with pytest.raises(PostgresDestinationProfileError):
                    future.result(timeout=5)
                pytest.fail("worker did not establish a PostgreSQL connection")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", (pid,))
                if cursor.fetchone() == ("Lock",):
                    break
                time.sleep(.02)
            else:
                cursor.execute("ROLLBACK")
                with pytest.raises((PostgresDestinationProfileError, TimeoutError)):
                    future.result(timeout=5)
                pytest.fail("worker did not block on stable profile lock")
            cursor.execute("COMMIT")
            with pytest.raises(PostgresDestinationProfileError):
                future.result(timeout=5)


def test_postgres_rotation_blocks_old_reader_until_new_version_is_current(postgres_authority):
    dsn, psycopg, authority = postgres_authority
    item = profile(expires_at=datetime.now(UTC).replace(microsecond=0) + timedelta(minutes=5))
    authority.create(item)
    authority.terminal(tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                       expected_generation=0, state="DEACTIVATED", event_ref=opaque("destinationfence:v1:"))
    successor = profile(destination_ref=item.destination_ref, version=2, expires_at=item.expires_at)
    with psycopg.connect(dsn, autocommit=True) as blocker:
        cursor = blocker.cursor()
        cursor.execute("BEGIN")
        cursor.execute(
            "SELECT destination_ref FROM anonflow_destination_identities "
            "WHERE destination_ref=%s FOR UPDATE", (item.destination_ref,))
        cursor.execute(
            "INSERT INTO anonflow_destination_profiles "
            "(tenant_ref,destination_ref,version,profile_digest,not_before,expires_at) "
            "VALUES (%s,%s,%s,%s,%s,%s)",
            (TENANT, item.destination_ref, 2, successor.profile_digest,
             successor.not_before, successor.expires_at))
        cursor.execute(
            "INSERT INTO anonflow_destination_profile_fences "
            "(tenant_ref,destination_ref,version,generation,state,event_ref) "
            "VALUES (%s,%s,2,0,'ACTIVE',NULL)", (TENANT, item.destination_ref))
        pids: Queue[int] = Queue()

        def connect():
            connection = psycopg.connect(dsn, autocommit=True)
            with connection.cursor() as worker:
                worker.execute("SELECT pg_backend_pid()")
                pids.put(worker.fetchone()[0])
            return connection

        racing = PostgresDestinationProfileAuthority(connect)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(racing.fence, tenant_ref=TENANT, destination_ref=item.destination_ref, version=1,
                                     expected_generation=0, expected_profile_digest=item.profile_digest)
            try:
                pid = pids.get(timeout=3)
            except Empty:
                cursor.execute("ROLLBACK")
                with pytest.raises(PostgresDestinationProfileError):
                    future.result(timeout=5)
                pytest.fail("reader did not establish a PostgreSQL connection")
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", (pid,))
                if cursor.fetchone() == ("Lock",):
                    break
                time.sleep(.02)
            else:
                cursor.execute("ROLLBACK")
                with pytest.raises((PostgresDestinationProfileError, TimeoutError)):
                    future.result(timeout=5)
                pytest.fail("reader did not block on destination identity lock")
            cursor.execute("COMMIT")
            with pytest.raises(PostgresDestinationProfileError):
                future.result(timeout=5)
