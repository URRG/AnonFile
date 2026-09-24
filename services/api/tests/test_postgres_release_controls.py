"""M45a1 fake PostgreSQL tests for immutable control snapshots/fences."""
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

from app.postgres_release_controls import (
    PostgresReleaseControlAuthority,
    PostgresReleaseControlError,
    ReleaseControlSnapshot,
)

NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def digest() -> str:
    return "sha256:" + secrets.token_hex(32)


TENANT = opaque("tenantref:v1:")
OTHER = opaque("tenantref:v1:")


class Database:
    def __init__(self) -> None:
        self.snapshots = {}
        self.fences = {}
        self.now = NOW
        self.advance_after_initial_fence = False


class Connection:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.snapshots = copy.deepcopy(database.snapshots)
        self.fences = copy.deepcopy(database.fences)
        self.autocommit = True
        self.committed = False
        self.rolled_back = False
        self.closed = False

    def cursor(self) -> "Cursor":
        return Cursor(self)

    def commit(self) -> None:
        self.database.snapshots = self.snapshots
        self.database.fences = self.fences
        self.committed = True

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
        normalized = " ".join(sql.split())
        self._row = None
        self.rowcount = -1
        if normalized in {"BEGIN", "COMMIT", "ROLLBACK"}:
            return
        if normalized == "SELECT date_trunc('second', clock_timestamp())":
            self._row = (self.connection.database.now,)
            return
        if normalized == "SHOW transaction_isolation":
            self._row = ("read committed",)
            return
        if normalized.startswith("INSERT INTO anonflow_release_control_snapshots"):
            tenant, snapshot_ref, control_digest, expires_at = params
            key = (tenant, snapshot_ref)
            if snapshot_ref not in {item[1] for item in self.connection.snapshots}:
                self.connection.snapshots[key] = (tenant, snapshot_ref, control_digest, expires_at)
                self._row = (snapshot_ref,)
                self.rowcount = 1
            else:
                self.rowcount = 0
            return
        if normalized.startswith("SELECT tenant_ref, snapshot_ref, control_digest, expires_at"):
            tenant, snapshot_ref = params
            self._row = self.connection.snapshots.get((tenant, snapshot_ref))
            return
        if normalized.startswith("SELECT generation, state, event_ref, changed_at"):
            tenant, snapshot_ref = params
            options = [value for (item_tenant, item_ref, _), value in self.connection.fences.items()
                       if (item_tenant, item_ref) == (tenant, snapshot_ref)]
            if options:
                self._row = max(options, key=lambda value: value[0])
            return
        if normalized.startswith("INSERT INTO anonflow_release_control_fences"):
            if len(params) == 3:
                tenant, snapshot_ref, changed_at = params
                generation, state, event_ref = 0, "ACTIVE", None
            else:
                tenant, snapshot_ref, generation, state, event_ref, changed_at = params
            key = (tenant, snapshot_ref, generation)
            if key not in self.connection.fences:
                self.connection.fences[key] = (generation, state, event_ref, changed_at)
                self.rowcount = 1
                if generation == 0 and self.connection.database.advance_after_initial_fence:
                    self.connection.database.now = self.connection.snapshots[(tenant, snapshot_ref)][3]
            else:
                self.rowcount = 0
            return
        raise AssertionError(normalized)


def adapter(database: Database):
    connections = []

    def connect():
        connection = Connection(database)
        connections.append(connection)
        return connection

    return PostgresReleaseControlAuthority(connect), connections


def snapshot(*, tenant=TENANT, snapshot_ref=None, expires_at=None, control_digest=None):
    return ReleaseControlSnapshot(
        tenant,
        snapshot_ref or opaque("releasectrlref:v1:"),
        control_digest or digest(),
        expires_at or NOW + timedelta(minutes=5),
    )


def test_create_is_exact_idempotent_and_fence_is_tenant_scoped():
    database = Database()
    authority, connections = adapter(database)
    item = snapshot()
    assert authority.create(item).generation == 0
    assert authority.create(item).state == "ACTIVE"
    assert authority.fence(tenant_ref=TENANT, snapshot_ref=item.snapshot_ref,
                           expected_generation=0).snapshot == item
    with pytest.raises(PostgresReleaseControlError):
        authority.fence(tenant_ref=OTHER, snapshot_ref=item.snapshot_ref, expected_generation=0)
    assert all(connection.closed for connection in connections)
    assert connections[-1].rolled_back


def test_create_rejects_ambiguous_replay_expiry_and_mid_transaction_expiry():
    database = Database()
    authority, _ = adapter(database)
    item = snapshot()
    authority.create(item)
    with pytest.raises(PostgresReleaseControlError):
        authority.create(snapshot(snapshot_ref=item.snapshot_ref, control_digest=digest()))
    with pytest.raises(PostgresReleaseControlError):
        authority.create(snapshot(expires_at=NOW))
    database.advance_after_initial_fence = True
    with pytest.raises(PostgresReleaseControlError):
        authority.create(snapshot())


def test_terminal_state_is_monotonic_idempotent_and_fences_future_reads():
    database = Database()
    authority, _ = adapter(database)
    item = snapshot()
    authority.create(item)
    event_ref = opaque("controlfence:v1:")
    terminal = authority.terminal(tenant_ref=TENANT, snapshot_ref=item.snapshot_ref,
                                  expected_generation=0, state="QUARANTINED", event_ref=event_ref)
    assert (terminal.generation, terminal.state) == (1, "QUARANTINED")
    assert authority.terminal(tenant_ref=TENANT, snapshot_ref=item.snapshot_ref,
                              expected_generation=0, state="QUARANTINED", event_ref=event_ref) == terminal
    with pytest.raises(PostgresReleaseControlError):
        authority.fence(tenant_ref=TENANT, snapshot_ref=item.snapshot_ref, expected_generation=0)
    with pytest.raises(PostgresReleaseControlError):
        authority.terminal(tenant_ref=TENANT, snapshot_ref=item.snapshot_ref,
                           expected_generation=0, state="REVOKED",
                           event_ref=opaque("controlfence:v1:"))


def test_lock_active_requires_caller_transaction_generation_and_db_clock():
    database = Database()
    authority, _ = adapter(database)
    item = snapshot()
    authority.create(item)
    connection = Connection(database)
    cursor = connection.cursor()
    cursor.execute("BEGIN")
    assert authority.lock_active(cursor, tenant_ref=TENANT, snapshot_ref=item.snapshot_ref,
                                 expected_generation=0).snapshot == item
    with pytest.raises(PostgresReleaseControlError):
        authority.lock_active(cursor, tenant_ref=TENANT, snapshot_ref=item.snapshot_ref,
                              expected_generation=1)
    database.now = item.expires_at
    with pytest.raises(PostgresReleaseControlError):
        authority.lock_active(cursor, tenant_ref=TENANT, snapshot_ref=item.snapshot_ref,
                              expected_generation=0)


@pytest.fixture
def postgres_authority():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "009_m45_release_control_foundation.sql"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(migration.read_text(encoding="utf-8"))
    return dsn, psycopg, PostgresReleaseControlAuthority(lambda: psycopg.connect(dsn, autocommit=True))


def test_postgres_authority_fences_cross_tenant_expiry_idempotency_and_race(postgres_authority):
    dsn, psycopg, authority = postgres_authority
    moment = datetime.now(UTC).replace(microsecond=0)
    item = snapshot(expires_at=moment + timedelta(minutes=5))
    assert authority.create(item).generation == 0
    assert authority.create(item).generation == 0
    with pytest.raises(PostgresReleaseControlError):
        authority.fence(tenant_ref=OTHER, snapshot_ref=item.snapshot_ref, expected_generation=0)
    with pytest.raises(PostgresReleaseControlError):
        authority.create(snapshot(expires_at=moment))

    with psycopg.connect(dsn, autocommit=True) as repeatable_read:
        cursor = repeatable_read.cursor()
        cursor.execute("BEGIN ISOLATION LEVEL REPEATABLE READ")
        with pytest.raises(PostgresReleaseControlError):
            authority.lock_active(cursor, tenant_ref=item.tenant_ref,
                                  snapshot_ref=item.snapshot_ref, expected_generation=0)
        cursor.execute("ROLLBACK")

    # Transaction A inserts a terminal fence while retaining the shared
    # snapshot lock. Transaction B must wait, take a fresh READ COMMITTED
    # statement snapshot, then reject rather than return stale ACTIVE state.
    event_ref = opaque("controlfence:v1:")
    with psycopg.connect(dsn, autocommit=True) as blocker:
        cursor = blocker.cursor()
        cursor.execute("BEGIN")
        cursor.execute("SELECT snapshot_ref FROM anonflow_release_control_snapshots "
                       "WHERE tenant_ref=%s AND snapshot_ref=%s FOR UPDATE",
                       (item.tenant_ref, item.snapshot_ref))
        cursor.execute("INSERT INTO anonflow_release_control_fences "
                       "(tenant_ref,snapshot_ref,generation,state,event_ref) VALUES (%s,%s,1,'QUARANTINED',%s)",
                       (item.tenant_ref, item.snapshot_ref, event_ref))
        worker_pids: Queue[int] = Queue()

        def worker_connect():
            connection = psycopg.connect(dsn, autocommit=True)
            with connection.cursor() as worker_cursor:
                worker_cursor.execute("SELECT pg_backend_pid()")
                worker_pids.put(worker_cursor.fetchone()[0])
            return connection

        racing_authority = PostgresReleaseControlAuthority(worker_connect)
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(racing_authority.fence, tenant_ref=item.tenant_ref,
                                     snapshot_ref=item.snapshot_ref, expected_generation=0)
            try:
                worker_pid = worker_pids.get(timeout=3)
            except Empty:
                cursor.execute("ROLLBACK")
                with pytest.raises(PostgresReleaseControlError):
                    future.result(timeout=5)
                pytest.fail("fence worker did not establish a PostgreSQL connection")
            deadline = time.monotonic() + 3
            locked = False
            while time.monotonic() < deadline:
                cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid=%s", (worker_pid,))
                row = cursor.fetchone()
                if row == ("Lock",):
                    locked = True
                    break
                time.sleep(0.02)
            if not locked:
                cursor.execute("ROLLBACK")
                with pytest.raises((PostgresReleaseControlError, TimeoutError)):
                    future.result(timeout=5)
                pytest.fail("fence worker did not block on the snapshot row lock")
            cursor.execute("COMMIT")
            with pytest.raises(PostgresReleaseControlError):
                future.result(timeout=5)
