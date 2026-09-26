"""M48b1 source snapshot authority tests."""
from __future__ import annotations

import copy
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import secrets
from types import SimpleNamespace

import pytest

from app.postgres_source_snapshots import (
    PostgresSourceSnapshotAuthority,
    PostgresSourceSnapshotError,
    SourceDatasetSnapshot,
    SourceDatasetSnapshotFence,
)

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)
APP = "snapshot-test-tenant"


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


TENANT = opaque("tenantref:v1:")


def snapshot(**changes: object) -> SourceDatasetSnapshot:
    values: dict[str, object] = {
        "tenant_ref": TENANT,
        "source_dataset_ref": opaque("supplierdatasetref:v1:"),
        "source_content_digest": "sha256:" + secrets.token_hex(32),
        "provenance_digest": "sha256:" + secrets.token_hex(32),
        "input_schema_digest": "sha256:" + secrets.token_hex(32),
        "source_byte_count": 1,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(changes)
    return SourceDatasetSnapshot(**values)


class Database:
    def __init__(self) -> None:
        self.snapshots: dict[tuple[str, str], tuple[object, ...]] = {}
        self.fences: dict[tuple[str, str, int], tuple[object, ...]] = {}
        self.now = NOW
        self.tenant = (APP, TENANT, 0, "ACTIVE")


class Connection:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.snapshots = copy.deepcopy(database.snapshots)
        self.fences = copy.deepcopy(database.fences)
        self.autocommit = True
        self.info = SimpleNamespace(transaction_status=SimpleNamespace(name="IDLE"))

    def cursor(self) -> "Cursor":
        return Cursor(self)

    def commit(self) -> None:
        self.database.snapshots = self.snapshots
        self.database.fences = self.fences
        self.info.transaction_status = SimpleNamespace(name="IDLE")

    def rollback(self) -> None:
        self.info.transaction_status = SimpleNamespace(name="IDLE")

    def close(self) -> None:
        pass


class Cursor:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self._row: tuple[object, ...] | None = None
        self.rowcount = -1

    def fetchone(self) -> tuple[object, ...] | None:
        return self._row

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        query = " ".join(sql.split())
        self._row, self.rowcount = None, -1
        if query == "BEGIN":
            self.connection.info.transaction_status = SimpleNamespace(name="INTRANS")
        elif query == "SHOW transaction_isolation":
            self._row = ("read committed",)
        elif query == "SELECT date_trunc('second', clock_timestamp())":
            self._row = (self.connection.database.now,)
        elif query.startswith("SELECT application_tenant,tenant_ref"):
            self._row = self.connection.database.tenant[:2] if params == (APP,) else None
        elif query.startswith("SELECT generation,state FROM anonflow_tenant_identity_fences"):
            self._row = self.connection.database.tenant[2:] if params == (APP,) else None
        elif query.startswith("INSERT INTO anonflow_source_dataset_snapshots"):
            values = tuple(params)
            if values[1] not in {row[1] for row in self.connection.snapshots.values()}:
                self.connection.snapshots[(values[0], values[1])] = values
                self._row, self.rowcount = (values[1],), 1
        elif query.startswith("SELECT tenant_ref,source_dataset_ref,source_content_digest"):
            self._row = self.connection.snapshots.get(tuple(params))
        elif query.startswith("SELECT generation,state,event_ref,changed_at"):
            rows = [row for (tenant, ref, _), row in self.connection.fences.items()
                    if (tenant, ref) == tuple(params)]
            self._row = max(rows, key=lambda row: row[0]) if rows else None
        elif query.startswith("INSERT INTO anonflow_source_dataset_snapshot_fences"):
            if len(params) == 3:
                tenant, ref, changed_at = params
                generation, state, event_ref = 0, "ACTIVE", None
            else:
                tenant, ref, generation, state, event_ref, changed_at = params
            key = (tenant, ref, generation)
            if key not in self.connection.fences:
                self.connection.fences[key] = (generation, state, event_ref, changed_at)
                self.rowcount = 1
        else:
            raise AssertionError(query)


def authority(database: Database) -> PostgresSourceSnapshotAuthority:
    return PostgresSourceSnapshotAuthority(lambda: Connection(database))


def test_create_is_exactly_idempotent_and_rejects_global_reference_field_drift():
    database = Database()
    service = authority(database)
    item = snapshot()
    assert service.create(item, application_tenant=APP, expected_tenant_generation=0).state == "ACTIVE"
    assert service.create(item, application_tenant=APP, expected_tenant_generation=0).snapshot == item
    with pytest.raises(PostgresSourceSnapshotError):
        service.create(snapshot(source_dataset_ref=item.source_dataset_ref),
                       application_tenant=APP, expected_tenant_generation=0)


def test_lock_demands_active_transaction_and_terminal_fence_blocks_future_reads():
    database = Database()
    service = authority(database)
    item = snapshot()
    service.create(item, application_tenant=APP, expected_tenant_generation=0)
    with pytest.raises(PostgresSourceSnapshotError):
        service.lock_active(Connection(database).cursor(), snapshot=item, expected_generation=0)
    event = opaque("sourcesnapshotfence:v1:")
    assert service.terminal(snapshot=item, expected_generation=0, state="REVOKED", event_ref=event).state == "REVOKED"
    connection = Connection(database)
    cursor = connection.cursor()
    cursor.execute("BEGIN")
    with pytest.raises(PostgresSourceSnapshotError):
        service.lock_active(cursor, snapshot=item, expected_generation=0)


def test_expired_fence_uses_database_clock_and_exact_retry_is_idempotent():
    database = Database()
    service = authority(database)
    item = snapshot()
    service.create(item, application_tenant=APP, expected_tenant_generation=0)
    event = opaque("sourcesnapshotfence:v1:")
    with pytest.raises(PostgresSourceSnapshotError):
        service.terminal(snapshot=item, expected_generation=0, state="EXPIRED", event_ref=event)
    database.now = item.expires_at
    result = service.terminal(snapshot=item, expected_generation=0, state="EXPIRED", event_ref=event)
    assert service.terminal(snapshot=item, expected_generation=0, state="EXPIRED", event_ref=event) == result


@pytest.mark.parametrize("changes", (
    {"source_byte_count": 0},
    {"source_byte_count": 2**63},
    {"source_content_digest": "sha256:BAD"},
))
def test_snapshot_values_fail_closed(changes: dict[str, object]):
    with pytest.raises(PostgresSourceSnapshotError):
        snapshot(**changes)


def test_malformed_fence_state_has_fixed_error():
    with pytest.raises(PostgresSourceSnapshotError):
        SourceDatasetSnapshotFence(snapshot(), 1, object(), opaque("sourcesnapshotfence:v1:"), NOW)


@pytest.fixture
def postgres_snapshots():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migrations = Path(__file__).parents[1] / "migrations"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute((migrations / "011_m45_tenant_identity_foundation.sql").read_text())
        migration = (migrations / "016_m48b1_source_dataset_snapshots.sql").read_text()
        connection.execute(migration)
        connection.execute(migration)
        connection.execute(
            "INSERT INTO anonflow_tenant_identities(application_tenant,tenant_ref) "
            "VALUES (%s,%s) ON CONFLICT DO NOTHING", (APP, TENANT))
        connection.execute(
            "INSERT INTO anonflow_tenant_identity_fences "
            "(application_tenant,generation,state,event_ref) VALUES (%s,0,'ACTIVE',NULL) "
            "ON CONFLICT DO NOTHING", (APP,))
    return dsn, psycopg


def test_postgres_orphan_global_collision_replay_terminal_and_immutable(postgres_snapshots):
    dsn, psycopg = postgres_snapshots
    service = PostgresSourceSnapshotAuthority(lambda: psycopg.connect(dsn, autocommit=True))
    now = datetime.now(UTC).replace(microsecond=0)
    item = snapshot(expires_at=now + timedelta(minutes=2))
    assert service.create(item, application_tenant=APP, expected_tenant_generation=0).generation == 0
    assert service.create(item, application_tenant=APP, expected_tenant_generation=0).snapshot == item
    with pytest.raises(PostgresSourceSnapshotError):
        service.create(snapshot(source_dataset_ref=item.source_dataset_ref, expires_at=item.expires_at),
                       application_tenant=APP, expected_tenant_generation=0)
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.ForeignKeyViolation):
            connection.execute(
                "INSERT INTO anonflow_source_dataset_snapshots "
                "(tenant_ref,source_dataset_ref,source_content_digest,provenance_digest,"
                "input_schema_digest,source_byte_count,expires_at,snapshot_digest) "
                "VALUES (%s,%s,%s,%s,%s,1,%s,%s)",
                (opaque("tenantref:v1:"), opaque("supplierdatasetref:v1:"),
                 "sha256:" + "0" * 64, "sha256:" + "1" * 64, "sha256:" + "2" * 64,
                 now + timedelta(minutes=2), "sha256:" + "3" * 64))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("UPDATE anonflow_source_dataset_snapshots SET source_byte_count=2 "
                               "WHERE tenant_ref=%s AND source_dataset_ref=%s",
                               (item.tenant_ref, item.source_dataset_ref))
    with pytest.raises(PostgresSourceSnapshotError):
        service.terminal(snapshot=item, expected_generation=0, state="EXPIRED",
                         event_ref=opaque("sourcesnapshotfence:v1:"))
    result = service.terminal(snapshot=item, expected_generation=0, state="REVOKED",
                              event_ref=opaque("sourcesnapshotfence:v1:"))
    with psycopg.connect(dsn, autocommit=True) as connection:
        cursor = connection.cursor()
        cursor.execute("BEGIN")
        with pytest.raises(PostgresSourceSnapshotError):
            service.lock_active(cursor, snapshot=item, expected_generation=0)
        cursor.execute("ROLLBACK")
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("UPDATE anonflow_source_dataset_snapshot_fences SET state='ACTIVE' "
                               "WHERE tenant_ref=%s AND source_dataset_ref=%s AND generation=%s",
                               (item.tenant_ref, item.source_dataset_ref, result.generation))
