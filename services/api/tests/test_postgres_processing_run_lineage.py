"""M48b3 processing-run lineage regressions."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import secrets
from types import SimpleNamespace

import pytest

from app.postgres_policy_method_snapshots import (
    PolicyMethodSnapshot,
    PostgresPolicyMethodSnapshotAuthority,
)
from app.postgres_processing_run_lineage import (
    PostgresProcessingRunLineageAuthority,
    PostgresProcessingRunLineageError,
    ProcessingRunLineage,
)
from app.postgres_source_snapshots import PostgresSourceSnapshotAuthority, SourceDatasetSnapshot
from app.postgres_tenant_identities import PostgresTenantIdentityAuthority, TenantIdentity

NOW = datetime(2026, 9, 26, 12, 0, tzinfo=UTC)
APP = "run-lineage-test"


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def digest() -> str:
    return "sha256:" + secrets.token_hex(32)


TENANT = opaque("tenantref:v1:")


def source(**changes: object) -> SourceDatasetSnapshot:
    values: dict[str, object] = {
        "tenant_ref": TENANT,
        "source_dataset_ref": opaque("supplierdatasetref:v1:"),
        "source_content_digest": digest(),
        "provenance_digest": digest(),
        "input_schema_digest": digest(),
        "source_byte_count": 1,
        "expires_at": NOW + timedelta(minutes=10),
    }
    values.update(changes)
    return SourceDatasetSnapshot(**values)


def policy(**changes: object) -> PolicyMethodSnapshot:
    values: dict[str, object] = {
        "tenant_ref": TENANT,
        "policy_method_ref": opaque("policymethodref:v1:"),
        "policy_digest": digest(),
        "method_id": "method",
        "method_version": "v1",
        "method_config_digest": digest(),
        "taxonomy_mapping_digest": digest(),
        "output_schema_digest": digest(),
        "expires_at": NOW + timedelta(minutes=8),
    }
    values.update(changes)
    return PolicyMethodSnapshot(**values)


def lineage(item_source: SourceDatasetSnapshot, item_policy: PolicyMethodSnapshot,
            **changes: object) -> ProcessingRunLineage:
    values: dict[str, object] = {
        "tenant_ref": TENANT,
        "processing_run_ref": opaque("processingrunref:v1:"),
        "source_snapshot_digest": item_source.digest,
        "source_dataset_ref": item_source.source_dataset_ref,
        "source_content_digest": item_source.source_content_digest,
        "provenance_digest": item_source.provenance_digest,
        "policy_method_snapshot_digest": item_policy.snapshot_digest,
        "policy_method_ref": item_policy.policy_method_ref,
        "policy_digest": item_policy.policy_digest,
        "output_schema_digest": item_policy.output_schema_digest,
        "expires_at": NOW + timedelta(minutes=5),
    }
    values.update(changes)
    return ProcessingRunLineage(**values)


class Connection:
    def __init__(self, source_item: SourceDatasetSnapshot, policy_item: PolicyMethodSnapshot) -> None:
        self.autocommit = True
        self.info = SimpleNamespace(transaction_status=SimpleNamespace(name="IDLE"))
        self.source_item = source_item
        self.policy_item = policy_item
        self.run: ProcessingRunLineage | None = None
        self.fence: tuple[object, ...] | None = None
        self.now = NOW
        self.queries: list[str] = []

    def cursor(self) -> "Cursor":
        return Cursor(self)

    def commit(self) -> None:
        self.info.transaction_status = SimpleNamespace(name="IDLE")

    def rollback(self) -> None:
        self.info.transaction_status = SimpleNamespace(name="IDLE")

    def close(self) -> None:
        pass


class Cursor:
    def __init__(self, connection: Connection) -> None:
        self.connection = connection
        self.value: tuple[object, ...] | None = None
        self.rowcount = -1

    def fetchone(self) -> tuple[object, ...] | None:
        return self.value

    def execute(self, sql: str, params: tuple[object, ...] = ()) -> None:
        query = " ".join(sql.split())
        self.connection.queries.append(query)
        self.value = None
        self.rowcount = -1
        if query == "BEGIN":
            self.connection.info.transaction_status = SimpleNamespace(name="INTRANS")
        elif query == "SHOW transaction_isolation":
            self.value = ("read committed",)
        elif query == "SELECT date_trunc('second', clock_timestamp())":
            self.value = (self.connection.now,)
        elif query.startswith("SELECT application_tenant, tenant_ref"):
            self.value = (APP, TENANT) if params == (APP,) else None
        elif query.startswith("SELECT generation, state, event_ref, changed_at FROM anonflow_tenant_identity_fences"):
            self.value = (0, "ACTIVE", None, NOW)
        elif query.startswith("SELECT tenant_ref,source_dataset_ref,source_content_digest"):
            item = self.connection.source_item
            self.value = (item.tenant_ref, item.source_dataset_ref, item.source_content_digest,
                          item.provenance_digest, item.input_schema_digest, item.source_byte_count,
                          item.expires_at, item.digest)
        elif query.startswith("SELECT generation,state,event_ref,changed_at FROM anonflow_source_dataset_snapshot_fences"):
            self.value = (0, "ACTIVE", None, NOW)
        elif query.startswith("SELECT tenant_ref,policy_method_ref,policy_digest"):
            item = self.connection.policy_item
            self.value = (item.tenant_ref, item.policy_method_ref, item.policy_digest,
                          item.method_id, item.method_version, item.method_config_digest,
                          item.taxonomy_mapping_digest, item.output_schema_digest, item.expires_at)
        elif query.startswith("SELECT generation,state,event_ref,changed_at FROM anonflow_policy_method_snapshot_fences"):
            self.value = (0, "ACTIVE", None, NOW)
        elif query.startswith("INSERT INTO anonflow_processing_run_lineages"):
            if self.connection.run is None:
                self.connection.run = ProcessingRunLineage(*params)
                self.value = (params[1],)
                self.rowcount = 1
        elif query.startswith("SELECT tenant_ref,processing_run_ref,source_snapshot_digest"):
            item = self.connection.run
            self.value = None if item is None else (
                item.tenant_ref, item.processing_run_ref, item.source_snapshot_digest,
                item.source_dataset_ref, item.source_content_digest, item.provenance_digest,
                item.policy_method_snapshot_digest, item.policy_method_ref, item.policy_digest,
                item.output_schema_digest, item.expires_at, item.lineage_digest)
        elif query.startswith("INSERT INTO anonflow_processing_run_lineage_fences"):
            if len(params) == 3:
                self.connection.fence = (0, "ACTIVE", None, params[2])
            else:
                self.connection.fence = (params[2], params[3], params[4], params[5])
            self.rowcount = 1
        elif query.startswith("SELECT generation,state,event_ref,changed_at FROM anonflow_processing_run_lineage_fences"):
            self.value = self.connection.fence
        else:
            raise AssertionError(query)


def authority(connection: Connection) -> PostgresProcessingRunLineageAuthority:
    tenant = PostgresTenantIdentityAuthority(lambda: connection)
    return PostgresProcessingRunLineageAuthority(lambda: connection, tenant)


def test_create_binds_exact_live_parents_in_tenant_source_policy_order():
    source_item, policy_item = source(), policy()
    connection = Connection(source_item, policy_item)
    item = lineage(source_item, policy_item)
    result = authority(connection).create(
        item, application_tenant=APP, source=source_item, policy=policy_item,
        expected_tenant_generation=0, expected_source_generation=0,
        expected_policy_generation=0)
    assert result.generation == 0
    assert item.lineage_digest != item.source_snapshot_digest
    query_text = "\n".join(connection.queries)
    assert query_text.index("anonflow_tenant_identities") < query_text.index("anonflow_source_dataset_snapshots")
    assert query_text.index("anonflow_source_dataset_snapshots") < query_text.index("anonflow_policy_method_snapshots")
    assert authority(connection).create(
        item, application_tenant=APP, source=source_item, policy=policy_item,
        expected_tenant_generation=0, expected_source_generation=0,
        expected_policy_generation=0) == result


@pytest.mark.parametrize("field", [
    "source_snapshot_digest", "source_content_digest", "provenance_digest",
    "policy_method_snapshot_digest", "policy_digest", "output_schema_digest",
])
def test_create_rejects_every_copied_digest_drift(field: str):
    source_item, policy_item = source(), policy()
    item = lineage(source_item, policy_item, **{field: digest()})
    with pytest.raises(PostgresProcessingRunLineageError):
        authority(Connection(source_item, policy_item)).create(
            item, application_tenant=APP, source=source_item, policy=policy_item,
            expected_tenant_generation=0, expected_source_generation=0,
            expected_policy_generation=0)


def test_create_rejects_parent_expiry_overrun():
    source_item, policy_item = source(), policy()
    item = lineage(source_item, policy_item, expires_at=policy_item.expires_at + timedelta(seconds=1))
    with pytest.raises(PostgresProcessingRunLineageError):
        authority(Connection(source_item, policy_item)).create(
            item, application_tenant=APP, source=source_item, policy=policy_item,
            expected_tenant_generation=0, expected_source_generation=0,
            expected_policy_generation=0)


def test_lock_active_and_terminal_fail_closed():
    source_item, policy_item = source(), policy()
    connection = Connection(source_item, policy_item)
    service = authority(connection)
    item = lineage(source_item, policy_item)
    service.create(item, application_tenant=APP, source=source_item, policy=policy_item,
                   expected_tenant_generation=0, expected_source_generation=0,
                   expected_policy_generation=0)
    with pytest.raises(PostgresProcessingRunLineageError):
        service.lock_active(Connection(source_item, policy_item).cursor(), application_tenant=APP,
                            lineage=item, source=source_item, policy=policy_item,
                            expected_tenant_generation=0, expected_source_generation=0,
                            expected_policy_generation=0, expected_generation=0)
    terminal = service.terminal(lineage=item, expected_generation=0, state="REVOKED",
                                event_ref=opaque("processingrunfence:v1:"))
    assert terminal.state == "REVOKED"


@pytest.fixture
def live():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    root = Path(__file__).parents[1]
    with psycopg.connect(dsn, autocommit=True) as connection:
        for migration in ("011_m45_tenant_identity_foundation.sql",
                          "016_m48b1_source_dataset_snapshots.sql",
                          "017_m48b2_policy_method_snapshot.sql",
                          "018_m48b3_processing_run_lineage.sql"):
            connection.execute((root / "migrations" / migration).read_text())
    return dsn, psycopg


def test_live_sql_rejects_orphans_bad_copy_and_invalid_fences(live):
    dsn, psycopg = live
    factory = lambda: psycopg.connect(dsn, autocommit=True)
    tenant = PostgresTenantIdentityAuthority(factory)
    source_authority = PostgresSourceSnapshotAuthority(factory)
    policy_authority = PostgresPolicyMethodSnapshotAuthority(factory, tenant)
    tenant_ref = opaque("tenantref:v1:")
    app = "run-raw-" + secrets.token_hex(6)
    now = datetime.now(UTC).replace(microsecond=0)
    tenant.create(TenantIdentity(app, tenant_ref))
    source_item = source(tenant_ref=tenant_ref, expires_at=now + timedelta(minutes=2))
    policy_item = policy(tenant_ref=tenant_ref, expires_at=now + timedelta(minutes=2))
    source_authority.create(source_item, application_tenant=app, expected_tenant_generation=0)
    policy_authority.create(policy_item, application_tenant=app, expected_tenant_generation=0)
    item = lineage(source_item, policy_item, tenant_ref=tenant_ref, expires_at=now + timedelta(minutes=1))
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("INSERT INTO anonflow_processing_run_lineages "
                               "(tenant_ref,processing_run_ref,source_snapshot_digest,source_dataset_ref,source_content_digest,provenance_digest,policy_method_snapshot_digest,policy_method_ref,policy_digest,output_schema_digest,expires_at,lineage_digest) "
                               "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                               (opaque("tenantref:v1:"), opaque("processingrunref:v1:"), item.source_snapshot_digest,
                                item.source_dataset_ref, item.source_content_digest, item.provenance_digest,
                                item.policy_method_snapshot_digest, item.policy_method_ref, item.policy_digest,
                                item.output_schema_digest, item.expires_at, item.lineage_digest))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("INSERT INTO anonflow_processing_run_lineages "
                               "(tenant_ref,processing_run_ref,source_snapshot_digest,source_dataset_ref,source_content_digest,provenance_digest,policy_method_snapshot_digest,policy_method_ref,policy_digest,output_schema_digest,expires_at,lineage_digest) "
                               "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                               (tenant_ref, item.processing_run_ref, digest(), item.source_dataset_ref,
                                item.source_content_digest, item.provenance_digest,
                                item.policy_method_snapshot_digest, item.policy_method_ref, item.policy_digest,
                                item.output_schema_digest, item.expires_at, item.lineage_digest))
    with psycopg.connect(dsn, autocommit=False) as connection:
        connection.execute("INSERT INTO anonflow_processing_run_lineages "
                           "(tenant_ref,processing_run_ref,source_snapshot_digest,source_dataset_ref,source_content_digest,provenance_digest,policy_method_snapshot_digest,policy_method_ref,policy_digest,output_schema_digest,expires_at,lineage_digest) "
                           "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                           (item.tenant_ref, item.processing_run_ref, item.source_snapshot_digest,
                            item.source_dataset_ref, item.source_content_digest, item.provenance_digest,
                            item.policy_method_snapshot_digest, item.policy_method_ref, item.policy_digest,
                            item.output_schema_digest, item.expires_at, item.lineage_digest))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.commit()


def test_live_sql_rejects_invalid_run_fence_transitions(live):
    dsn, psycopg = live
    factory = lambda: psycopg.connect(dsn, autocommit=True)
    tenant = PostgresTenantIdentityAuthority(factory)
    source_authority = PostgresSourceSnapshotAuthority(factory)
    policy_authority = PostgresPolicyMethodSnapshotAuthority(factory, tenant)
    lineage_authority = PostgresProcessingRunLineageAuthority(factory, tenant)
    app = "run-fence-" + secrets.token_hex(6)
    tenant_ref = opaque("tenantref:v1:")
    tenant.create(TenantIdentity(app, tenant_ref))
    now = datetime.now(UTC).replace(microsecond=0)
    source_item = source(tenant_ref=tenant_ref, expires_at=now + timedelta(minutes=5))
    policy_item = policy(tenant_ref=tenant_ref, expires_at=now + timedelta(minutes=5))
    source_authority.create(source_item, application_tenant=app, expected_tenant_generation=0)
    policy_authority.create(policy_item, application_tenant=app, expected_tenant_generation=0)
    item = lineage(source_item, policy_item, tenant_ref=tenant_ref, expires_at=now + timedelta(minutes=2))
    lineage_authority.create(item, application_tenant=app, source=source_item, policy=policy_item,
                             expected_tenant_generation=0, expected_source_generation=0,
                             expected_policy_generation=0)
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("INSERT INTO anonflow_processing_run_lineage_fences "
                               "(tenant_ref,processing_run_ref,generation,state,event_ref) "
                               "VALUES (%s,%s,1,'EXPIRED',%s)",
                               (tenant_ref, item.processing_run_ref,
                                opaque("processingrunfence:v1:")))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("UPDATE anonflow_processing_run_lineages SET expires_at=expires_at "
                               "WHERE tenant_ref=%s AND processing_run_ref=%s",
                               (tenant_ref, item.processing_run_ref))
    source_authority.terminal(snapshot=source_item, expected_generation=0, state="REVOKED",
                              event_ref=opaque("sourcesnapshotfence:v1:"))
    blocked = lineage(source_item, policy_item, tenant_ref=tenant_ref,
                      expires_at=now + timedelta(minutes=1))
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("INSERT INTO anonflow_processing_run_lineages "
                               "(tenant_ref,processing_run_ref,source_snapshot_digest,source_dataset_ref,source_content_digest,provenance_digest,policy_method_snapshot_digest,policy_method_ref,policy_digest,output_schema_digest,expires_at,lineage_digest) "
                               "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                               (blocked.tenant_ref, blocked.processing_run_ref,
                                blocked.source_snapshot_digest, blocked.source_dataset_ref,
                                blocked.source_content_digest, blocked.provenance_digest,
                                blocked.policy_method_snapshot_digest, blocked.policy_method_ref,
                                blocked.policy_digest, blocked.output_schema_digest,
                                blocked.expires_at, blocked.lineage_digest))
    lineage_authority.terminal(lineage=item, expected_generation=0, state="REVOKED",
                               event_ref=opaque("processingrunfence:v1:"))
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("INSERT INTO anonflow_processing_run_lineage_fences "
                               "(tenant_ref,processing_run_ref,generation,state,event_ref) "
                               "VALUES (%s,%s,2,'REVOKED',%s)",
                               (tenant_ref, item.processing_run_ref,
                                opaque("processingrunfence:v1:")))
