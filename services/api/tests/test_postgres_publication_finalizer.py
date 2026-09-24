"""M40 real PostgreSQL tests for fenced publication finalization."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import secrets
import traceback

import pytest

from app.openbao_datakey import OpenBaoTransitDataKey
from app.postgres_metadata import PostgresControlPlaneMetadata
from app.postgres_publication_finalizer import (PostgresPublicationFinalizationError,
                                                PostgresPublicationFinalizer)
from app.postgres_publication_intents import PostgresPublicationIntents, PublicationIntent
from app.postgres_worker_jobs import PostgresLeasedWorkerJobs
from app.production_substrate import (ControlPlaneMetadata, EncryptedObjectReference,
                                      LeasedWorkerClaim, TenantMetadataTransaction)
from app.s3_ciphertext_transport import S3CiphertextTransport
from app.worker_encrypted_objects import WorkerEncryptedObjects


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def digest() -> str:
    return "sha256:" + secrets.token_hex(32)


def _worker() -> WorkerEncryptedObjects:
    """A genuine worker composition; its recovery boundary is monkeypatched."""
    return WorkerEncryptedObjects(openbao=object.__new__(OpenBaoTransitDataKey),
                                  ciphertexts=object.__new__(S3CiphertextTransport))


def test_finalizer_rejects_unverified_reference_before_opening_a_connection(monkeypatch):
    tenant, publication, object_ref = opaque("tenantref:v1:"), opaque("publicationref:v1:"), opaque("objectref:v1:")
    now = datetime(2030, 1, 1, tzinfo=UTC)
    claim = LeasedWorkerClaim(tenant, opaque("workref:v1:"), opaque("workerclaim:v1:"), opaque("workerref:v1:"), 1, 1, now, now + timedelta(seconds=10))
    authorized = EncryptedObjectReference(tenant, object_ref, publication, "keyref:v1:verify", digest(), 1)
    opened: list[bool] = []
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", lambda *_args, **_kwargs: authorized)
    fabricated = EncryptedObjectReference(tenant, object_ref, publication, "keyref:v1:verify", digest(), 1)
    with pytest.raises(PostgresPublicationFinalizationError):
        PostgresPublicationFinalizer(lambda: opened.append(True), _worker()).finalize(claim=claim, reference=fabricated, openbao_token="test-token")
    assert opened == []


def test_finalizer_suppresses_recovery_exception_context(monkeypatch):
    tenant, publication, object_ref = opaque("tenantref:v1:"), opaque("publicationref:v1:"), opaque("objectref:v1:")
    now = datetime(2030, 1, 1, tzinfo=UTC)
    claim = LeasedWorkerClaim(tenant, opaque("workref:v1:"), opaque("workerclaim:v1:"), opaque("workerref:v1:"), 1, 1, now, now + timedelta(seconds=10))
    reference = EncryptedObjectReference(tenant, object_ref, publication, "keyref:v1:verify", digest(), 1)
    def bad(*_args, **_kwargs): raise RuntimeError("openbao-token=secret-marker")
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", bad)
    with pytest.raises(PostgresPublicationFinalizationError) as error:
        PostgresPublicationFinalizer(lambda: None, _worker()).finalize(claim=claim, reference=reference, openbao_token="test-token")
    assert "secret-marker" not in "".join(traceback.format_exception(error.type, error.value, error.tb))


@pytest.fixture
def pg_finalizer(monkeypatch):
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migrations = [Path(__file__).parents[1] / "migrations" / name for name in (
        "001_m26_postgres_metadata.sql", "002_m28_postgres_worker_jobs.sql", "003_m39_publication_intents.sql", "004_m40_publication_finalizations.sql")]
    with psycopg.connect(dsn, autocommit=True) as connection:
        for migration in migrations: connection.execute(migration.read_text(encoding="utf-8"))
    connect = lambda: psycopg.connect(dsn, autocommit=True)
    tenant, publication, object_ref, work, target = (opaque("tenantref:v1:"), opaque("publicationref:v1:"), opaque("objectref:v1:"), opaque("workref:v1:"), opaque("metarecord:v1:"))
    key = "keyref:v1:finalization-key"
    metadata, jobs, intents = PostgresControlPlaneMetadata(connect), PostgresLeasedWorkerJobs(connect), PostgresPublicationIntents(connect)
    metadata.commit(TenantMetadataTransaction(tenant, opaque("metatx:v1:"), {target: 0}, (ControlPlaneMetadata(tenant, target, "release_artifact", 1, {}),)))
    plan = PublicationIntent(tenant, publication, opaque("metatx:v1:"), object_ref, key, work, target, "release_artifact", digest(), digest(), 1, {})
    assert intents.begin(plan) == plan and jobs.enqueue(tenant, work)
    claim = jobs.claim(tenant, opaque("workerref:v1:"), lease_seconds=60)
    reference = EncryptedObjectReference(tenant, object_ref, publication, key, digest(), 99)
    calls: list[tuple[object, object]] = []
    def recover(_self, **kwargs):
        calls.append((kwargs["tenant_ref"], kwargs["object_ref"])); return reference
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", recover)
    return {"psycopg": psycopg, "dsn": dsn, "connect": connect, "metadata": metadata, "jobs": jobs, "plan": plan, "claim": claim, "reference": reference, "objects": _worker(), "calls": calls}


def _finalizer(state, connect=None):
    return PostgresPublicationFinalizer(connect or state["connect"], state["objects"])


def _count(state, table: str) -> int:
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        return connection.execute("SELECT count(*) FROM " + table + " WHERE tenant_ref=%s", (state["plan"].tenant_ref,)).fetchone()[0]


def _m40_transaction_exists(state) -> bool:
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        return connection.execute(
            "SELECT EXISTS(SELECT 1 FROM anonflow_metadata_transactions "
            "WHERE tenant_ref=%s AND transaction_id=%s)",
            (state["plan"].tenant_ref, state["plan"].transaction_id)).fetchone()[0]


def test_postgresql_finalization_concurrent_same_claim_commits_exactly_once(pg_finalizer):
    state = pg_finalizer
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _ignored: _finalizer(state).finalize(claim=state["claim"], reference=state["reference"], openbao_token="test-token"), range(2)))
    assert sorted(result.already_finalized for result in results) == [False, True]
    assert {result.metadata.version for result in results} == {2}
    assert _count(state, "anonflow_publication_finalizations") == 1
    assert len(state["calls"]) == 2


def test_postgresql_finalization_rejects_expired_and_reclaimed_claim_without_write(pg_finalizer):
    state = pg_finalizer
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        leased_at, lease_expires_at = connection.execute(
            "WITH database_clock AS (SELECT date_trunc('second', clock_timestamp()) AS now) "
            "UPDATE anonflow_worker_jobs SET leased_at=database_clock.now-interval '3 seconds', "
            "lease_expires_at=database_clock.now-interval '1 second' FROM database_clock "
            "WHERE tenant_ref=%s AND work_ref=%s RETURNING leased_at, lease_expires_at",
            (state["plan"].tenant_ref, state["plan"].work_ref)).fetchone()
    expired_claim = LeasedWorkerClaim(
        state["claim"].tenant_ref, state["claim"].work_ref, state["claim"].claim_id,
        state["claim"].worker_ref, state["claim"].delivery_attempt,
        state["claim"].lease_epoch, leased_at, lease_expires_at)
    with pytest.raises(PostgresPublicationFinalizationError): _finalizer(state).finalize(claim=expired_claim, reference=state["reference"], openbao_token="test-token")
    replacement = state["jobs"].claim(state["plan"].tenant_ref, opaque("workerref:v1:"), lease_seconds=60)
    assert replacement is not None and replacement.lease_epoch == state["claim"].lease_epoch + 1
    with pytest.raises(PostgresPublicationFinalizationError): _finalizer(state).finalize(claim=state["claim"], reference=state["reference"], openbao_token="test-token")
    assert state["metadata"].read(state["plan"].tenant_ref, state["plan"].target_ref).version == 1 and _count(state, "anonflow_publication_finalizations") == 0


def test_postgresql_finalization_metadata_cas_conflict_rolls_back_everything(pg_finalizer):
    state = pg_finalizer
    state["metadata"].commit(TenantMetadataTransaction(state["plan"].tenant_ref, opaque("metatx:v1:"), {state["plan"].target_ref: 1}, (ControlPlaneMetadata(state["plan"].tenant_ref, state["plan"].target_ref, "release_artifact", 2, {}),)))
    with pytest.raises(PostgresPublicationFinalizationError): _finalizer(state).finalize(claim=state["claim"], reference=state["reference"], openbao_token="test-token")
    assert state["metadata"].read(state["plan"].tenant_ref, state["plan"].target_ref).version == 2 and _count(state, "anonflow_publication_finalizations") == 0
    assert _m40_transaction_exists(state) is False
    assert state["jobs"].acknowledge(state["claim"]) is True


def test_postgresql_finalization_rejects_wrong_tenant_or_intent_object(pg_finalizer, monkeypatch):
    state = pg_finalizer
    wrong_tenant = EncryptedObjectReference(opaque("tenantref:v1:"), state["reference"].object_ref, state["reference"].publication_ref, state["reference"].key_ref, state["reference"].ciphertext_digest, 99)
    with pytest.raises(PostgresPublicationFinalizationError): _finalizer(state).finalize(claim=state["claim"], reference=wrong_tenant, openbao_token="test-token")
    wrong_object = EncryptedObjectReference(state["plan"].tenant_ref, opaque("objectref:v1:"), state["reference"].publication_ref, state["reference"].key_ref, state["reference"].ciphertext_digest, 99)
    # Echo the candidate exactly so this is an authenticated-object mismatch
    # at the immutable intent check, not a superficial recovery failure.
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", lambda _self, **_kwargs: wrong_object)
    with pytest.raises(PostgresPublicationFinalizationError): _finalizer(state).finalize(claim=state["claim"], reference=wrong_object, openbao_token="test-token")
    assert state["metadata"].read(state["plan"].tenant_ref, state["plan"].target_ref).version == 1 and _count(state, "anonflow_publication_finalizations") == 0
    assert _m40_transaction_exists(state) is False


def test_postgresql_finalization_fault_after_metadata_before_ack_rolls_back(pg_finalizer):
    state = pg_finalizer
    class FaultCursor:
        def __init__(self, cursor): self._cursor = cursor
        def execute(self, sql, params=None):
            if "UPDATE anonflow_worker_jobs SET completed_at" in sql: raise RuntimeError("injected failure")
            return self._cursor.execute(sql, params)
        def __getattr__(self, name): return getattr(self._cursor, name)
    class FaultConnection:
        autocommit = True
        def __init__(self, connection): self._connection = connection
        def cursor(self): return FaultCursor(self._connection.cursor())
        def close(self): return self._connection.close()
    with pytest.raises(PostgresPublicationFinalizationError):
        _finalizer(state, lambda: FaultConnection(state["connect"]())).finalize(claim=state["claim"], reference=state["reference"], openbao_token="test-token")
    assert state["metadata"].read(state["plan"].tenant_ref, state["plan"].target_ref).version == 1 and _count(state, "anonflow_publication_finalizations") == 0
    assert _m40_transaction_exists(state) is False
    assert state["jobs"].acknowledge(state["claim"]) is True


def test_postgresql_finalization_exact_replay_altered_claim_and_tamper_rejection(pg_finalizer):
    state = pg_finalizer
    assert _finalizer(state).finalize(claim=state["claim"], reference=state["reference"], openbao_token="test-token").already_finalized is False
    assert _finalizer(state).finalize(claim=state["claim"], reference=state["reference"], openbao_token="test-token").already_finalized is True
    altered = LeasedWorkerClaim(state["claim"].tenant_ref, state["claim"].work_ref, state["claim"].claim_id, state["claim"].worker_ref, state["claim"].delivery_attempt, state["claim"].lease_epoch, state["claim"].leased_at, state["claim"].lease_expires_at - timedelta(seconds=1))
    with pytest.raises(PostgresPublicationFinalizationError): _finalizer(state).finalize(claim=altered, reference=state["reference"], openbao_token="test-token")
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        connection.execute("UPDATE anonflow_metadata_records SET document=jsonb_set(document, '{attributes,state}', '\"FAILED\"'::jsonb) WHERE tenant_ref=%s AND record_id=%s", (state["plan"].tenant_ref, state["plan"].target_ref))
    with pytest.raises(PostgresPublicationFinalizationError): _finalizer(state).finalize(claim=state["claim"], reference=state["reference"], openbao_token="test-token")
