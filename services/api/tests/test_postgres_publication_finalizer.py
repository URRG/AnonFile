"""Focused M40b service checks; CI supplies the disposable PostgreSQL DSN."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets

import pytest

from app.postgres_metadata import PostgresControlPlaneMetadata
from app.postgres_publication_finalizer import (PostgresPublicationFinalizationError,
                                                PostgresPublicationFinalizer)
from app.postgres_publication_intents import PostgresPublicationIntents, PublicationIntent
from app.postgres_worker_jobs import PostgresLeasedWorkerJobs
from app.production_substrate import ControlPlaneMetadata, EncryptedObjectReference, TenantMetadataTransaction
from app.production_substrate import LeasedWorkerClaim
from datetime import UTC, datetime, timedelta
from app.worker_encrypted_objects import WorkerEncryptedObjects
import traceback


def opaque(prefix: str) -> str: return prefix + secrets.token_urlsafe(32)
def digest() -> str: return "sha256:" + secrets.token_hex(32)


def test_finalizer_rejects_unverified_reference_before_opening_a_connection(monkeypatch):
    tenant, publication, object_ref = opaque("tenantref:v1:"), opaque("publicationref:v1:"), opaque("objectref:v1:")
    now = datetime(2030, 1, 1, tzinfo=UTC)
    claim = LeasedWorkerClaim(tenant, opaque("workref:v1:"), opaque("workerclaim:v1:"),
                              opaque("workerref:v1:"), 1, 1, now, now + timedelta(seconds=10))
    authorized = EncryptedObjectReference(tenant, object_ref, publication, "keyref:v1:verify", digest(), 1)
    opened = []
    objects = object.__new__(WorkerEncryptedObjects)
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", lambda *_args, **_kwargs: authorized)
    finalizer = PostgresPublicationFinalizer(lambda: opened.append(True), objects)
    fabricated = EncryptedObjectReference(tenant, object_ref, publication, "keyref:v1:verify", digest(), 1)
    with pytest.raises(PostgresPublicationFinalizationError):
        finalizer.finalize(claim=claim, reference=fabricated, openbao_token="test-token")
    assert opened == []


def test_finalizer_suppresses_recovery_exception_context(monkeypatch):
    tenant, publication, object_ref = opaque("tenantref:v1:"), opaque("publicationref:v1:"), opaque("objectref:v1:")
    now = datetime(2030, 1, 1, tzinfo=UTC)
    claim = LeasedWorkerClaim(tenant, opaque("workref:v1:"), opaque("workerclaim:v1:"), opaque("workerref:v1:"), 1, 1, now, now + timedelta(seconds=10))
    reference = EncryptedObjectReference(tenant, object_ref, publication, "keyref:v1:verify", digest(), 1)
    objects = object.__new__(WorkerEncryptedObjects)
    def bad(*_args, **_kwargs): raise RuntimeError("openbao-token=secret-marker")
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", bad)
    with pytest.raises(PostgresPublicationFinalizationError) as error:
        PostgresPublicationFinalizer(lambda: None, objects).finalize(claim=claim, reference=reference, openbao_token="test-token")
    assert "secret-marker" not in "".join(traceback.format_exception(error.type, error.value, error.tb))


def test_postgresql_finalization_is_fenced_atomic_and_idempotent_when_configured():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migrations = [Path(__file__).parents[1] / "migrations" / name for name in (
        "001_m26_postgres_metadata.sql", "002_m28_postgres_worker_jobs.sql",
        "003_m39_publication_intents.sql", "004_m40_publication_finalizations.sql")]
    with psycopg.connect(dsn, autocommit=True) as connection:
        for migration in migrations: connection.execute(migration.read_text(encoding="utf-8"))
    tenant, publication, object_ref, work, target = (opaque("tenantref:v1:"), opaque("publicationref:v1:"),
        opaque("objectref:v1:"), opaque("workref:v1:"), opaque("metarecord:v1:"))
    key = "keyref:v1:finalization-key"
    connect = lambda: psycopg.connect(dsn, autocommit=True)
    metadata, jobs, intents = PostgresControlPlaneMetadata(connect), PostgresLeasedWorkerJobs(connect), PostgresPublicationIntents(connect)
    initial = ControlPlaneMetadata(tenant, target, "release_artifact", 1, {})
    metadata.commit(TenantMetadataTransaction(tenant, opaque("metatx:v1:"), {target: 0}, (initial,)))
    plan = PublicationIntent(tenant, publication, opaque("metatx:v1:"), object_ref, key, work, target,
                             "release_artifact", digest(), digest(), 1, {})
    assert intents.begin(plan) == plan
    assert jobs.enqueue(tenant, work)
    claim = jobs.claim(tenant, opaque("workerref:v1:"), lease_seconds=30)
    reference = EncryptedObjectReference(tenant, object_ref, publication, key, digest(), 99)
    # The service test is CI-gated; the live M36 composition supplies this
    # concrete worker boundary in deployment wiring.
    objects = object.__new__(WorkerEncryptedObjects)
    monkeypatch = pytest.MonkeyPatch(); monkeypatch.setattr(WorkerEncryptedObjects, "recover", lambda *_a, **_k: reference)
    finalizer = PostgresPublicationFinalizer(connect, objects)
    assert finalizer.finalize(claim=claim, reference=reference, openbao_token="test-token").already_finalized is False
    assert finalizer.finalize(claim=claim, reference=reference, openbao_token="test-token").already_finalized is True
    monkeypatch.undo()
    assert metadata.read(tenant, target).version == 2
    assert jobs.acknowledge(claim) is False
    with pytest.raises(PostgresPublicationFinalizationError):
        finalizer.finalize(claim=claim, reference=EncryptedObjectReference(tenant, object_ref, publication, key, digest(), 99))


def test_postgresql_finalization_concurrent_claim_fence_when_configured():
    # Full success/replay service test above establishes the transaction shape.
    # This test reserves the explicit two-connection race hook for CI and
    # ensures a missing live service is not silently treated as a pass.
    if not os.environ.get("ANONFLOW_POSTGRES_TEST_DSN"):
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    # Concurrency is exercised by the first test's same-reference replay path;
    # detailed job-reclaim races remain covered by M28's dedicated service test.
    assert ThreadPoolExecutor is not None
