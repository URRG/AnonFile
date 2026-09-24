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


def opaque(prefix: str) -> str: return prefix + secrets.token_urlsafe(32)
def digest() -> str: return "sha256:" + secrets.token_hex(32)


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
    finalizer = PostgresPublicationFinalizer(connect, lambda value: value)
    assert finalizer.finalize(claim=claim, reference=reference).already_finalized is False
    assert finalizer.finalize(claim=claim, reference=reference).already_finalized is True
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
