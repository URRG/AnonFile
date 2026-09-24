"""M28 fake and optional service tests for metadata-only leased jobs."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import secrets

import pytest

from app.postgres_worker_jobs import (PostgresLeasedWorkerJobs, PostgresWorkerJobError)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


TENANT = opaque("tenantref:v1:")
WORK = opaque("workref:v1:")
WORKER = opaque("workerref:v1:")


class FakeDatabase:
    def __init__(self):
        self.jobs = {}
        self.now = datetime(2030, 1, 1, tzinfo=UTC)


class FakeConnection:
    def __init__(self, database):
        self.database = database
        self.jobs = copy.deepcopy(database.jobs)
        self.autocommit = True
        self.closed = self.committed = self.rolled_back = False

    def cursor(self): return FakeCursor(self)
    def close(self): self.closed = True
    def commit(self):
        self.database.jobs = self.jobs
        self.committed = True
    def rollback(self): self.rolled_back = True


class FakeCursor:
    def __init__(self, connection):
        self.connection, self._row, self.rowcount = connection, None, -1
    def fetchone(self): return self._row
    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self._row, self.rowcount = None, -1
        if normalized == "BEGIN": return
        if normalized == "COMMIT": self.connection.commit(); return
        if normalized == "ROLLBACK": self.connection.rollback(); return
        if normalized.startswith("INSERT INTO anonflow_worker_jobs"):
            tenant, work, max_attempts = params; key = (tenant, work)
            if key not in self.connection.jobs:
                self.connection.jobs[key] = {"max": max_attempts, "attempt": 0, "epoch": 0,
                                             "claim": None, "worker": None, "leased": None,
                                             "expires": None, "completed": None}
                self._row, self.rowcount = (max_attempts,), 1
            else: self.rowcount = 0
            return
        if normalized.startswith("SELECT max_attempts FROM anonflow_worker_jobs"):
            job = self.connection.jobs.get((params[0], params[1]))
            self._row = None if job is None else (job["max"],)
            return
        if normalized.startswith("WITH database_clock AS"):
            tenant, claim, worker, seconds = params
            eligible = [(key, job) for key, job in self.connection.jobs.items()
                        if key[0] == tenant and job["completed"] is None and job["attempt"] < job["max"]
                        and (job["expires"] is None or job["expires"] <= self.connection.database.now)]
            if not eligible: return
            key, job = sorted(eligible)[0]; previous = job["claim"]
            job["attempt"] += 1; job["epoch"] += 1; job["claim"] = claim; job["worker"] = worker
            job["leased"] = self.connection.database.now; job["expires"] = job["leased"] + timedelta(seconds=seconds)
            self._row = (key[0], key[1], claim, worker, job["attempt"], job["epoch"], job["leased"], job["expires"], previous)
            self.rowcount = 1; return
        if normalized.startswith("UPDATE anonflow_worker_jobs SET completed_at"):
            tenant, work, claim, epoch = params; job = self.connection.jobs.get((tenant, work))
            if (job is not None and job["completed"] is None and job["claim"] == claim and job["epoch"] == epoch
                    and job["expires"] > self.connection.database.now):
                job["completed"] = self.connection.database.now; self.rowcount = 1
            else: self.rowcount = 0
            return
        raise AssertionError(normalized)


def fake_adapter(database):
    connections = []
    def connect():
        result = FakeConnection(database); connections.append(result); return result
    return PostgresLeasedWorkerJobs(connect), connections


def test_fake_enqueue_claim_reclaim_and_fenced_acknowledgement():
    database = FakeDatabase(); jobs, connections = fake_adapter(database)
    assert jobs.enqueue(TENANT, WORK, max_attempts=2) is True
    assert jobs.enqueue(TENANT, WORK, max_attempts=2) is False
    with pytest.raises(PostgresWorkerJobError): jobs.enqueue(TENANT, WORK, max_attempts=99)
    first = jobs.claim(TENANT, WORKER, lease_seconds=5)
    assert first.delivery_attempt == first.lease_epoch == 1
    assert first.reclaimed_from_claim_id is None
    assert jobs.acknowledge(first) is True
    assert jobs.claim(TENANT, WORKER) is None

    other_work = opaque("workref:v1:"); assert jobs.enqueue(TENANT, other_work, max_attempts=2)
    original = jobs.claim(TENANT, WORKER, lease_seconds=5)
    database.now += timedelta(seconds=5)
    replacement = jobs.claim(TENANT, opaque("workerref:v1:"), lease_seconds=5)
    assert replacement.work_ref == other_work
    assert replacement.delivery_attempt == replacement.lease_epoch == 2
    assert replacement.reclaimed_from_claim_id == original.claim_id
    assert jobs.acknowledge(original) is False
    assert jobs.acknowledge(replacement) is True
    assert all(item.closed for item in connections)
    assert any(item.rolled_back for item in connections)


def test_fake_rejects_expired_claim_and_attempt_budget_without_payload_inputs():
    database = FakeDatabase(); jobs, _ = fake_adapter(database)
    assert jobs.enqueue(TENANT, WORK, max_attempts=1)
    claim = jobs.claim(TENANT, WORKER, lease_seconds=1)
    database.now += timedelta(seconds=1)
    assert jobs.acknowledge(claim) is False
    assert jobs.claim(TENANT, WORKER) is None
    with pytest.raises(PostgresWorkerJobError): jobs.enqueue(TENANT, "source bytes", max_attempts=1)
    with pytest.raises(PostgresWorkerJobError): jobs.claim(TENANT, WORKER, lease_seconds=3601)


def test_fake_rejects_a_valid_shaped_but_impossible_claim_row():
    database = FakeDatabase(); jobs, connections = fake_adapter(database)
    assert jobs.enqueue(TENANT, WORK, max_attempts=10)
    # Simulate privileged row tampering that the M22 object alone cannot
    # distinguish from a first delivery unless adapter invariants are checked.
    database.jobs[(TENANT, WORK)]["attempt"] = 4
    database.jobs[(TENANT, WORK)]["epoch"] = 4
    with pytest.raises(PostgresWorkerJobError): jobs.claim(TENANT, WORKER)
    assert connections[-1].rolled_back and connections[-1].closed


def test_postgresql_service_claim_reclaim_and_stale_ack_when_configured():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "002_m28_postgres_worker_jobs.sql"
    with psycopg.connect(dsn, autocommit=True) as connection: connection.execute(migration.read_text(encoding="utf-8"))
    tenant, work, worker = opaque("tenantref:v1:"), opaque("workref:v1:"), opaque("workerref:v1:")
    jobs = PostgresLeasedWorkerJobs(lambda: psycopg.connect(dsn, autocommit=True))
    assert jobs.enqueue(tenant, work, max_attempts=2)
    assert jobs.enqueue(tenant, work, max_attempts=2) is False
    with pytest.raises(PostgresWorkerJobError): jobs.enqueue(tenant, work, max_attempts=1)
    first = jobs.claim(tenant, worker, lease_seconds=1)
    assert first.delivery_attempt == first.lease_epoch == 1
    # Make expiry server-side without relying on a host clock or a sleep.
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("UPDATE anonflow_worker_jobs SET leased_at=clock_timestamp() - interval '2 seconds', "
                           "lease_expires_at=clock_timestamp() - interval '1 second' "
                           "WHERE tenant_ref=%s AND work_ref=%s", (tenant, work))
    second = jobs.claim(tenant, opaque("workerref:v1:"), lease_seconds=5)
    assert second.delivery_attempt == second.lease_epoch == 2
    assert second.reclaimed_from_claim_id == first.claim_id
    assert jobs.acknowledge(first) is False
    assert jobs.acknowledge(second) is True
    assert jobs.claim(tenant, worker) is None


def test_postgresql_service_concurrent_claim_is_single_fenced_delivery_when_configured():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "002_m28_postgres_worker_jobs.sql"
    with psycopg.connect(dsn, autocommit=True) as connection: connection.execute(migration.read_text(encoding="utf-8"))
    tenant, work = opaque("tenantref:v1:"), opaque("workref:v1:")
    jobs = PostgresLeasedWorkerJobs(lambda: psycopg.connect(dsn, autocommit=True))
    assert jobs.enqueue(tenant, work)
    workers = (opaque("workerref:v1:"), opaque("workerref:v1:"))
    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = list(executor.map(lambda worker: jobs.claim(tenant, worker, lease_seconds=30), workers))
    delivered = [claim for claim in claims if claim is not None]
    assert len(delivered) == 1
    assert delivered[0].delivery_attempt == delivered[0].lease_epoch == 1
