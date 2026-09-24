"""Metadata-only PostgreSQL leased worker jobs.

This is intentionally a small persistence boundary: jobs contain a tenant and
an opaque ``work_ref`` only.  It neither carries work payloads nor starts a
worker.  PostgreSQL's clock is authoritative for expiry so host clock skew
cannot revive a stale worker claim.
"""
from __future__ import annotations

import secrets
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from app.production_substrate import (LeasedWorkerClaim, MAX_LEASE_SECONDS,
                                      ProductionSubstrateContractError)


MAX_DELIVERY_ATTEMPTS = 100


class PostgresWorkerJobError(RuntimeError):
    """Fixed fail-closed outcome for invalid, unavailable, or stale work."""

    def __init__(self) -> None:
        super().__init__("PostgreSQL worker job persistence unavailable")


def _fail() -> None:
    raise PostgresWorkerJobError()


def _reference(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def _validate_claim_inputs(tenant_ref: object, work_ref: object, worker_ref: object) -> None:
    """Use the M22 shape as the single reference validator."""
    now = datetime(2020, 1, 1, tzinfo=UTC)
    try:
        LeasedWorkerClaim(tenant_ref, work_ref, _reference("workerclaim:v1:"), worker_ref,
                          1, 1, now, now + timedelta(seconds=1))
    except (ProductionSubstrateContractError, TypeError):
        _fail()


def _validate_enqueue(tenant_ref: object, work_ref: object, max_attempts: object) -> int:
    _validate_claim_inputs(tenant_ref, work_ref, _reference("workerref:v1:"))
    if type(max_attempts) is not int or isinstance(max_attempts, bool) or not 1 <= max_attempts <= MAX_DELIVERY_ATTEMPTS:
        _fail()
    return max_attempts


def _row(cursor: Any) -> tuple[object, ...] | None:
    result = cursor.fetchone()
    if result is None:
        return None
    if type(result) is not tuple:
        _fail()
    return result


class PostgresLeasedWorkerJobs:
    """Tenant-scoped, database-clock, at-least-once PostgreSQL job adapter.

    The injected factory must make a *fresh* DB-API PostgreSQL connection with
    ``autocommit is True``.  Every operation owns its explicit transaction.
    """

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        if not callable(connection_factory):
            _fail()
        self._connection_factory = connection_factory

    @staticmethod
    def _rollback(connection: Any) -> None:
        try:
            connection.cursor().execute("ROLLBACK")
        except Exception:
            pass

    @staticmethod
    def _finish(connection: Any) -> None:
        try:
            connection.cursor().execute("COMMIT")
        except Exception:
            _fail()

    @staticmethod
    def _close(connection: Any) -> None:
        try:
            connection.close()
        except Exception:
            pass

    def _connection(self) -> Any:
        connection = self._connection_factory()
        if connection is None or getattr(connection, "autocommit", None) is not True:
            _fail()
        return connection

    def enqueue(self, tenant_ref: str, work_ref: str, *, max_attempts: int = 3) -> bool:
        """Durably create one job; duplicate tenant/work refs are harmless.

        A duplicate never alters its attempt budget, which avoids a caller
        accidentally resurrecting a poison job by replaying enqueue.
        """
        attempts = _validate_enqueue(tenant_ref, work_ref, max_attempts)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            cursor.execute(
                "INSERT INTO anonflow_worker_jobs (tenant_ref, work_ref, max_attempts) "
                "VALUES (%s, %s, %s) ON CONFLICT DO NOTHING RETURNING max_attempts",
                (tenant_ref, work_ref, attempts))
            inserted = _row(cursor)
            if inserted is not None:
                if len(inserted) != 1 or inserted[0] != attempts or cursor.rowcount != 1:
                    _fail()
                self._finish(connection)
                return True
            if cursor.rowcount != 0:
                _fail()
            cursor.execute("SELECT max_attempts FROM anonflow_worker_jobs "
                           "WHERE tenant_ref=%s AND work_ref=%s FOR UPDATE", (tenant_ref, work_ref))
            existing = _row(cursor)
            if existing is None or len(existing) != 1 or existing[0] != attempts:
                _fail()
            self._finish(connection)
            return False
        except PostgresWorkerJobError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            raise PostgresWorkerJobError() from None
        finally:
            if connection is not None: self._close(connection)

    def claim(self, tenant_ref: str, worker_ref: str, *, lease_seconds: int = 60) -> LeasedWorkerClaim | None:
        """Claim one eligible job using PostgreSQL time and SKIP LOCKED."""
        # work_ref is only needed to validate the M22-shaped tenant/worker pair.
        _validate_claim_inputs(tenant_ref, _reference("workref:v1:"), worker_ref)
        if type(lease_seconds) is not int or isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= MAX_LEASE_SECONDS:
            _fail()
        claim_id = _reference("workerclaim:v1:")
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            cursor.execute(
                "WITH database_clock AS (SELECT date_trunc('second', clock_timestamp()) AS current_time),"
                " next_job AS ("
                " SELECT tenant_ref, work_ref, claim_id AS previous_claim_id"
                " FROM anonflow_worker_jobs, database_clock"
                " WHERE tenant_ref=%s AND completed_at IS NULL"
                " AND delivery_attempt < max_attempts"
                " AND (lease_expires_at IS NULL OR lease_expires_at <= database_clock.current_time)"
                " ORDER BY (lease_expires_at IS NOT NULL), created_at, work_ref"
                " FOR UPDATE OF anonflow_worker_jobs SKIP LOCKED LIMIT 1"
                ") UPDATE anonflow_worker_jobs AS job"
                " SET delivery_attempt=job.delivery_attempt+1, lease_epoch=job.lease_epoch+1,"
                " claim_id=%s, worker_ref=%s, leased_at=database_clock.current_time,"
                " lease_expires_at=database_clock.current_time + (%s * interval '1 second')"
                " FROM next_job, database_clock WHERE job.tenant_ref=next_job.tenant_ref AND job.work_ref=next_job.work_ref"
                " RETURNING job.tenant_ref, job.work_ref, job.claim_id, job.worker_ref,"
                " job.delivery_attempt, job.lease_epoch, job.leased_at, job.lease_expires_at,"
                " next_job.previous_claim_id",
                (tenant_ref, claim_id, worker_ref, lease_seconds))
            stored = _row(cursor)
            if stored is None:
                self._finish(connection)
                return None
            if len(stored) != 9:
                _fail()
            try:
                claim = LeasedWorkerClaim(*stored)
            except (ProductionSubstrateContractError, TypeError):
                _fail()
            if (claim.tenant_ref != tenant_ref or claim.claim_id != claim_id or claim.worker_ref != worker_ref
                    or claim.delivery_attempt != claim.lease_epoch
                    or (claim.lease_expires_at - claim.leased_at).total_seconds() != lease_seconds
                    or (claim.delivery_attempt == 1 and claim.reclaimed_from_claim_id is not None)
                    or (claim.delivery_attempt > 1 and claim.reclaimed_from_claim_id is None)):
                _fail()
            self._finish(connection)
            return claim
        except PostgresWorkerJobError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            raise PostgresWorkerJobError() from None
        finally:
            if connection is not None: self._close(connection)

    def acknowledge(self, claim: LeasedWorkerClaim) -> bool:
        """Complete only the current unexpired claim (claim id + fencing CAS)."""
        if type(claim) is not LeasedWorkerClaim:
            _fail()
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            cursor.execute(
                "UPDATE anonflow_worker_jobs SET completed_at=date_trunc('second', clock_timestamp())"
                " WHERE tenant_ref=%s AND work_ref=%s AND claim_id=%s AND lease_epoch=%s"
                " AND completed_at IS NULL AND lease_expires_at > clock_timestamp()",
                (claim.tenant_ref, claim.work_ref, claim.claim_id, claim.lease_epoch))
            if cursor.rowcount not in (0, 1):
                _fail()
            self._finish(connection)
            return cursor.rowcount == 1
        except PostgresWorkerJobError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            raise PostgresWorkerJobError() from None
        finally:
            if connection is not None: self._close(connection)
