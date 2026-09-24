"""Bounded, metadata-only observation of stale publication intents.

This adapter deliberately has no S3/OpenBao dependency and cannot finalize a
publication, mutate a metadata record, acknowledge a worker claim, or delete
anything.  It only creates a short database-clock observation lease so that
one scanner can inspect a particular stale plan at a time.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import re
import secrets
from typing import Any

from app.postgres_publication_intents import (_MAX_ROW_BYTES, _PUBLICATION, _TENANT,
                                              _decode, _text)


_OBSERVATION = re.compile(r"observation:v1:[A-Za-z0-9_-]{43}\Z")
_REASON = "OPERATOR_CONFIRMED_UNRECOVERABLE"
_OBSERVED = "OBSERVED"
_QUARANTINED = "QUARANTINED"
_MAX_SCAN = 100
_MAX_AGE_SECONDS = 31 * 24 * 60 * 60
_MAX_LEASE_SECONDS = 60 * 60


class PostgresPublicationReconciliationError(RuntimeError):
    """Fixed fail-closed result for invalid, stale, or unavailable metadata."""

    def __init__(self) -> None:
        super().__init__("PostgreSQL publication reconciliation unavailable")


def _fail() -> None:
    raise PostgresPublicationReconciliationError() from None


def _positive(value: object, maximum: int) -> int:
    if type(value) is not int or isinstance(value, bool) or not 1 <= value <= maximum:
        _fail()
    return value


def _token() -> str:
    return "observation:v1:" + secrets.token_urlsafe(32)


def _timestamp(value: object) -> datetime:
    """Accept a PostgreSQL-aware value and return its canonical UTC instant."""
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try:
        return value.astimezone(UTC)
    except (OverflowError, ValueError):
        _fail()


def _row(cursor: Any) -> tuple[object, ...] | None:
    value = cursor.fetchone()
    if value is None:
        return None
    if type(value) is not tuple:
        _fail()
    return value


def _rows(cursor: Any) -> tuple[tuple[object, ...], ...]:
    try:
        values = cursor.fetchall()
    except Exception:
        _fail()
    if type(values) not in (list, tuple) or any(type(value) is not tuple for value in values):
        _fail()
    return tuple(values)


@dataclass(frozen=True, slots=True)
class PublicationObservation:
    """Small, non-payload observation lease returned to a reconciler."""

    tenant_ref: str
    publication_ref: str
    object_ref: str
    work_ref: str
    created_at: datetime
    observation_epoch: int
    observation_token: str
    lease_expires_at: datetime
    state: str = _OBSERVED
    reason: str | None = None

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.publication_ref, _PUBLICATION)
        # Decode through M39's immutable plan grammar rather than duplicating
        # less strict object/work validators here.
        _text(self.object_ref, re.compile(r"objectref:v1:[A-Za-z0-9_-]{43}\Z"))
        _text(self.work_ref, re.compile(r"workref:v1:[A-Za-z0-9_-]{43}\Z"))
        object.__setattr__(self, "created_at", _timestamp(self.created_at))
        _positive(self.observation_epoch, 2**63 - 1)
        _text(self.observation_token, _OBSERVATION)
        object.__setattr__(self, "lease_expires_at", _timestamp(self.lease_expires_at))
        if self.lease_expires_at <= self.created_at or self.state != _OBSERVED or self.reason is not None:
            _fail()


class PostgresPublicationReconciler:
    """Tenant-scoped keyset scanner for old unfinalized plans.

    ``scan`` uses only PostgreSQL metadata and PostgreSQL's clock.  It skips a
    plan while its corresponding M28 worker claim is live, ignores quarantined
    plans, limits every call to 100, and grants an observation only by a
    compare-and-swap on an absent/expired prior observation lease.
    """

    def __init__(self, connection_factory: Callable[[], Any], *,
                 quarantine_authorizer: Callable[[str, str, str], bool] | None = None) -> None:
        if not callable(connection_factory) or (quarantine_authorizer is not None
                                                and not callable(quarantine_authorizer)):
            _fail()
        self._connection_factory = connection_factory
        self._quarantine_authorizer = quarantine_authorizer

    def _connection(self) -> Any:
        connection = self._connection_factory()
        if connection is None or getattr(connection, "autocommit", None) is not True:
            _fail()
        return connection

    @staticmethod
    def _close(connection: Any) -> None:
        try:
            connection.close()
        except Exception:
            pass

    @staticmethod
    def _rollback(connection: Any) -> None:
        try:
            connection.cursor().execute("ROLLBACK")
        except Exception:
            pass

    @staticmethod
    def _commit(connection: Any) -> None:
        try:
            connection.cursor().execute("COMMIT")
        except Exception:
            _fail()

    def scan(self, tenant_ref: str, *, older_than_seconds: int,
             lease_seconds: int = 300, limit: int = _MAX_SCAN,
             after_publication_ref: str | None = None) -> tuple[PublicationObservation, ...]:
        """Observe up to ``limit`` eligible stale intents after a keyset cursor.

        Commit uncertainty intentionally reports failure.  Replaying it cannot
        create a second active observation: the persisted token remains live
        until its database-clock lease expires.
        """
        _text(tenant_ref, _TENANT)
        age = _positive(older_than_seconds, _MAX_AGE_SECONDS)
        lease = _positive(lease_seconds, _MAX_LEASE_SECONDS)
        count = _positive(limit, _MAX_SCAN)
        if after_publication_ref is not None:
            _text(after_publication_ref, _PUBLICATION)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            cursor.execute(
                "SELECT i.publication_ref, i.transaction_id, i.plan_digest, "
                "CASE WHEN octet_length(i.document::text) <= %s THEN i.document ELSE NULL END, i.created_at "
                "FROM anonflow_publication_intents AS i "
                "WHERE i.tenant_ref=%s AND (%s::text IS NULL OR i.publication_ref > %s) "
                "AND i.created_at <= clock_timestamp() - (%s * interval '1 second') "
                "AND NOT EXISTS (SELECT 1 FROM anonflow_publication_finalizations AS f "
                "WHERE f.tenant_ref=i.tenant_ref AND f.publication_ref=i.publication_ref) "
                "AND NOT EXISTS (SELECT 1 FROM anonflow_worker_jobs AS j "
                "WHERE j.tenant_ref=i.tenant_ref AND j.work_ref=i.document->>'work_ref' "
                "AND j.completed_at IS NULL AND j.lease_expires_at > clock_timestamp()) "
                "AND NOT EXISTS (SELECT 1 FROM anonflow_publication_observations AS o "
                "WHERE o.tenant_ref=i.tenant_ref AND o.publication_ref=i.publication_ref "
                "AND (o.state='QUARANTINED' OR (o.state='OBSERVED' "
                "AND o.lease_expires_at > clock_timestamp()))) "
                "ORDER BY i.publication_ref FOR UPDATE OF i SKIP LOCKED LIMIT %s",
                (_MAX_ROW_BYTES, tenant_ref, after_publication_ref, after_publication_ref, age, count))
            candidates = _rows(cursor)
            result: list[PublicationObservation] = []
            for publication_ref, transaction_id, plan_digest, document, created_at in candidates:
                if type(publication_ref) is not str or type(transaction_id) is not str or type(plan_digest) is not str:
                    _fail()
                intent = _decode(document, tenant_ref=tenant_ref, publication_ref=publication_ref,
                                 transaction_id=transaction_id, plan_digest=plan_digest)
                token = _token()
                cursor.execute(
                    "INSERT INTO anonflow_publication_observations "
                    "(tenant_ref, publication_ref, observation_epoch, observation_token, state, lease_expires_at) "
                    "VALUES (%s,%s,1,%s,'OBSERVED',clock_timestamp() + (%s * interval '1 second')) "
                    "ON CONFLICT (tenant_ref, publication_ref) DO UPDATE SET "
                    "observation_epoch=anonflow_publication_observations.observation_epoch+1, "
                    "observation_token=EXCLUDED.observation_token, observed_at=clock_timestamp(), "
                    "lease_expires_at=clock_timestamp() + (%s * interval '1 second') "
                    "WHERE anonflow_publication_observations.state='OBSERVED' "
                    "AND anonflow_publication_observations.lease_expires_at <= clock_timestamp() "
                    "RETURNING observation_epoch, observation_token, lease_expires_at, "
                    "lease_expires_at > clock_timestamp()",
                    (tenant_ref, publication_ref, token, lease, lease))
                granted = _row(cursor)
                if granted is None:
                    if cursor.rowcount != 0:
                        _fail()
                    continue
                if len(granted) != 4:
                    _fail()
                epoch, stored_token, expiry, live = granted
                if live is not True:
                    _fail()
                observation = PublicationObservation(tenant_ref, publication_ref, intent.object_ref,
                                                     intent.work_ref, created_at, epoch, stored_token, expiry)
                cursor.execute(
                    "INSERT INTO anonflow_publication_observation_events "
                    "(tenant_ref, publication_ref, observation_epoch, event_type, reason) "
                    "VALUES (%s,%s,%s,'OBSERVED',NULL)",
                    (tenant_ref, publication_ref, epoch))
                if cursor.rowcount != 1:
                    _fail()
                result.append(observation)
            self._commit(connection)
            return tuple(result)
        except PostgresPublicationReconciliationError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            raise PostgresPublicationReconciliationError() from None
        finally:
            if connection is not None:
                self._close(connection)

    def quarantine(self, tenant_ref: str, publication_ref: str, observation_token: str, *,
                   reason: str) -> bool:
        """Quarantine only an explicitly named operator-confirmed reason.

        The row is changed only if this scanner still owns its unexpired lease.
        This preserves a durable immutable event; it does not delete, repair,
        finalize, or acknowledge anything.
        """
        _text(tenant_ref, _TENANT)
        _text(publication_ref, _PUBLICATION)
        _text(observation_token, _OBSERVATION)
        if reason != _REASON:
            _fail()
        if self._quarantine_authorizer is None:
            _fail()
        try:
            authorized = self._quarantine_authorizer(tenant_ref, publication_ref, reason)
        except Exception:
            _fail()
        if authorized is not True:
            _fail()
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            cursor.execute(
                "UPDATE anonflow_publication_observations SET state='QUARANTINED', reason=%s, "
                "quarantined_at=clock_timestamp() WHERE tenant_ref=%s AND publication_ref=%s "
                "AND observation_token=%s AND state='OBSERVED' "
                "AND lease_expires_at > clock_timestamp() RETURNING observation_epoch",
                (reason, tenant_ref, publication_ref, observation_token))
            changed = _row(cursor)
            if changed is None:
                if cursor.rowcount != 0:
                    _fail()
                self._commit(connection)
                return False
            if len(changed) != 1 or type(changed[0]) is not int or changed[0] < 1:
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_publication_observation_events "
                "(tenant_ref, publication_ref, observation_epoch, event_type, reason) "
                "VALUES (%s,%s,%s,'QUARANTINED',%s)",
                (tenant_ref, publication_ref, changed[0], reason))
            if cursor.rowcount != 1:
                _fail()
            self._commit(connection)
            return True
        except PostgresPublicationReconciliationError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            raise PostgresPublicationReconciliationError() from None
        finally:
            if connection is not None:
                self._close(connection)
