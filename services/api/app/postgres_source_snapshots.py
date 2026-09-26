"""M48b1 immutable PostgreSQL source-dataset snapshot metadata authority.

This stores opaque metadata only. It is not an upload, object store, PII
container, supplier-rights evaluator, API, worker, or release authority.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any

_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_APPLICATION_TENANT = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_SOURCE = re.compile(r"supplierdatasetref:v1:" + _OPAQUE + r"\Z")
_EVENT = re.compile(r"sourcesnapshotfence:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DOMAIN = b"anonflow-source-dataset-snapshot:v1:\x00"
_SCHEMA = "source-dataset-snapshot-v1"
_TERMINAL_STATES = frozenset({"QUARANTINED", "REVOKED", "EXPIRED"})


class PostgresSourceSnapshotError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL source snapshot authority unavailable")


def _fail() -> None:
    raise PostgresSourceSnapshotError() from None


def _text(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        _fail()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        _fail()
    return value


def _source_byte_count(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 < value <= 2**63 - 1:
        _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try:
        result = value.astimezone(UTC)
    except (ValueError, OverflowError):
        _fail()
    if result.microsecond:
        _fail()
    return result


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _row(cursor: Any) -> tuple[object, ...] | None:
    value = cursor.fetchone()
    if value is None:
        return None
    if type(value) is not tuple:
        _fail()
    return value


def _database_now(cursor: Any) -> datetime:
    cursor.execute("SELECT date_trunc('second', clock_timestamp())")
    value = _row(cursor)
    if value is None or len(value) != 1:
        _fail()
    return _time(value[0])


def _require_read_committed(cursor: Any) -> None:
    cursor.execute("SHOW transaction_isolation")
    if _row(cursor) != ("read committed",):
        _fail()


def _require_active_transaction(cursor: Any) -> None:
    connection = getattr(cursor, "connection", None)
    info = getattr(connection, "info", None)
    status = getattr(info, "transaction_status", None)
    if getattr(status, "name", None) != "INTRANS":
        _fail()


@dataclass(frozen=True, slots=True)
class SourceDatasetSnapshot:
    tenant_ref: str
    source_dataset_ref: str
    source_content_digest: str
    provenance_digest: str
    input_schema_digest: str
    source_byte_count: int
    expires_at: datetime
    digest: str = ""

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.source_dataset_ref, _SOURCE)
        _text(self.source_content_digest, _DIGEST)
        _text(self.provenance_digest, _DIGEST)
        _text(self.input_schema_digest, _DIGEST)
        _source_byte_count(self.source_byte_count)
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        calculated = "sha256:" + hashlib.sha256(
            _DOMAIN + json.dumps(self.canonical(), ensure_ascii=True,
                                 sort_keys=True, separators=(",", ":")).encode("ascii")
        ).hexdigest()
        if self.digest not in ("", calculated):
            _fail()
        object.__setattr__(self, "digest", calculated)

    def canonical(self) -> dict[str, object]:
        return {
            "expires_at": _instant(self.expires_at),
            "input_schema_digest": self.input_schema_digest,
            "provenance_digest": self.provenance_digest,
            "schema": _SCHEMA,
            "source_byte_count": self.source_byte_count,
            "source_content_digest": self.source_content_digest,
            "source_dataset_ref": self.source_dataset_ref,
            "tenant_ref": self.tenant_ref,
        }


@dataclass(frozen=True, slots=True)
class SourceDatasetSnapshotFence:
    snapshot: SourceDatasetSnapshot
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime

    def __post_init__(self) -> None:
        if type(self.snapshot) is not SourceDatasetSnapshot:
            _fail()
        if type(self.state) is not str or self.state not in {"ACTIVE", *_TERMINAL_STATES}:
            _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "ACTIVE" or self.event_ref is not None:
                _fail()
        elif self.state == "ACTIVE" or self.event_ref is None:
            _fail()
        if self.event_ref is not None:
            _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


def _decode_snapshot(row: tuple[object, ...] | None) -> SourceDatasetSnapshot | None:
    if row is None:
        return None
    if len(row) != 8:
        _fail()
    return SourceDatasetSnapshot(*row)


class PostgresSourceSnapshotAuthority:
    """Immutable source metadata with append-only terminal state fences."""

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        if not callable(connection_factory):
            _fail()
        self._connection_factory = connection_factory

    def _connection(self) -> Any:
        connection = self._connection_factory()
        if connection is None or getattr(connection, "autocommit", None) is not True:
            _fail()
        return connection

    @staticmethod
    def _rollback(connection: Any) -> None:
        try:
            connection.rollback()
        except Exception:
            pass

    @staticmethod
    def _close(connection: Any) -> None:
        try:
            connection.close()
        except Exception:
            pass

    @staticmethod
    def _lock_tenant(cursor: Any, application_tenant: str, tenant_ref: str,
                     expected_generation: int) -> None:
        cursor.execute(
            "SELECT application_tenant,tenant_ref FROM anonflow_tenant_identities "
            "WHERE application_tenant=%s FOR UPDATE", (application_tenant,))
        if _row(cursor) != (application_tenant, tenant_ref):
            _fail()
        cursor.execute(
            "SELECT generation,state FROM anonflow_tenant_identity_fences "
            "WHERE application_tenant=%s ORDER BY generation DESC LIMIT 1",
            (application_tenant,))
        if _row(cursor) != (expected_generation, "ACTIVE"):
            _fail()

    @staticmethod
    def _lock_snapshot(cursor: Any, tenant_ref: str,
                       source_dataset_ref: str) -> SourceDatasetSnapshot | None:
        cursor.execute(
            "SELECT tenant_ref,source_dataset_ref,source_content_digest,"
            "provenance_digest,input_schema_digest,source_byte_count,expires_at,"
            "snapshot_digest FROM anonflow_source_dataset_snapshots "
            "WHERE tenant_ref=%s AND source_dataset_ref=%s FOR UPDATE",
            (tenant_ref, source_dataset_ref))
        return _decode_snapshot(_row(cursor))

    @staticmethod
    def _latest(cursor: Any, snapshot: SourceDatasetSnapshot) -> SourceDatasetSnapshotFence | None:
        cursor.execute(
            "SELECT generation,state,event_ref,changed_at "
            "FROM anonflow_source_dataset_snapshot_fences WHERE tenant_ref=%s "
            "AND source_dataset_ref=%s ORDER BY generation DESC LIMIT 1",
            (snapshot.tenant_ref, snapshot.source_dataset_ref))
        row = _row(cursor)
        if row is None:
            return None
        if len(row) != 4:
            _fail()
        return SourceDatasetSnapshotFence(snapshot, *row)

    def create(self, snapshot: SourceDatasetSnapshot, *, application_tenant: str,
               expected_tenant_generation: int) -> SourceDatasetSnapshotFence:
        """Create exact metadata while retaining an active tenant-identity lock."""
        if type(snapshot) is not SourceDatasetSnapshot:
            _fail()
        _text(application_tenant, _APPLICATION_TENANT)
        _generation(expected_tenant_generation)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_active_transaction(cursor)
            _require_read_committed(cursor)
            self._lock_tenant(cursor, application_tenant, snapshot.tenant_ref,
                              expected_tenant_generation)
            if snapshot.expires_at <= _database_now(cursor):
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_source_dataset_snapshots "
                "(tenant_ref,source_dataset_ref,source_content_digest,"
                "provenance_digest,input_schema_digest,source_byte_count,expires_at,"
                "snapshot_digest) VALUES (%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT DO NOTHING RETURNING source_dataset_ref",
                (snapshot.tenant_ref, snapshot.source_dataset_ref,
                 snapshot.source_content_digest, snapshot.provenance_digest,
                 snapshot.input_schema_digest, snapshot.source_byte_count,
                 snapshot.expires_at, snapshot.digest))
            inserted = _row(cursor) is not None
            locked = self._lock_snapshot(cursor, snapshot.tenant_ref,
                                         snapshot.source_dataset_ref)
            if locked != snapshot:
                _fail()
            if inserted:
                moment = _database_now(cursor)
                cursor.execute(
                    "INSERT INTO anonflow_source_dataset_snapshot_fences "
                    "(tenant_ref,source_dataset_ref,generation,state,event_ref,changed_at) "
                    "VALUES (%s,%s,0,'ACTIVE',NULL,%s)",
                    (snapshot.tenant_ref, snapshot.source_dataset_ref, moment))
                if cursor.rowcount != 1:
                    _fail()
                result = SourceDatasetSnapshotFence(snapshot, 0, "ACTIVE", None, moment)
            else:
                result = self._latest(cursor, snapshot)
                if result is None:
                    _fail()
            self._lock_tenant(cursor, application_tenant, snapshot.tenant_ref,
                              expected_tenant_generation)
            if snapshot.expires_at <= _database_now(cursor):
                _fail()
            connection.commit()
            return result
        except PostgresSourceSnapshotError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)

    def lock_active(self, cursor: Any, *, snapshot: SourceDatasetSnapshot,
                    expected_generation: int) -> SourceDatasetSnapshotFence:
        """Lock an active snapshot in a live READ COMMITTED transaction.

        This deliberately does not check the application-tenant identity. A
        future admission transaction must lock that authority first, then keep
        both locks through its own mutation. The row lock precedes the latest
        fence query so a caller waiting behind a committed terminal fence
        cannot observe stale ACTIVE state.
        """
        if type(snapshot) is not SourceDatasetSnapshot:
            _fail()
        _generation(expected_generation)
        try:
            _require_active_transaction(cursor)
            _require_read_committed(cursor)
            locked = self._lock_snapshot(cursor, snapshot.tenant_ref,
                                         snapshot.source_dataset_ref)
            latest = None if locked is None else self._latest(cursor, locked)
            if (locked != snapshot or latest is None
                    or latest.generation != expected_generation
                    or latest.state != "ACTIVE"
                    or snapshot.expires_at <= _database_now(cursor)):
                _fail()
            return latest
        except PostgresSourceSnapshotError:
            raise
        except Exception:
            _fail()

    def terminal(self, *, snapshot: SourceDatasetSnapshot, expected_generation: int,
                 state: str, event_ref: str) -> SourceDatasetSnapshotFence:
        """Append one terminal fence; only an exact retry is idempotent."""
        if type(snapshot) is not SourceDatasetSnapshot:
            _fail()
        _generation(expected_generation)
        if type(state) is not str or state not in _TERMINAL_STATES:
            _fail()
        _text(event_ref, _EVENT)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            locked = self._lock_snapshot(cursor, snapshot.tenant_ref,
                                         snapshot.source_dataset_ref)
            latest = None if locked is None else self._latest(cursor, locked)
            if locked != snapshot or latest is None:
                _fail()
            if (latest.generation == expected_generation + 1
                    and latest.state == state and latest.event_ref == event_ref):
                connection.commit()
                return latest
            if latest.generation != expected_generation or latest.state != "ACTIVE":
                _fail()
            moment = _database_now(cursor)
            if state == "EXPIRED" and moment < snapshot.expires_at:
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_source_dataset_snapshot_fences "
                "(tenant_ref,source_dataset_ref,generation,state,event_ref,changed_at) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (snapshot.tenant_ref, snapshot.source_dataset_ref,
                 expected_generation + 1, state, event_ref, moment))
            if cursor.rowcount != 1:
                _fail()
            result = SourceDatasetSnapshotFence(
                snapshot, expected_generation + 1, state, event_ref, moment)
            connection.commit()
            return result
        except PostgresSourceSnapshotError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)
