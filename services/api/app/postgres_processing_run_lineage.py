"""M48b3 immutable PostgreSQL processing-run lineage metadata.

The authority is intentionally inert: it binds already-approved source and
policy/method snapshots to an opaque run reference.  It does not process
bytes, invoke a worker, or authorize a release.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any

from app.postgres_policy_method_snapshots import PolicyMethodSnapshot
from app.postgres_source_snapshots import SourceDatasetSnapshot
from app.postgres_tenant_identities import PostgresTenantIdentityAuthority

_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_RUN = re.compile(r"processingrunref:v1:" + _OPAQUE + r"\Z")
_EVENT = re.compile(r"processingrunfence:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_APPLICATION_TENANT = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_TERMINAL = frozenset({"QUARANTINED", "REVOKED", "EXPIRED"})
_DOMAIN = b"anonflow-processing-run-lineage:v1:\x00"
_SCHEMA = "processing-run-lineage-v1"


class PostgresProcessingRunLineageError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL processing run lineage authority unavailable")


def _fail() -> None:
    raise PostgresProcessingRunLineageError() from None


def _text(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        _fail()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try:
        value = value.astimezone(UTC)
    except (ValueError, OverflowError):
        _fail()
    if value.microsecond:
        _fail()
    return value


def _row(cursor: Any) -> tuple[object, ...] | None:
    value = cursor.fetchone()
    if value is not None and type(value) is not tuple:
        _fail()
    return value


def _now(cursor: Any) -> datetime:
    cursor.execute("SELECT date_trunc('second', clock_timestamp())")
    value = _row(cursor)
    if value is None or len(value) != 1:
        _fail()
    return _time(value[0])


def _require_transaction(cursor: Any) -> None:
    status = getattr(getattr(getattr(cursor, "connection", None), "info", None),
                     "transaction_status", None)
    if getattr(status, "name", None) != "INTRANS":
        _fail()
    cursor.execute("SHOW transaction_isolation")
    if _row(cursor) != ("read committed",):
        _fail()


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class ProcessingRunLineage:
    tenant_ref: str
    processing_run_ref: str
    source_snapshot_digest: str
    source_dataset_ref: str
    source_content_digest: str
    provenance_digest: str
    policy_method_snapshot_digest: str
    policy_method_ref: str
    policy_digest: str
    output_schema_digest: str
    expires_at: datetime
    lineage_digest: str = ""

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.processing_run_ref, _RUN)
        _text(self.source_dataset_ref, re.compile(r"supplierdatasetref:v1:" + _OPAQUE + r"\Z"))
        _text(self.policy_method_ref, re.compile(r"policymethodref:v1:" + _OPAQUE + r"\Z"))
        for value in (self.source_snapshot_digest, self.source_content_digest,
                      self.provenance_digest, self.policy_method_snapshot_digest,
                      self.policy_digest, self.output_schema_digest):
            _text(value, _DIGEST)
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        encoded = json.dumps(self.canonical(), sort_keys=True, separators=(",", ":"),
                             ensure_ascii=True, allow_nan=False).encode("ascii")
        calculated = "sha256:" + hashlib.sha256(_DOMAIN + encoded).hexdigest()
        if self.lineage_digest not in ("", calculated):
            _fail()
        object.__setattr__(self, "lineage_digest", calculated)

    def canonical(self) -> dict[str, object]:
        return {
            "expires_at": _instant(self.expires_at),
            "output_schema_digest": self.output_schema_digest,
            "policy_digest": self.policy_digest,
            "policy_method_ref": self.policy_method_ref,
            "policy_method_snapshot_digest": self.policy_method_snapshot_digest,
            "processing_run_ref": self.processing_run_ref,
            "provenance_digest": self.provenance_digest,
            "schema": _SCHEMA,
            "source_content_digest": self.source_content_digest,
            "source_dataset_ref": self.source_dataset_ref,
            "source_snapshot_digest": self.source_snapshot_digest,
            "tenant_ref": self.tenant_ref,
        }


@dataclass(frozen=True, slots=True)
class ProcessingRunLineageFence:
    lineage: ProcessingRunLineage
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime

    def __post_init__(self) -> None:
        if type(self.lineage) is not ProcessingRunLineage or type(self.state) is not str:
            _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "ACTIVE" or self.event_ref is not None:
                _fail()
        elif self.generation != 1 or self.state not in _TERMINAL or self.event_ref is None:
            _fail()
        if self.event_ref is not None:
            _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


def _decode_lineage(row: tuple[object, ...] | None) -> ProcessingRunLineage | None:
    if row is None:
        return None
    if len(row) != 12:
        _fail()
    return ProcessingRunLineage(*row)


class PostgresProcessingRunLineageAuthority:
    """Create and fence immutable lineage under locked, live parent snapshots."""

    def __init__(self, connection_factory: Callable[[], Any],
                 tenant_authority: PostgresTenantIdentityAuthority) -> None:
        if not callable(connection_factory) or type(tenant_authority) is not PostgresTenantIdentityAuthority:
            _fail()
        self._connection_factory = connection_factory
        self._tenant_authority = tenant_authority

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
            connection.rollback()
        except Exception:
            pass

    @staticmethod
    def _lock_source(cursor: Any, source: SourceDatasetSnapshot,
                     expected_generation: int) -> None:
        cursor.execute(
            "SELECT tenant_ref,source_dataset_ref,source_content_digest,provenance_digest,"
            "input_schema_digest,source_byte_count,expires_at,snapshot_digest "
            "FROM anonflow_source_dataset_snapshots WHERE tenant_ref=%s "
            "AND source_dataset_ref=%s FOR UPDATE",
            (source.tenant_ref, source.source_dataset_ref),
        )
        if _row(cursor) != (source.tenant_ref, source.source_dataset_ref,
                            source.source_content_digest, source.provenance_digest,
                            source.input_schema_digest, source.source_byte_count,
                            source.expires_at, source.digest):
            _fail()
        cursor.execute(
            "SELECT generation,state,event_ref,changed_at "
            "FROM anonflow_source_dataset_snapshot_fences WHERE tenant_ref=%s "
            "AND source_dataset_ref=%s ORDER BY generation DESC LIMIT 1",
            (source.tenant_ref, source.source_dataset_ref),
        )
        fence = _row(cursor)
        if fence is None or len(fence) != 4 or fence[0] != expected_generation or fence[1] != "ACTIVE":
            _fail()

    @staticmethod
    def _lock_policy(cursor: Any, policy: PolicyMethodSnapshot,
                     expected_generation: int) -> None:
        cursor.execute(
            "SELECT tenant_ref,policy_method_ref,policy_digest,method_id,method_version,"
            "method_config_digest,taxonomy_mapping_digest,output_schema_digest,expires_at "
            "FROM anonflow_policy_method_snapshots WHERE tenant_ref=%s "
            "AND policy_method_ref=%s FOR UPDATE",
            (policy.tenant_ref, policy.policy_method_ref),
        )
        if _row(cursor) != (policy.tenant_ref, policy.policy_method_ref, policy.policy_digest,
                            policy.method_id, policy.method_version, policy.method_config_digest,
                            policy.taxonomy_mapping_digest, policy.output_schema_digest,
                            policy.expires_at):
            _fail()
        cursor.execute(
            "SELECT generation,state,event_ref,changed_at "
            "FROM anonflow_policy_method_snapshot_fences WHERE tenant_ref=%s "
            "AND policy_method_ref=%s ORDER BY generation DESC LIMIT 1",
            (policy.tenant_ref, policy.policy_method_ref),
        )
        fence = _row(cursor)
        if fence is None or len(fence) != 4 or fence[0] != expected_generation or fence[1] != "ACTIVE":
            _fail()

    @staticmethod
    def _lock_lineage(cursor: Any, lineage: ProcessingRunLineage) -> ProcessingRunLineage | None:
        cursor.execute(
            "SELECT tenant_ref,processing_run_ref,source_snapshot_digest,source_dataset_ref,"
            "source_content_digest,provenance_digest,policy_method_snapshot_digest,"
            "policy_method_ref,policy_digest,output_schema_digest,expires_at,lineage_digest "
            "FROM anonflow_processing_run_lineages WHERE tenant_ref=%s "
            "AND processing_run_ref=%s FOR UPDATE",
            (lineage.tenant_ref, lineage.processing_run_ref),
        )
        return _decode_lineage(_row(cursor))

    @staticmethod
    def _latest(cursor: Any, lineage: ProcessingRunLineage) -> ProcessingRunLineageFence | None:
        cursor.execute(
            "SELECT generation,state,event_ref,changed_at FROM anonflow_processing_run_lineage_fences "
            "WHERE tenant_ref=%s AND processing_run_ref=%s ORDER BY generation DESC LIMIT 1",
            (lineage.tenant_ref, lineage.processing_run_ref),
        )
        value = _row(cursor)
        if value is None:
            return None
        if len(value) != 4:
            _fail()
        return ProcessingRunLineageFence(lineage, *value)

    def _lock_parents(self, cursor: Any, *, application_tenant: str,
                      lineage: ProcessingRunLineage, source: SourceDatasetSnapshot,
                      policy: PolicyMethodSnapshot, expected_tenant_generation: int,
                      expected_source_generation: int,
                      expected_policy_generation: int) -> None:
        self._tenant_authority.lock_active(
            cursor, application_tenant=application_tenant, tenant_ref=lineage.tenant_ref,
            expected_generation=expected_tenant_generation)
        self._lock_source(cursor, source, expected_source_generation)
        self._lock_policy(cursor, policy, expected_policy_generation)
        if (source.tenant_ref != lineage.tenant_ref or policy.tenant_ref != lineage.tenant_ref
                or lineage.source_snapshot_digest != source.digest
                or lineage.source_dataset_ref != source.source_dataset_ref
                or lineage.source_content_digest != source.source_content_digest
                or lineage.provenance_digest != source.provenance_digest
                or lineage.policy_method_snapshot_digest != policy.snapshot_digest
                or lineage.policy_method_ref != policy.policy_method_ref
                or lineage.policy_digest != policy.policy_digest
                or lineage.output_schema_digest != policy.output_schema_digest
                or lineage.expires_at > source.expires_at
                or lineage.expires_at > policy.expires_at):
            _fail()

    def create(self, lineage: ProcessingRunLineage, *, application_tenant: str,
               source: SourceDatasetSnapshot, policy: PolicyMethodSnapshot,
               expected_tenant_generation: int, expected_source_generation: int,
               expected_policy_generation: int) -> ProcessingRunLineageFence:
        if type(lineage) is not ProcessingRunLineage or type(source) is not SourceDatasetSnapshot \
                or type(policy) is not PolicyMethodSnapshot:
            _fail()
        _text(application_tenant, _APPLICATION_TENANT)
        for generation in (expected_tenant_generation, expected_source_generation, expected_policy_generation):
            _generation(generation)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_transaction(cursor)
            self._lock_parents(cursor, application_tenant=application_tenant, lineage=lineage,
                               source=source, policy=policy,
                               expected_tenant_generation=expected_tenant_generation,
                               expected_source_generation=expected_source_generation,
                               expected_policy_generation=expected_policy_generation)
            if lineage.expires_at <= _now(cursor):
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_processing_run_lineages "
                "(tenant_ref,processing_run_ref,source_snapshot_digest,source_dataset_ref,"
                "source_content_digest,provenance_digest,policy_method_snapshot_digest,"
                "policy_method_ref,policy_digest,output_schema_digest,expires_at,lineage_digest) "
                "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) "
                "ON CONFLICT DO NOTHING RETURNING processing_run_ref",
                (lineage.tenant_ref, lineage.processing_run_ref, lineage.source_snapshot_digest,
                 lineage.source_dataset_ref, lineage.source_content_digest, lineage.provenance_digest,
                 lineage.policy_method_snapshot_digest, lineage.policy_method_ref, lineage.policy_digest,
                 lineage.output_schema_digest, lineage.expires_at, lineage.lineage_digest),
            )
            inserted = _row(cursor) is not None
            locked = self._lock_lineage(cursor, lineage)
            if locked != lineage:
                _fail()
            if inserted:
                moment = _now(cursor)
                cursor.execute(
                    "INSERT INTO anonflow_processing_run_lineage_fences "
                    "(tenant_ref,processing_run_ref,generation,state,event_ref,changed_at) "
                    "VALUES (%s,%s,0,'ACTIVE',NULL,%s)",
                    (lineage.tenant_ref, lineage.processing_run_ref, moment),
                )
                if cursor.rowcount != 1:
                    _fail()
                result = ProcessingRunLineageFence(lineage, 0, "ACTIVE", None, moment)
            else:
                result = self._latest(cursor, lineage)
                if result is None:
                    _fail()
            self._lock_parents(cursor, application_tenant=application_tenant, lineage=lineage,
                               source=source, policy=policy,
                               expected_tenant_generation=expected_tenant_generation,
                               expected_source_generation=expected_source_generation,
                               expected_policy_generation=expected_policy_generation)
            if lineage.expires_at <= _now(cursor):
                _fail()
            connection.commit()
            return result
        except PostgresProcessingRunLineageError:
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

    def lock_active(self, cursor: Any, *, application_tenant: str,
                    lineage: ProcessingRunLineage, source: SourceDatasetSnapshot,
                    policy: PolicyMethodSnapshot, expected_tenant_generation: int,
                    expected_source_generation: int, expected_policy_generation: int,
                    expected_generation: int) -> ProcessingRunLineageFence:
        if type(lineage) is not ProcessingRunLineage or type(source) is not SourceDatasetSnapshot \
                or type(policy) is not PolicyMethodSnapshot:
            _fail()
        _text(application_tenant, _APPLICATION_TENANT)
        for generation in (expected_tenant_generation, expected_source_generation,
                           expected_policy_generation, expected_generation):
            _generation(generation)
        try:
            _require_transaction(cursor)
            self._lock_parents(cursor, application_tenant=application_tenant, lineage=lineage,
                               source=source, policy=policy,
                               expected_tenant_generation=expected_tenant_generation,
                               expected_source_generation=expected_source_generation,
                               expected_policy_generation=expected_policy_generation)
            locked = self._lock_lineage(cursor, lineage)
            fence = None if locked is None else self._latest(cursor, locked)
            if (locked != lineage or fence is None or fence.generation != expected_generation
                    or fence.state != "ACTIVE" or lineage.expires_at <= _now(cursor)):
                _fail()
            return fence
        except PostgresProcessingRunLineageError:
            raise
        except Exception:
            _fail()

    def terminal(self, *, lineage: ProcessingRunLineage, expected_generation: int,
                 state: str, event_ref: str) -> ProcessingRunLineageFence:
        if type(lineage) is not ProcessingRunLineage or type(state) is not str or state not in _TERMINAL:
            _fail()
        _generation(expected_generation)
        _text(event_ref, _EVENT)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_transaction(cursor)
            locked = self._lock_lineage(cursor, lineage)
            latest = None if locked is None else self._latest(cursor, locked)
            if locked != lineage or latest is None:
                _fail()
            if (latest.generation == expected_generation + 1 and latest.state == state
                    and latest.event_ref == event_ref):
                connection.commit()
                return latest
            moment = _now(cursor)
            if (latest.generation != expected_generation or latest.state != "ACTIVE"
                    or (state == "EXPIRED" and moment < lineage.expires_at)):
                _fail()
            cursor.execute(
                "INSERT INTO anonflow_processing_run_lineage_fences "
                "(tenant_ref,processing_run_ref,generation,state,event_ref,changed_at) "
                "VALUES (%s,%s,%s,%s,%s,%s)",
                (lineage.tenant_ref, lineage.processing_run_ref, expected_generation + 1,
                 state, event_ref, moment),
            )
            if cursor.rowcount != 1:
                _fail()
            result = ProcessingRunLineageFence(lineage, expected_generation + 1, state, event_ref, moment)
            connection.commit()
            return result
        except PostgresProcessingRunLineageError:
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
