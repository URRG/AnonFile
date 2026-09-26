"""M48b2 immutable, expiry-bound policy/method snapshot metadata.

This is an inert audit binding.  It does not execute a method, load bytes,
authorize processing, or authorize any release.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import re
from typing import Any

from app.postgres_tenant_identities import PostgresTenantIdentityAuthority

_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_REF = re.compile(r"policymethodref:v1:" + _OPAQUE + r"\Z")
_EVENT = re.compile(r"policymethodfence:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_METHOD = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_TERMINAL = frozenset({"QUARANTINED", "REVOKED", "EXPIRED"})
_DOMAIN = b"anonflow-policy-method-snapshot:v1\0"


class PostgresPolicyMethodSnapshotError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL policy method snapshot authority unavailable")


def _fail() -> None: raise PostgresPolicyMethodSnapshotError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value): _fail()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1: _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None: _fail()
    try: result = value.astimezone(UTC)
    except (ValueError, OverflowError): _fail()
    if result.microsecond: _fail()
    return result


def _row(cursor: Any) -> tuple[object, ...] | None:
    result = cursor.fetchone()
    if result is not None and type(result) is not tuple: _fail()
    return result


def _now(cursor: Any) -> datetime:
    cursor.execute("SELECT date_trunc('second', clock_timestamp())")
    result = _row(cursor)
    if result is None or len(result) != 1: _fail()
    return _time(result[0])


def _read_committed(cursor: Any) -> None:
    cursor.execute("SHOW transaction_isolation")
    result = _row(cursor)
    if result is None or len(result) != 1 or result[0] != "read committed": _fail()


def _active_transaction(cursor: Any) -> None:
    status = getattr(getattr(getattr(cursor, "connection", None), "info", None), "transaction_status", None)
    if getattr(status, "name", None) != "INTRANS": _fail()


def _canonical(snapshot: "PolicyMethodSnapshot") -> bytes:
    record = {"expires_at": snapshot.expires_at.isoformat().replace("+00:00", "Z"),
              "method_config_digest": snapshot.method_config_digest, "method_id": snapshot.method_id,
              "method_version": snapshot.method_version, "output_schema_digest": snapshot.output_schema_digest,
              "policy_digest": snapshot.policy_digest, "policy_method_ref": snapshot.policy_method_ref,
              "taxonomy_mapping_digest": snapshot.taxonomy_mapping_digest, "tenant_ref": snapshot.tenant_ref}
    try:
        return _DOMAIN + json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                                    allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError): _fail()


@dataclass(frozen=True, slots=True)
class PolicyMethodSnapshot:
    tenant_ref: str
    policy_method_ref: str
    policy_digest: str
    method_id: str
    method_version: str
    method_config_digest: str
    taxonomy_mapping_digest: str
    output_schema_digest: str
    expires_at: datetime
    snapshot_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.policy_method_ref, _REF)
        _text(self.method_id, _METHOD)
        _text(self.method_version, _METHOD)
        for item in (self.policy_digest, self.method_config_digest, self.taxonomy_mapping_digest,
                     self.output_schema_digest): _text(item, _DIGEST)
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        object.__setattr__(self, "snapshot_digest", "sha256:" + hashlib.sha256(_canonical(self)).hexdigest())


@dataclass(frozen=True, slots=True)
class PolicyMethodSnapshotFence:
    snapshot: PolicyMethodSnapshot
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime
    def __post_init__(self) -> None:
        if type(self.snapshot) is not PolicyMethodSnapshot or type(self.state) is not str: _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "ACTIVE" or self.event_ref is not None: _fail()
        elif self.generation != 1 or self.state not in _TERMINAL or self.event_ref is None:
            _fail()
        if self.event_ref is not None: _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


def _decode(row: tuple[object, ...] | None) -> PolicyMethodSnapshot | None:
    if row is None: return None
    if len(row) != 9: _fail()
    return PolicyMethodSnapshot(*row)


class PostgresPolicyMethodSnapshotAuthority:
    """Immutable snapshot records fenced by a live M45a3 tenant identity."""
    def __init__(self, connection_factory: Callable[[], Any], tenant_authority: PostgresTenantIdentityAuthority) -> None:
        if not callable(connection_factory) or type(tenant_authority) is not PostgresTenantIdentityAuthority: _fail()
        self._connection_factory, self._tenant_authority = connection_factory, tenant_authority

    def _connection(self) -> Any:
        value = self._connection_factory()
        if value is None or getattr(value, "autocommit", None) is not True: _fail()
        return value

    @staticmethod
    def _close(connection: Any) -> None:
        try: connection.close()
        except Exception: pass
    @staticmethod
    def _rollback(connection: Any) -> None:
        try: connection.rollback()
        except Exception: pass

    @staticmethod
    def _lock(cursor: Any, *, tenant_ref: str, policy_method_ref: str) -> PolicyMethodSnapshot | None:
        cursor.execute("SELECT tenant_ref,policy_method_ref,policy_digest,method_id,method_version,method_config_digest,"
                       "taxonomy_mapping_digest,output_schema_digest,expires_at FROM anonflow_policy_method_snapshots "
                       "WHERE tenant_ref=%s AND policy_method_ref=%s FOR UPDATE", (tenant_ref, policy_method_ref))
        return _decode(_row(cursor))

    @staticmethod
    def _latest(cursor: Any, snapshot: PolicyMethodSnapshot) -> PolicyMethodSnapshotFence | None:
        cursor.execute("SELECT generation,state,event_ref,changed_at FROM anonflow_policy_method_snapshot_fences "
                       "WHERE tenant_ref=%s AND policy_method_ref=%s ORDER BY generation DESC LIMIT 1",
                       (snapshot.tenant_ref, snapshot.policy_method_ref))
        result = _row(cursor)
        if result is None: return None
        if len(result) != 4: _fail()
        return PolicyMethodSnapshotFence(snapshot, *result)

    def _lock_tenant(self, cursor: Any, *, application_tenant: str, tenant_ref: str,
                     expected_tenant_generation: int) -> None:
        # M45a3's stable identity row is the serialization point.  This wrapper
        # supplies the active-transaction guard that its older public helper lacks.
        _active_transaction(cursor)
        self._tenant_authority.lock_active(cursor, application_tenant=application_tenant,
                                           tenant_ref=tenant_ref, expected_generation=expected_tenant_generation)

    def create(self, snapshot: PolicyMethodSnapshot, *, application_tenant: str,
               expected_tenant_generation: int) -> PolicyMethodSnapshotFence:
        if type(snapshot) is not PolicyMethodSnapshot: _fail()
        _generation(expected_tenant_generation)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _active_transaction(cursor)
            _read_committed(cursor)
            self._lock_tenant(cursor, application_tenant=application_tenant, tenant_ref=snapshot.tenant_ref,
                              expected_tenant_generation=expected_tenant_generation)
            if snapshot.expires_at <= _now(cursor): _fail()
            cursor.execute("INSERT INTO anonflow_policy_method_snapshots "
                           "(tenant_ref,policy_method_ref,policy_digest,method_id,method_version,method_config_digest,taxonomy_mapping_digest,output_schema_digest,expires_at) "
                           "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING policy_method_ref",
                           (snapshot.tenant_ref, snapshot.policy_method_ref, snapshot.policy_digest, snapshot.method_id,
                            snapshot.method_version, snapshot.method_config_digest, snapshot.taxonomy_mapping_digest,
                            snapshot.output_schema_digest, snapshot.expires_at))
            inserted = _row(cursor) is not None
            locked = self._lock(cursor, tenant_ref=snapshot.tenant_ref, policy_method_ref=snapshot.policy_method_ref)
            if locked != snapshot: _fail()
            if inserted:
                moment = _now(cursor)
                cursor.execute("INSERT INTO anonflow_policy_method_snapshot_fences "
                               "(tenant_ref,policy_method_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,0,'ACTIVE',NULL,%s)",
                               (snapshot.tenant_ref, snapshot.policy_method_ref, moment))
                if cursor.rowcount != 1: _fail()
                result = PolicyMethodSnapshotFence(snapshot, 0, "ACTIVE", None, moment)
            else:
                result = self._latest(cursor, snapshot)
                if result is None: _fail()
            # Re-read under the held tenant lock immediately before committing.
            self._lock_tenant(cursor, application_tenant=application_tenant, tenant_ref=snapshot.tenant_ref,
                              expected_tenant_generation=expected_tenant_generation)
            if snapshot.expires_at <= _now(cursor): _fail()
            connection.commit()
            return result
        except PostgresPolicyMethodSnapshotError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)

    def lock_active(self, cursor: Any, *, application_tenant: str, tenant_ref: str, policy_method_ref: str,
                    expected_tenant_generation: int, expected_snapshot_digest: str,
                    expected_generation: int) -> PolicyMethodSnapshotFence:
        _text(tenant_ref, _TENANT)
        _text(policy_method_ref, _REF)
        _text(expected_snapshot_digest, _DIGEST)
        _generation(expected_tenant_generation)
        _generation(expected_generation)
        try:
            _active_transaction(cursor)
            _read_committed(cursor)
            self._lock_tenant(cursor, application_tenant=application_tenant, tenant_ref=tenant_ref,
                              expected_tenant_generation=expected_tenant_generation)
            snapshot = self._lock(cursor, tenant_ref=tenant_ref, policy_method_ref=policy_method_ref)
            fence = None if snapshot is None else self._latest(cursor, snapshot)
            if (snapshot is None or fence is None or snapshot.snapshot_digest != expected_snapshot_digest
                    or fence.generation != expected_generation or fence.state != "ACTIVE" or snapshot.expires_at <= _now(cursor)): _fail()
            return fence
        except PostgresPolicyMethodSnapshotError: raise
        except Exception: _fail()

    def fence(self, *, application_tenant: str, tenant_ref: str,
              policy_method_ref: str, expected_tenant_generation: int,
              expected_snapshot_digest: str,
              expected_generation: int) -> PolicyMethodSnapshotFence:
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            result = self.lock_active(
                cursor,
                application_tenant=application_tenant,
                tenant_ref=tenant_ref,
                policy_method_ref=policy_method_ref,
                expected_tenant_generation=expected_tenant_generation,
                expected_snapshot_digest=expected_snapshot_digest,
                expected_generation=expected_generation,
            )
            connection.commit()
            return result
        except PostgresPolicyMethodSnapshotError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)

    def terminal(self, *, application_tenant: str, tenant_ref: str, policy_method_ref: str,
                 expected_tenant_generation: int, expected_generation: int, state: str,
                 event_ref: str) -> PolicyMethodSnapshotFence:
        _text(tenant_ref, _TENANT)
        _text(policy_method_ref, _REF)
        _generation(expected_tenant_generation)
        _generation(expected_generation)
        if type(state) is not str or state not in _TERMINAL: _fail()
        _text(event_ref, _EVENT)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _active_transaction(cursor)
            _read_committed(cursor)
            self._lock_tenant(cursor, application_tenant=application_tenant, tenant_ref=tenant_ref,
                              expected_tenant_generation=expected_tenant_generation)
            snapshot = self._lock(cursor, tenant_ref=tenant_ref, policy_method_ref=policy_method_ref)
            latest = None if snapshot is None else self._latest(cursor, snapshot)
            if latest is None: _fail()
            if latest.generation == expected_generation + 1 and latest.state == state and latest.event_ref == event_ref:
                connection.commit()
                return latest
            moment = _now(cursor)
            if (latest.generation != expected_generation or latest.state != "ACTIVE"
                    or (state == "EXPIRED" and moment < snapshot.expires_at)): _fail()
            cursor.execute("INSERT INTO anonflow_policy_method_snapshot_fences "
                           "(tenant_ref,policy_method_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,%s,%s,%s,%s)",
                           (tenant_ref, policy_method_ref, expected_generation + 1, state, event_ref, moment))
            if cursor.rowcount != 1: _fail()
            result = PolicyMethodSnapshotFence(snapshot, expected_generation + 1, state, event_ref, moment)
            connection.commit()
            return result
        except PostgresPolicyMethodSnapshotError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)
