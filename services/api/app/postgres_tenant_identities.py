"""M45a3 PostgreSQL tenant identity mapping and terminal fence primitive.

This is not tenant provisioning, legal approval, authorization, or a release
workflow.  It only gives a later PostgreSQL-native authority a stable,
one-to-one application-tenant to opaque tenant-reference identity that can be
disabled or quarantined without a stale-active race.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
import re
from typing import Any

_APPLICATION_TENANT = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_TENANT = re.compile(r"tenantref:v1:[A-Za-z0-9_-]{43}\Z")
_EVENT = re.compile(r"tenantfence:v1:[A-Za-z0-9_-]{43}\Z")
_STATES = frozenset({"ACTIVE", "DISABLED", "QUARANTINED"})


class PostgresTenantIdentityError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL tenant identity authority unavailable")


def _fail() -> None:
    raise PostgresTenantIdentityError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1:
        _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try: result = value.astimezone(UTC)
    except (ValueError, OverflowError):
        _fail()
    if result.microsecond:
        _fail()
    return result


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
    value = _row(cursor)
    if value is None or len(value) != 1 or value[0] != "read committed":
        _fail()


def _require_active_transaction(cursor: Any) -> None:
    """Reject a cursor whose row lock would end with its SELECT statement."""
    connection = getattr(cursor, "connection", None)
    info = getattr(connection, "info", None)
    status = getattr(info, "transaction_status", None)
    if getattr(status, "name", None) != "INTRANS":
        _fail()


@dataclass(frozen=True, slots=True)
class TenantIdentity:
    application_tenant: str
    tenant_ref: str

    def __post_init__(self) -> None:
        _text(self.application_tenant, _APPLICATION_TENANT)
        _text(self.tenant_ref, _TENANT)


@dataclass(frozen=True, slots=True)
class TenantIdentityFence:
    identity: TenantIdentity
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime

    def __post_init__(self) -> None:
        if type(self.identity) is not TenantIdentity or type(self.state) is not str or self.state not in _STATES:
            _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "ACTIVE" or self.event_ref is not None:
                _fail()
        elif self.state == "ACTIVE" or self.event_ref is None:
            _fail()
        if self.event_ref is not None: _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


class PostgresTenantIdentityAuthority:
    """Immutable one-to-one mappings with append-only terminal fences.

    A later issuer must retain ``lock_active``'s READ COMMITTED transaction
    through its own mutation. This adapter never provisions identities or
    exposes HTTP.
    """
    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        if not callable(connection_factory):
            _fail()
        self._connection_factory = connection_factory

    def _connection(self) -> Any:
        value = self._connection_factory()
        if value is None or getattr(value, "autocommit", None) is not True:
            _fail()
        return value

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
    def _lock_identity(cursor: Any, application_tenant: str) -> TenantIdentity | None:
        cursor.execute("SELECT application_tenant, tenant_ref FROM anonflow_tenant_identities "
                       "WHERE application_tenant=%s FOR UPDATE", (application_tenant,))
        value = _row(cursor)
        if value is None:
            return None
        if len(value) != 2:
            _fail()
        return TenantIdentity(value[0], value[1])

    @staticmethod
    def _latest(cursor: Any, identity: TenantIdentity) -> TenantIdentityFence | None:
        cursor.execute("SELECT generation, state, event_ref, changed_at FROM anonflow_tenant_identity_fences "
                       "WHERE application_tenant=%s ORDER BY generation DESC LIMIT 1", (identity.application_tenant,))
        value = _row(cursor)
        if value is None:
            return None
        if len(value) != 4:
            _fail()
        return TenantIdentityFence(identity, value[0], value[1], value[2], value[3])

    def create(self, identity: TenantIdentity) -> TenantIdentityFence:
        if type(identity) is not TenantIdentity:
            _fail()
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            moment = _database_now(cursor)
            cursor.execute("INSERT INTO anonflow_tenant_identities (application_tenant, tenant_ref) VALUES (%s,%s) "
                           "ON CONFLICT DO NOTHING RETURNING application_tenant", (identity.application_tenant, identity.tenant_ref))
            inserted = _row(cursor) is not None
            locked = self._lock_identity(cursor, identity.application_tenant)
            if locked != identity:
                _fail()
            current = self._latest(cursor, locked)
            if inserted:
                cursor.execute("INSERT INTO anonflow_tenant_identity_fences "
                               "(application_tenant,generation,state,event_ref,changed_at) VALUES (%s,0,'ACTIVE',NULL,%s)",
                               (identity.application_tenant, moment))
                if cursor.rowcount != 1:
                    _fail()
                current = TenantIdentityFence(identity, 0, "ACTIVE", None, moment)
            if current is None:
                _fail()
            connection.commit()
            return current
        except PostgresTenantIdentityError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)

    def lock_active(self, cursor: Any, *, application_tenant: str, tenant_ref: str,
                    expected_generation: int) -> TenantIdentityFence:
        _text(application_tenant, _APPLICATION_TENANT)
        _text(tenant_ref, _TENANT)
        _generation(expected_generation)
        try:
            _require_active_transaction(cursor)
            _require_read_committed(cursor)
            identity = self._lock_identity(cursor, application_tenant)
            fence = None if identity is None else self._latest(cursor, identity)
            if (identity is None or identity.tenant_ref != tenant_ref or fence is None
                    or fence.generation != expected_generation or fence.state != "ACTIVE"):
                _fail()
            return fence
        except PostgresTenantIdentityError:
            raise
        except Exception:
            _fail()

    def fence(self, *, application_tenant: str, tenant_ref: str,
              expected_generation: int) -> TenantIdentityFence:
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            result = self.lock_active(cursor, application_tenant=application_tenant, tenant_ref=tenant_ref,
                                      expected_generation=expected_generation)
            connection.commit()
            return result
        except PostgresTenantIdentityError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)

    def terminal(self, *, application_tenant: str, tenant_ref: str, expected_generation: int,
                 state: str, event_ref: str) -> TenantIdentityFence:
        _text(application_tenant, _APPLICATION_TENANT)
        _text(tenant_ref, _TENANT)
        _generation(expected_generation)
        if type(state) is not str or state not in {"DISABLED", "QUARANTINED"}:
            _fail()
        _text(event_ref, _EVENT)
        connection = None
        try:
            connection = self._connection()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            _require_read_committed(cursor)
            identity = self._lock_identity(cursor, application_tenant)
            latest = None if identity is None else self._latest(cursor, identity)
            if identity is None or identity.tenant_ref != tenant_ref or latest is None:
                _fail()
            if (latest.generation == expected_generation + 1 and latest.state == state and latest.event_ref == event_ref):
                connection.commit()
                return latest
            if latest.generation != expected_generation or latest.state != "ACTIVE":
                _fail()
            moment = _database_now(cursor)
            cursor.execute("INSERT INTO anonflow_tenant_identity_fences "
                           "(application_tenant,generation,state,event_ref,changed_at) VALUES (%s,%s,%s,%s,%s)",
                           (application_tenant, expected_generation + 1, state, event_ref, moment))
            if cursor.rowcount != 1:
                _fail()
            result = TenantIdentityFence(identity, expected_generation + 1, state, event_ref, moment)
            connection.commit()
            return result
        except PostgresTenantIdentityError:
            if connection is not None: self._rollback(connection)
            raise
        except Exception:
            if connection is not None: self._rollback(connection)
            _fail()
        finally:
            if connection is not None: self._close(connection)
