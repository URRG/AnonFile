"""M49a1 inert, tenant-bound supplier-organization identity metadata ledger.

This is not a supplier onboarding API, a signing workflow, or an assertion of
legal validity.  Callers of this adapter must already be trusted server-side
administrators; it deliberately offers no self-provisioning surface.
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
_REF = re.compile(r"supplierorgref:v1:" + _OPAQUE + r"\Z")
_CASE = re.compile(r"supplierorgcase:v1:" + _OPAQUE + r"\Z")
_EVENT = re.compile(r"supplierorgfence:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_TERMINAL = frozenset({"QUARANTINED", "REVOKED", "EXPIRED"})
_DOMAIN = b"anonflow-supplier-organization-identity:v1\0"


class PostgresSupplierOrganizationError(RuntimeError):
    def __init__(self) -> None: super().__init__("PostgreSQL supplier organization authority unavailable")


def _fail() -> None: raise PostgresSupplierOrganizationError() from None
def _text(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value): _fail()
    return value
def _generation(value: object) -> int:
    if type(value) is not int or isinstance(value, bool) or not 0 <= value <= 2**63 - 1: _fail()
    return value
def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None: _fail()
    try: value = value.astimezone(UTC)
    except (ValueError, OverflowError): _fail()
    if value.microsecond: _fail()
    return value
def _row(cursor: Any) -> tuple[object, ...] | None:
    value = cursor.fetchone()
    if value is not None and type(value) is not tuple: _fail()
    return value
def _now(cursor: Any) -> datetime:
    cursor.execute("SELECT date_trunc('second', clock_timestamp())")
    value = _row(cursor)
    if value is None or len(value) != 1: _fail()
    return _time(value[0])
def _read_committed(cursor: Any) -> None:
    cursor.execute("SHOW transaction_isolation")
    value = _row(cursor)
    if value is None or len(value) != 1 or value[0] != "read committed": _fail()
def _active_transaction(cursor: Any) -> None:
    status = getattr(getattr(getattr(cursor, "connection", None), "info", None), "transaction_status", None)
    if getattr(status, "name", None) != "INTRANS": _fail()


@dataclass(frozen=True, slots=True)
class SupplierOrganization:
    tenant_ref: str
    supplier_org_ref: str
    provisioning_case_ref: str
    evidence_digest: str
    expires_at: datetime
    identity_digest: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT); _text(self.supplier_org_ref, _REF)
        _text(self.provisioning_case_ref, _CASE); _text(self.evidence_digest, _DIGEST)
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        record = {"evidence_digest": self.evidence_digest, "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
                  "provisioning_case_ref": self.provisioning_case_ref, "supplier_org_ref": self.supplier_org_ref,
                  "tenant_ref": self.tenant_ref}
        try: encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")
        except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError): _fail()
        object.__setattr__(self, "identity_digest", "sha256:" + hashlib.sha256(_DOMAIN + encoded).hexdigest())


@dataclass(frozen=True, slots=True)
class SupplierOrganizationFence:
    organization: SupplierOrganization
    generation: int
    state: str
    event_ref: str | None
    changed_at: datetime
    def __post_init__(self) -> None:
        if type(self.organization) is not SupplierOrganization or type(self.state) is not str: _fail()
        _generation(self.generation)
        if self.generation == 0:
            if self.state != "ACTIVE" or self.event_ref is not None: _fail()
        elif self.generation != 1 or self.state not in _TERMINAL or self.event_ref is None: _fail()
        if self.event_ref is not None: _text(self.event_ref, _EVENT)
        object.__setattr__(self, "changed_at", _time(self.changed_at))


def _decode(row: tuple[object, ...] | None) -> SupplierOrganization | None:
    if row is None: return None
    if len(row) != 5: _fail()
    return SupplierOrganization(*row)


class PostgresSupplierOrganizationAuthority:
    """Database-only immutable metadata authority; it creates no HTTP route."""
    def __init__(self, connection_factory: Callable[[], Any], tenant_authority: PostgresTenantIdentityAuthority) -> None:
        if not callable(connection_factory) or type(tenant_authority) is not PostgresTenantIdentityAuthority: _fail()
        self._connection_factory, self._tenant_authority = connection_factory, tenant_authority
    def _connection(self) -> Any:
        value = self._connection_factory()
        if value is None or getattr(value, "autocommit", None) is not True: _fail()
        return value
    @staticmethod
    def _finish(connection: Any, rollback: bool = False) -> None:
        try: connection.rollback() if rollback else connection.close()
        except Exception: pass
    @staticmethod
    def _lock(cursor: Any, tenant_ref: str, supplier_org_ref: str) -> SupplierOrganization | None:
        cursor.execute("SELECT tenant_ref,supplier_org_ref,provisioning_case_ref,evidence_digest,expires_at FROM anonflow_supplier_organizations WHERE tenant_ref=%s AND supplier_org_ref=%s FOR UPDATE", (tenant_ref, supplier_org_ref))
        return _decode(_row(cursor))
    @staticmethod
    def _latest(cursor: Any, organization: SupplierOrganization) -> SupplierOrganizationFence | None:
        cursor.execute("SELECT generation,state,event_ref,changed_at FROM anonflow_supplier_organization_fences WHERE tenant_ref=%s AND supplier_org_ref=%s ORDER BY generation DESC LIMIT 1", (organization.tenant_ref, organization.supplier_org_ref))
        value = _row(cursor)
        if value is None: return None
        if len(value) != 4: _fail()
        return SupplierOrganizationFence(organization, *value)
    def _lock_tenant(self, cursor: Any, application_tenant: str, tenant_ref: str, generation: int) -> None:
        _active_transaction(cursor)
        self._tenant_authority.lock_active(cursor, application_tenant=application_tenant, tenant_ref=tenant_ref, expected_generation=generation)

    def create(self, organization: SupplierOrganization, *, application_tenant: str, expected_tenant_generation: int) -> SupplierOrganizationFence:
        if type(organization) is not SupplierOrganization: _fail()
        _generation(expected_tenant_generation); connection = None
        try:
            connection = self._connection(); cursor = connection.cursor(); cursor.execute("BEGIN"); _read_committed(cursor)
            self._lock_tenant(cursor, application_tenant, organization.tenant_ref, expected_tenant_generation)
            if organization.expires_at <= _now(cursor): _fail()
            cursor.execute("INSERT INTO anonflow_supplier_organizations (tenant_ref,supplier_org_ref,provisioning_case_ref,evidence_digest,expires_at) VALUES (%s,%s,%s,%s,%s) ON CONFLICT DO NOTHING RETURNING supplier_org_ref", (organization.tenant_ref, organization.supplier_org_ref, organization.provisioning_case_ref, organization.evidence_digest, organization.expires_at))
            inserted = _row(cursor) is not None; locked = self._lock(cursor, organization.tenant_ref, organization.supplier_org_ref)
            if locked != organization: _fail()
            if inserted:
                moment = _now(cursor); cursor.execute("INSERT INTO anonflow_supplier_organization_fences (tenant_ref,supplier_org_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,0,'ACTIVE',NULL,%s)", (organization.tenant_ref, organization.supplier_org_ref, moment))
                if cursor.rowcount != 1: _fail()
                result = SupplierOrganizationFence(organization, 0, "ACTIVE", None, moment)
            else:
                result = self._latest(cursor, organization)
                if result is None: _fail()
            self._lock_tenant(cursor, application_tenant, organization.tenant_ref, expected_tenant_generation)
            if result.generation != 0 or result.state != "ACTIVE" or organization.expires_at <= _now(cursor): _fail()
            connection.commit(); return result
        except PostgresSupplierOrganizationError:
            if connection is not None: self._finish(connection, True)
            raise
        except Exception:
            if connection is not None: self._finish(connection, True)
            _fail()
        finally:
            if connection is not None: self._finish(connection)

    def lock_active(self, cursor: Any, *, application_tenant: str, tenant_ref: str, supplier_org_ref: str, expected_tenant_generation: int, expected_identity_digest: str, expected_generation: int) -> SupplierOrganizationFence:
        _text(tenant_ref, _TENANT); _text(supplier_org_ref, _REF); _text(expected_identity_digest, _DIGEST)
        _generation(expected_tenant_generation); _generation(expected_generation)
        try:
            _active_transaction(cursor); _read_committed(cursor); self._lock_tenant(cursor, application_tenant, tenant_ref, expected_tenant_generation)
            organization = self._lock(cursor, tenant_ref, supplier_org_ref); fence = None if organization is None else self._latest(cursor, organization)
            if organization is None or fence is None or organization.identity_digest != expected_identity_digest or fence.generation != expected_generation or fence.state != "ACTIVE" or organization.expires_at <= _now(cursor): _fail()
            return fence
        except PostgresSupplierOrganizationError: raise
        except Exception: _fail()

    def fence(self, **kwargs: Any) -> SupplierOrganizationFence:
        connection = None
        try:
            connection = self._connection(); cursor = connection.cursor(); cursor.execute("BEGIN")
            result = self.lock_active(cursor, **kwargs); connection.commit(); return result
        except PostgresSupplierOrganizationError:
            if connection is not None: self._finish(connection, True)
            raise
        except Exception:
            if connection is not None: self._finish(connection, True)
            _fail()
        finally:
            if connection is not None: self._finish(connection)

    def terminal(self, *, application_tenant: str, tenant_ref: str, supplier_org_ref: str, expected_tenant_generation: int, expected_generation: int, state: str, event_ref: str) -> SupplierOrganizationFence:
        _text(tenant_ref, _TENANT); _text(supplier_org_ref, _REF); _generation(expected_tenant_generation); _generation(expected_generation)
        if type(state) is not str or state not in _TERMINAL: _fail()
        _text(event_ref, _EVENT); connection = None
        try:
            connection = self._connection(); cursor = connection.cursor(); cursor.execute("BEGIN"); _read_committed(cursor)
            self._lock_tenant(cursor, application_tenant, tenant_ref, expected_tenant_generation); organization = self._lock(cursor, tenant_ref, supplier_org_ref); latest = None if organization is None else self._latest(cursor, organization)
            if latest is None: _fail()
            if latest.generation == expected_generation + 1 and latest.state == state and latest.event_ref == event_ref:
                connection.commit(); return latest
            moment = _now(cursor)
            if latest.generation != expected_generation or latest.state != "ACTIVE" or (state == "EXPIRED" and moment < organization.expires_at): _fail()
            cursor.execute("INSERT INTO anonflow_supplier_organization_fences (tenant_ref,supplier_org_ref,generation,state,event_ref,changed_at) VALUES (%s,%s,%s,%s,%s,%s)", (tenant_ref, supplier_org_ref, expected_generation + 1, state, event_ref, moment))
            if cursor.rowcount != 1: _fail()
            result = SupplierOrganizationFence(organization, expected_generation + 1, state, event_ref, moment); connection.commit(); return result
        except PostgresSupplierOrganizationError:
            if connection is not None: self._finish(connection, True)
            raise
        except Exception:
            if connection is not None: self._finish(connection, True)
            _fail()
        finally:
            if connection is not None: self._finish(connection)
