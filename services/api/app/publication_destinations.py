"""Pure M44b server-owned publication-destination configuration.

This value layer resolves a destination only from an authenticated application's
tenant identity, an opaque destination reference, and trusted configuration.
It does not authorize a release, create a publication plan, expose a buyer, or
perform database/signing/network I/O.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import json
import re
from types import MappingProxyType


_APPLICATION_TENANT = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_TENANT_REF = re.compile(r"tenantref:v1:[A-Za-z0-9_-]{43}\Z")
_DESTINATION_REF = re.compile(r"destinationref:v1:[A-Za-z0-9_-]{43}\Z")
_RECIPIENT = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_PURPOSE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_METADATA_KIND = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
_KEY_REF = re.compile(r"keyref:v1:[a-z0-9][a-z0-9._:-]{0,95}\Z")
_OUTPUT_PROFILE = "candidate-canonical-binary-v1"
_STATUSES = frozenset({"ACTIVE", "INACTIVE"})
_MAX_DESTINATIONS = 64
_DOMAIN = b"anonflow-publication-destination:v1\0"


class PublicationDestinationError(ValueError):
    """Fixed fail-closed result which never reflects recipient configuration."""

    def __init__(self) -> None:
        super().__init__("publication destination unavailable")


def _fail() -> None:
    raise PublicationDestinationError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try:
        result = value.astimezone(UTC)
    except (OverflowError, ValueError):
        _fail()
    if result.microsecond:
        _fail()
    return result


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _canonical(value: object) -> bytes:
    try:
        return _DOMAIN + json.dumps(value, ensure_ascii=True, allow_nan=False,
                                    sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _digest_fields(item: "PublicationDestination") -> dict[str, object]:
    """Internal canonical form; it includes the config-only recipient label."""
    return {
        "application_tenant": item.application_tenant,
        "contract_digest": item.contract_digest,
        "destination_ref": item.destination_ref,
        "expires_at": _instant(item.expires_at),
        "key_ref": item.key_ref,
        "metadata_kind": item.metadata_kind,
        "not_before": _instant(item.not_before),
        "output_profile": item.output_profile,
        "purpose_code": item.purpose_code,
        "recipient_label": item.recipient_label,
        "status": item.status,
        "tenant_ref": item.tenant_ref,
        "version": item.version,
    }


@dataclass(frozen=True, slots=True)
class PublicationDestination:
    """One immutable server-provisioned destination profile.

    The recipient label is configuration-only.  It is deliberately absent from
    ``repr`` but included in the canonical digest so a later trusted issuer can
    match it to a verified release-case recipient commitment.
    """

    application_tenant: str
    tenant_ref: str
    destination_ref: str
    recipient_label: str = field(repr=False)
    purpose_code: str
    contract_digest: str
    metadata_kind: str
    key_ref: str
    version: int
    not_before: datetime
    expires_at: datetime
    status: str
    output_profile: str = _OUTPUT_PROFILE
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.application_tenant, _APPLICATION_TENANT)
        _text(self.tenant_ref, _TENANT_REF)
        _text(self.destination_ref, _DESTINATION_REF)
        _text(self.recipient_label, _RECIPIENT)
        _text(self.purpose_code, _PURPOSE)
        _text(self.contract_digest, _DIGEST)
        _text(self.metadata_kind, _METADATA_KIND)
        _text(self.key_ref, _KEY_REF)
        if type(self.version) is not int or isinstance(self.version, bool) or not 1 <= self.version <= 2**63 - 1:
            _fail()
        object.__setattr__(self, "not_before", _time(self.not_before))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if (self.expires_at <= self.not_before or type(self.status) is not str
                or self.status not in _STATUSES):
            _fail()
        if type(self.output_profile) is not str or self.output_profile != _OUTPUT_PROFILE:
            _fail()
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(
            _canonical(_digest_fields(self))).hexdigest())

    def is_active(self, *, at: datetime) -> bool:
        try:
            moment = _time(at)
            return self.status == "ACTIVE" and self.not_before <= moment < self.expires_at
        except PublicationDestinationError:
            return False


@dataclass(frozen=True, slots=True, init=False)
class PublicationDestinationRegistry:
    """Bounded immutable configuration; no caller plan fields enter resolution."""

    _by_destination: Mapping[str, PublicationDestination] = field(init=False, repr=False)
    _tenant_refs: Mapping[str, str] = field(init=False, repr=False)

    def __init__(self, destinations: tuple[PublicationDestination, ...]) -> None:
        if (type(destinations) is not tuple or not 1 <= len(destinations) <= _MAX_DESTINATIONS
                or any(type(item) is not PublicationDestination for item in destinations)):
            _fail()
        by_destination: dict[str, PublicationDestination] = {}
        tenant_refs: dict[str, str] = {}
        reverse_tenants: dict[str, str] = {}
        for item in destinations:
            if item.destination_ref in by_destination:
                _fail()
            mapped = tenant_refs.setdefault(item.application_tenant, item.tenant_ref)
            if mapped != item.tenant_ref:
                # One authenticated application tenant can never choose among
                # PG tenants by choosing a destination reference.
                _fail()
            owner = reverse_tenants.setdefault(item.tenant_ref, item.application_tenant)
            if owner != item.application_tenant:
                # The reverse collision would collapse two authenticated
                # application tenants into one PostgreSQL authorization scope.
                _fail()
            by_destination[item.destination_ref] = item
        object.__setattr__(self, "_by_destination", MappingProxyType(by_destination))
        object.__setattr__(self, "_tenant_refs", MappingProxyType(tenant_refs))

    def resolve(self, *, application_tenant: object, destination_ref: object,
                at: object) -> PublicationDestination:
        """Resolve only an active destination owned by this application tenant."""
        tenant = _text(application_tenant, _APPLICATION_TENANT)
        reference = _text(destination_ref, _DESTINATION_REF)
        moment = _time(at)
        result = self._by_destination.get(reference)
        if result is None or result.application_tenant != tenant or not result.is_active(at=moment):
            _fail()
        return result

    def tenant_ref_for(self, *, application_tenant: object) -> str:
        """Return the unique server-configured PG tenant mapping, if any."""
        tenant = _text(application_tenant, _APPLICATION_TENANT)
        result = self._tenant_refs.get(tenant)
        if result is None:
            _fail()
        return result
