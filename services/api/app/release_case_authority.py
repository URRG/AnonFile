"""Local, server-owned release-case issuer configuration.

An HTTP caller never provides recipient material, a contract binding, or an
issuer key.  This module loads those private/operator-controlled values only
at process startup and supplies one tenant-scoped authority to the trusted
worker path.  It is intentionally not release authorization or delivery.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import UTC, datetime
import json
import os
import re
from typing import Iterable

from app.release_case import ReleaseCaseAuthority, ReleaseCaseError


_MAX_CONFIG_BYTES = 32_000
_CONTRACT_REFERENCE = re.compile(r"contract-reference:v1:[A-Za-z0-9_-]{43}\Z")


class ReleaseCaseAuthorityError(ValueError):
    """Fixed configuration failure; never reflect contract/recipient secrets."""

    def __init__(self) -> None:
        super().__init__("Invalid release-case authority")


def _fail() -> None:
    raise ReleaseCaseAuthorityError()


def _expiry(value: object) -> datetime:
    if type(value) is not str or not 20 <= len(value) <= 40 or not value.endswith("Z") or "+" in value[:-1]:
        _fail()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if parsed.tzinfo is None or parsed.utcoffset() is None or parsed.microsecond:
            _fail()
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        _fail()


@dataclass(frozen=True, slots=True)
class ReleaseCaseControlAuthority:
    """Exact tenant issuer plus a server-owned contract scope."""

    issuer: ReleaseCaseAuthority = field(repr=False, compare=False)
    contract_reference: str = field(repr=False)
    contract_digest: str
    contract_expires_at: datetime

    def __post_init__(self) -> None:
        if (type(self) is not ReleaseCaseControlAuthority or type(self.issuer) is not ReleaseCaseAuthority
                or type(self.contract_reference) is not str or not _CONTRACT_REFERENCE.fullmatch(self.contract_reference)
                or type(self.contract_digest) is not str
                or not self.contract_digest.startswith("sha256:") or len(self.contract_digest) != 71
                or any(char not in "0123456789abcdef" for char in self.contract_digest[7:])
                or not isinstance(self.contract_expires_at, datetime) or self.contract_expires_at.tzinfo is None
                or self.contract_expires_at.utcoffset() is None or self.contract_expires_at.microsecond):
            _fail()
        if self.contract_expires_at.astimezone(UTC) <= datetime.now(UTC).replace(microsecond=0):
            _fail()

    @property
    def tenant(self) -> str:
        return self.issuer.tenant

    @property
    def authority_id(self) -> str:
        return self.issuer.authority_id

    def is_active(self, *, at: datetime | None = None) -> bool:
        return self.issuer.is_active(at=at)


def load_release_case_authorities() -> tuple[ReleaseCaseControlAuthority, ...]:
    """Load explicit per-tenant recipient/contract custody; missing config fails closed."""
    raw = os.getenv("ANONFLOW_RELEASE_CASE_AUTHORITIES", "")
    if not raw:
        return ()
    if len(raw.encode("utf-8")) > _MAX_CONFIG_BYTES:
        _fail()
    try:
        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError
                result[key] = value
            return result
        entries = json.loads(raw, object_pairs_hook=unique_object, parse_constant=lambda value: (_ for _ in ()).throw(ValueError()))
        if type(entries) is not list or not entries or len(entries) > 64:
            _fail()
        result, tenants = [], set()
        required = {"tenant", "issuer_key_id", "expires_at", "private_key", "recipient_commitment_salt",
                    "contract_reference", "contract_digest", "contract_expires_at"}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != required or type(entry["private_key"]) is not str or type(entry["recipient_commitment_salt"]) is not str:
                _fail()
            salt = base64.b64decode(entry["recipient_commitment_salt"], validate=True)
            issuer = ReleaseCaseAuthority(tenant=entry["tenant"], issuer_key_id=entry["issuer_key_id"],
                                          expires_at=_expiry(entry["expires_at"]),
                                          recipient_commitment_key_id="recipient-commitment-v1",
                                          private_key_b64=entry["private_key"], recipient_commitment_salt=salt)
            authority = ReleaseCaseControlAuthority(issuer=issuer, contract_reference=entry["contract_reference"],
                                                     contract_digest=entry["contract_digest"],
                                                     contract_expires_at=_expiry(entry["contract_expires_at"]))
            if authority.tenant in tenants:
                _fail()
            tenants.add(authority.tenant)
            result.append(authority)
        return tuple(result)
    except (TypeError, ValueError, UnicodeError, binascii.Error, ReleaseCaseError, ReleaseCaseAuthorityError):
        _fail()


def authority_for_tenant(authorities: Iterable[ReleaseCaseControlAuthority], *, tenant: str,
                         at: datetime | None = None) -> ReleaseCaseControlAuthority:
    matches = [item for item in authorities if type(item) is ReleaseCaseControlAuthority and item.tenant == tenant]
    moment = datetime.now(UTC).replace(microsecond=0) if at is None else at
    if len(matches) != 1 or not matches[0].is_active(at=moment):
        _fail()
    return matches[0]
