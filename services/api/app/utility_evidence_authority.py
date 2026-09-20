"""Server-owned authority selection for trusted utility-evidence workers.

The HTTP API never receives a utility commitment secret, source commitment, or
source/candidate body.  A tenant-scoped worker authority is loaded locally and
is used only after the store has supplied the private source and candidate.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import hashlib
import json
import os
import re
from typing import Iterable

from app.utility_evidence import UtilityEvidenceAuthority, UtilityEvidenceError


_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_MAX_CONFIG_BYTES = 32_000


class UtilityEvidenceAuthorityError(ValueError):
    """Fixed configuration failure which never exposes a secret."""

    def __init__(self) -> None:
        super().__init__("Invalid utility-evidence authority")


def _fail() -> None:
    raise UtilityEvidenceAuthorityError()


def _identity(value: object) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail()
    return value


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


@dataclass(frozen=True, slots=True)
class UtilityEvidenceControlAuthority:
    """One private, tenant-scoped issuer with a public non-secret identity."""

    tenant: str
    key_id: str
    _authority: UtilityEvidenceAuthority = field(repr=False, compare=False)
    authority_id: str = field(init=False)

    def __post_init__(self) -> None:
        _identity(self.tenant)
        _identity(self.key_id)
        if not isinstance(self._authority, UtilityEvidenceAuthority):
            _fail()
        public = {"schema": "utility-evidence-authority-v1", "tenant": self.tenant,
                  "key_id": self.key_id}
        object.__setattr__(self, "authority_id", "sha256:" + hashlib.sha256(_canonical(public)).hexdigest())

    def issue(self, source: object) -> str:
        try:
            return self._authority.issue(source)  # type: ignore[arg-type]
        except UtilityEvidenceError:
            _fail()

    @property
    def verifier(self) -> UtilityEvidenceAuthority:
        """Trusted-worker-only verifier; it is never serialized into controls."""
        return self._authority


def load_utility_evidence_authorities() -> tuple[UtilityEvidenceControlAuthority, ...]:
    """Load explicit local authority configuration; absence admits no evidence."""
    raw = os.getenv("ANONFLOW_UTILITY_EVIDENCE_AUTHORITIES", "")
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

        def no_constant(value):
            raise ValueError

        entries = json.loads(raw, object_pairs_hook=unique_object, parse_constant=no_constant)
        if type(entries) is not list or not entries or len(entries) > 64:
            _fail()
        result = []
        tenants = set()
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"tenant", "key_id", "key"}:
                _fail()
            if type(entry["key"]) is not str:
                _fail()
            key = base64.b64decode(entry["key"], validate=True)
            authority = UtilityEvidenceControlAuthority(
                tenant=entry["tenant"], key_id=entry["key_id"],
                _authority=UtilityEvidenceAuthority.from_secret(key),
            )
            if authority.tenant in tenants:
                _fail()
            tenants.add(authority.tenant)
            result.append(authority)
        return tuple(result)
    except (TypeError, ValueError, UnicodeError, binascii.Error, UtilityEvidenceError,
            UtilityEvidenceAuthorityError):
        _fail()


def authority_for_tenant(authorities: Iterable[UtilityEvidenceControlAuthority], *, tenant: str) -> UtilityEvidenceControlAuthority:
    """Return exactly one configured tenant authority, otherwise fail closed."""
    matches = [item for item in authorities if item.tenant == tenant]
    if len(matches) != 1:
        _fail()
    return matches[0]
