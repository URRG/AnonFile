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
import hmac
import json
import os
import re
from datetime import UTC, datetime
from typing import Iterable

from app.utility_evidence import DataUtilityReport, UtilityEvidenceAuthority, UtilityEvidenceError


_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"utilsig:v1:[A-Za-z0-9_-]{43}\Z")
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


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _expiry(value: object) -> datetime:
    if type(value) is not str or not 20 <= len(value) <= 40 or not value.endswith("Z") or "+" in value[:-1]:
        _fail()
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            _fail()
        return parsed.astimezone(UTC)
    except (ValueError, OverflowError):
        _fail()


@dataclass(frozen=True, slots=True)
class UtilityEvidenceControlAuthority:
    """One private, tenant-scoped issuer with a public non-secret identity."""

    tenant: str
    key_id: str
    expires_at: datetime
    _authority: UtilityEvidenceAuthority = field(repr=False, compare=False)
    authority_id: str = field(init=False)

    def __post_init__(self) -> None:
        _identity(self.tenant)
        _identity(self.key_id)
        if (not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None
                or self.expires_at.utcoffset() is None):
            _fail()
        if not isinstance(self._authority, UtilityEvidenceAuthority):
            _fail()
        public = {"schema": "utility-evidence-authority-v1", "tenant": self.tenant,
                  "key_id": self.key_id, "expires_at": self.expires_at.astimezone(UTC).isoformat()}
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

    def _message(self, *, tenant: str, run_id: str, processing_request_digest: str,
                 candidate_artifact_digest: str, policy_digest: str, rights_digest: str,
                 method_id: str, method_version: str, method_config_digest: str,
                 taxonomy_mapping_digest: str, idempotency_key: str,
                 report: DataUtilityReport) -> bytes:
        """Canonical control context whose HMAC makes a report admissible."""
        if not isinstance(report, DataUtilityReport) or tenant != self.tenant:
            _fail()
        for value in (run_id, method_id, method_version):
            _identity(value)
        if (type(idempotency_key) is not str or not 1 <= len(idempotency_key) <= 200
                or not idempotency_key.isascii() or any(character.isspace() for character in idempotency_key)):
            _fail()
        for value in (processing_request_digest, candidate_artifact_digest, policy_digest, rights_digest,
                      method_config_digest, taxonomy_mapping_digest):
            _digest(value)
        if report.candidate_artifact_digest != candidate_artifact_digest:
            _fail()
        return _canonical({
            "schema": "utility-evidence-attestation-v1", "authority_id": self.authority_id,
            "tenant": tenant, "run_id": run_id, "processing_request_digest": processing_request_digest,
            "candidate_artifact_digest": candidate_artifact_digest, "policy_digest": policy_digest,
            "rights_digest": rights_digest, "method_id": method_id, "method_version": method_version,
            "method_config_digest": method_config_digest, "taxonomy_mapping_digest": taxonomy_mapping_digest,
            "idempotency_key": idempotency_key,
            # Sign the full canonical source-safe report rather than trusting a
            # caller-provided report digest as a surrogate for its contents.
            "report": report.to_record(),
        })

    def sign_for_worker(self, **binding) -> str:
        """Issue inside the trusted worker; this is not an HTTP-client API."""
        message = self._message(**binding)
        signature = hmac.new(self._authority._secret, message, hashlib.sha256).digest()
        return "utilsig:v1:" + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    def verify(self, *, signature: object, **binding) -> bool:
        if type(signature) is not str or not _SIGNATURE.fullmatch(signature):
            return False
        try:
            supplied = base64.urlsafe_b64decode(signature.split(":", 2)[2] + "=")
            expected = hmac.new(self._authority._secret, self._message(**binding), hashlib.sha256).digest()
            return hmac.compare_digest(supplied, expected)
        except (ValueError, UnicodeError, UtilityEvidenceAuthorityError):
            return False

    def is_active(self, *, at: datetime | None = None) -> bool:
        moment = datetime.now(UTC) if at is None else at
        return (isinstance(moment, datetime) and moment.tzinfo is not None and moment.utcoffset() is not None
                and self.expires_at > moment.astimezone(UTC))


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
            if not isinstance(entry, dict) or set(entry) != {"tenant", "key_id", "expires_at", "key"}:
                _fail()
            if type(entry["key"]) is not str:
                _fail()
            key = base64.b64decode(entry["key"], validate=True)
            authority = UtilityEvidenceControlAuthority(
                tenant=entry["tenant"], key_id=entry["key_id"],
                expires_at=_expiry(entry["expires_at"]),
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


def authority_for_tenant(authorities: Iterable[UtilityEvidenceControlAuthority], *, tenant: str,
                         at: datetime | None = None) -> UtilityEvidenceControlAuthority:
    """Return exactly one configured tenant authority, otherwise fail closed."""
    matches = [item for item in authorities if item.tenant == tenant]
    moment = datetime.now(UTC) if at is None else at
    if len(matches) != 1 or not matches[0].is_active(at=moment):
        _fail()
    return matches[0]
