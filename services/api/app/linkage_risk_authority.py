"""Server-owned linkage configuration and attestation for trusted workers.

The HTTP API never accepts a linkage selection, reference records, a key, or
an alleged report.  Those values are loaded locally and remain inside the
trusted worker boundary; persisted controls contain only signed aggregate
evidence and opaque commitments.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import os
import re
from typing import Iterable

from app.linkage_risk import (LinkageCommitmentAuthority, LinkageKeyConfig,
                              LinkageReference, LinkageRiskError,
                              LinkageRiskReport, METHODOLOGY_DIGEST)


_ID = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"linksig:v1:[A-Za-z0-9_-]{43}\Z")
_REVISION = re.compile(r"linkrev:v1:[A-Za-z0-9_-]{43}\Z")
_MAX_CONFIG_BYTES = 64_000


class LinkageRiskAuthorityError(ValueError):
    """Fixed configuration/attestation failure with no sensitive reflection."""

    def __init__(self) -> None:
        super().__init__("Invalid linkage-risk authority")


def _fail() -> None:
    raise LinkageRiskAuthorityError()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _identifier(value: object) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        _fail()
    return value


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
class LinkageRiskControlAuthority:
    """Private tenant issuer with an opaque, configuration-bound identity."""

    tenant: str
    key_id: str
    expires_at: datetime
    _authority: LinkageCommitmentAuthority = field(repr=False, compare=False)
    _linkage_keys: LinkageKeyConfig = field(repr=False, compare=False)
    _reference: LinkageReference = field(repr=False, compare=False)
    linkage_config_revision: str = field(init=False)
    authority_id: str = field(init=False)

    def __post_init__(self) -> None:
        # This class is a trust boundary.  Subclasses can override public
        # properties or verification methods, so only this exact immutable
        # record type is a valid server authority.
        if type(self) is not LinkageRiskControlAuthority:
            _fail()
        _identifier(self.tenant)
        _identifier(self.key_id)
        if (not isinstance(self.expires_at, datetime) or self.expires_at.tzinfo is None
                or self.expires_at.utcoffset() is None
                or type(self._authority) is not LinkageCommitmentAuthority
                or type(self._linkage_keys) is not LinkageKeyConfig
                or type(self._reference) is not LinkageReference
                or not self._authority.verifies_key_config(self._linkage_keys)
                or not self._authority.verifies_reference(self._reference, linkage_keys=self._linkage_keys)):
            _fail()
        # The keyed revision binds both the private field selection and private
        # reference representation, without revealing either one.
        revision = "linkrev:v1:" + base64.urlsafe_b64encode(hmac.new(
            self._authority._secret,
            _canonical({"schema": "linkage-risk-config-v1", "fields": self._linkage_keys._fields,
                        "reference_commitment": self._reference.public_commitment}),
            hashlib.sha256).digest()).decode("ascii").rstrip("=")
        if not _REVISION.fullmatch(revision):
            _fail()
        object.__setattr__(self, "linkage_config_revision", revision)
        public = {"schema": "linkage-risk-authority-v1", "tenant": self.tenant, "key_id": self.key_id,
                  "expires_at": self.expires_at.astimezone(UTC).isoformat(),
                  "linkage_config_revision": revision}
        object.__setattr__(self, "authority_id", "sha256:" + hashlib.sha256(_canonical(public)).hexdigest())

    @property
    def linkage_keys(self) -> LinkageKeyConfig:
        return self._linkage_keys

    @property
    def reference(self) -> LinkageReference:
        return self._reference

    @property
    def commitment_verifier(self) -> LinkageCommitmentAuthority:
        return self._authority

    def is_active(self, *, at: datetime | None = None) -> bool:
        moment = datetime.now(UTC) if at is None else at
        return (isinstance(moment, datetime) and moment.tzinfo is not None and moment.utcoffset() is not None
                and self.expires_at > moment.astimezone(UTC))

    def _message(self, *, tenant: str, run_id: str, processing_request_digest: str,
                 candidate_artifact_digest: str, policy_digest: str, rights_digest: str,
                 method_id: str, method_version: str, method_config_digest: str,
                 taxonomy_mapping_digest: str, idempotency_key: str,
                 linkage_config_revision: str, report: LinkageRiskReport) -> bytes:
        if not isinstance(report, LinkageRiskReport) or tenant != self.tenant:
            _fail()
        for value in (run_id, method_id, method_version):
            _identifier(value)
        for value in (processing_request_digest, candidate_artifact_digest, policy_digest, rights_digest,
                      method_config_digest, taxonomy_mapping_digest):
            _digest(value)
        if (type(idempotency_key) is not str or not 1 <= len(idempotency_key) <= 200
                or not idempotency_key.isascii() or any(character.isspace() for character in idempotency_key)
                or linkage_config_revision != self.linkage_config_revision
                or report.candidate_artifact_digest != candidate_artifact_digest
                or report.linkage_key_commitment != self._linkage_keys.public_commitment
                or report.linkage_key_count != self._linkage_keys.field_count
                or report.reference_commitment != self._reference.public_commitment
                or report.methodology_digest != METHODOLOGY_DIGEST):
            _fail()
        return _canonical({
            "schema": "linkage-risk-attestation-v1", "authority_id": self.authority_id,
            "tenant": tenant, "run_id": run_id, "processing_request_digest": processing_request_digest,
            "candidate_artifact_digest": candidate_artifact_digest, "policy_digest": policy_digest,
            "rights_digest": rights_digest, "method_id": method_id, "method_version": method_version,
            "method_config_digest": method_config_digest,
            "taxonomy_mapping_digest": taxonomy_mapping_digest, "idempotency_key": idempotency_key,
            "linkage_config_revision": linkage_config_revision, "report": report.to_record(),
        })

    def sign_for_worker(self, **binding) -> str:
        """Sign inside the trusted worker only; never expose this to HTTP clients."""
        return "linksig:v1:" + base64.urlsafe_b64encode(hmac.new(
            self._authority._secret, self._message(**binding), hashlib.sha256).digest()).decode("ascii").rstrip("=")

    def verify(self, *, signature: object, **binding) -> bool:
        if type(signature) is not str or not _SIGNATURE.fullmatch(signature):
            return False
        try:
            supplied = base64.urlsafe_b64decode(signature.split(":", 2)[2] + "=")
            expected = hmac.new(self._authority._secret, self._message(**binding), hashlib.sha256).digest()
            return hmac.compare_digest(supplied, expected)
        except (ValueError, UnicodeError, LinkageRiskAuthorityError):
            return False


def load_linkage_risk_authorities() -> tuple[LinkageRiskControlAuthority, ...]:
    """Load local linkage references. Missing/invalid config admits no evidence."""
    raw = os.getenv("ANONFLOW_LINKAGE_RISK_AUTHORITIES", "")
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
            if (not isinstance(entry, dict) or set(entry) != {"tenant", "key_id", "expires_at", "key",
                                                              "linkage_key_fields", "reference_records"}
                    or type(entry["key"]) is not str):
                _fail()
            secret = base64.b64decode(entry["key"], validate=True)
            issuer = LinkageCommitmentAuthority.from_secret(secret)
            keys = issuer.issue_key_config(entry["linkage_key_fields"])
            reference = issuer.create_reference(entry["reference_records"], linkage_keys=keys)
            authority = LinkageRiskControlAuthority(
                tenant=entry["tenant"], key_id=entry["key_id"], expires_at=_expiry(entry["expires_at"]),
                _authority=issuer, _linkage_keys=keys, _reference=reference)
            if authority.tenant in tenants:
                _fail()
            tenants.add(authority.tenant)
            result.append(authority)
        return tuple(result)
    except (TypeError, ValueError, UnicodeError, binascii.Error, LinkageRiskError, LinkageRiskAuthorityError):
        _fail()


def authority_for_tenant(authorities: Iterable[LinkageRiskControlAuthority], *, tenant: str,
                         at: datetime | None = None) -> LinkageRiskControlAuthority:
    # Avoid attribute access until the exact trusted record type is known.
    # A supplied subclass could override ``tenant`` or verification methods.
    matches = [item for item in authorities
               if type(item) is LinkageRiskControlAuthority and item.tenant == tenant]
    moment = datetime.now(UTC) if at is None else at
    if len(matches) != 1 or not matches[0].is_active(at=moment):
        _fail()
    return matches[0]
