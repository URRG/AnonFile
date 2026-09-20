"""Fail-closed policy contract for source-safe privacy evidence references.

The contract intentionally evaluates only signed, opaque evidence references.
It neither reads a candidate nor produces an approved, exportable, or
deliverable state.  A passing set of measurements remains insufficient for a
release decision until independent governance is added elsewhere.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import hmac
import json
import re
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


PPM = 1_000_000
MAX_COUNT = 1_000_000_000
MAX_EVIDENCE_AGE_SECONDS = 31 * 24 * 60 * 60
MAX_EVIDENCE_LIFETIME_SECONDS = 31 * 24 * 60 * 60
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RIGHTS_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_REFERENCE = re.compile(r"evidence:v1:[A-Za-z0-9_-]{43}\Z")
_SIGNATURE = re.compile(r"(?:privacy-evidence-sig:v1:[A-Za-z0-9_-]{43}|privacy-evidence-sig:v2:[A-Za-z0-9_-]{86})\Z")
_AUTHORITY_ID = re.compile(r"privacy-authority:v2:[A-Za-z0-9_-]{43}\Z")


class PrivacyEvidencePolicyError(ValueError):
    """Fixed validation error that never contains supplied evidence details."""

    def __init__(self) -> None:
        super().__init__("Invalid privacy evidence policy input")


class PrivacyEvidenceOutcome(StrEnum):
    """There is deliberately no pass, ready, approved, or delivery state."""

    QUARANTINED = "QUARANTINED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


class PrivacyEvidenceReason(StrEnum):
    BINDING_MISMATCH = "BINDING_MISMATCH"
    CANDIDATE_EXPIRED = "CANDIDATE_EXPIRED"
    DUPLICATE_EVIDENCE_KIND = "DUPLICATE_EVIDENCE_KIND"
    EVIDENCE_EXPIRED = "EVIDENCE_EXPIRED"
    EVIDENCE_STALE = "EVIDENCE_STALE"
    EVIDENCE_TIME_INVALID = "EVIDENCE_TIME_INVALID"
    EVIDENCE_UNVERIFIED = "EVIDENCE_UNVERIFIED"
    INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED = "INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    THRESHOLD_EXCEEDED = "THRESHOLD_EXCEEDED"


class PrivacyEvidenceKind(StrEnum):
    RESIDUAL_SCAN = "RESIDUAL_SCAN"
    DISCLOSURE_RISK = "DISCLOSURE_RISK"
    UTILITY = "UTILITY"
    LINKAGE = "LINKAGE"
    BENCHMARK = "BENCHMARK"


class PrivacyEvidenceAttestationProfile(StrEnum):
    LEGACY_HMAC_V1 = "LEGACY_HMAC_V1"
    ED25519_V2 = "ED25519_V2"


_REQUIRED_KINDS = frozenset(PrivacyEvidenceKind)
_MAXIMUM_KINDS = frozenset({PrivacyEvidenceKind.RESIDUAL_SCAN, PrivacyEvidenceKind.LINKAGE})
_PPM_KINDS = frozenset({PrivacyEvidenceKind.RESIDUAL_SCAN, PrivacyEvidenceKind.UTILITY,
                         PrivacyEvidenceKind.LINKAGE, PrivacyEvidenceKind.BENCHMARK})


def _fail() -> None:
    raise PrivacyEvidencePolicyError()


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _rights_digest(value: object) -> str:
    if type(value) is not str or not _RIGHTS_DIGEST.fullmatch(value):
        _fail()
    return value


def _identifier(value: object) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail()
    return value


def _reference(value: object) -> str:
    if type(value) is not str or not _REFERENCE.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    instant = value.astimezone(UTC)
    if instant.microsecond:
        _fail()
    return instant


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _score(kind: PrivacyEvidenceKind, value: object) -> int:
    if type(value) is not int or isinstance(value, bool):
        _fail()
    upper = PPM if kind in _PPM_KINDS else MAX_COUNT
    lower = 1 if kind is PrivacyEvidenceKind.DISCLOSURE_RISK else 0
    if not lower <= value <= upper:
        _fail()
    return value


@dataclass(frozen=True, slots=True)
class PrivacyEvidenceBinding:
    """Opaque exact scope for the candidate and its intended recipient/purpose."""

    candidate_artifact_digest: str
    processing_policy_digest: str
    rights_digest: str
    recipient_reference: str = field(repr=False)
    purpose_code: str
    method_provenance_digest: str
    candidate_expires_at: datetime
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_artifact_digest", _digest(self.candidate_artifact_digest))
        object.__setattr__(self, "processing_policy_digest", _digest(self.processing_policy_digest))
        object.__setattr__(self, "rights_digest", _rights_digest(self.rights_digest))
        object.__setattr__(self, "recipient_reference", _digest(self.recipient_reference))
        object.__setattr__(self, "purpose_code", _identifier(self.purpose_code))
        object.__setattr__(self, "method_provenance_digest", _digest(self.method_provenance_digest))
        object.__setattr__(self, "candidate_expires_at", _time(self.candidate_expires_at))
        object.__setattr__(self, "digest", _hash(self.canonical()))

    def canonical(self) -> dict[str, str]:
        return {
            "candidate_artifact_digest": self.candidate_artifact_digest,
            "candidate_expires_at": _instant(self.candidate_expires_at),
            "method_provenance_digest": self.method_provenance_digest,
            "processing_policy_digest": self.processing_policy_digest,
            "purpose_code": self.purpose_code,
            "recipient_reference": self.recipient_reference,
            "rights_digest": self.rights_digest,
        }


@dataclass(frozen=True, slots=True)
class EvidenceRequirement:
    """One exact evidence kind, trusted issuer, and fail-closed threshold."""

    kind: PrivacyEvidenceKind
    issuer_key_id: str
    threshold: int
    authority_id: str | None = None
    public_key_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PrivacyEvidenceKind):
            _fail()
        object.__setattr__(self, "issuer_key_id", _identifier(self.issuer_key_id))
        object.__setattr__(self, "threshold", _score(self.kind, self.threshold))
        if self.authority_id is not None:
            if type(self.authority_id) is not str or not _AUTHORITY_ID.fullmatch(self.authority_id):
                _fail()
        if self.public_key_fingerprint is not None:
            object.__setattr__(self, "public_key_fingerprint", _digest(self.public_key_fingerprint))

    def passes(self, observed: int) -> bool:
        return observed <= self.threshold if self.kind in _MAXIMUM_KINDS else observed >= self.threshold

    def canonical(self) -> dict[str, object]:
        return {"authority_id": self.authority_id, "issuer_key_id": self.issuer_key_id,
                "kind": self.kind.value, "public_key_fingerprint": self.public_key_fingerprint,
                "threshold": self.threshold}


@dataclass(frozen=True, slots=True)
class PrivacyEvidencePolicy:
    """Complete policy: all five independent evidence families are mandatory."""

    policy_id: str
    method_provenance_digest: str
    max_evidence_age_seconds: int
    requirements: tuple[EvidenceRequirement, ...]
    attestation_profile: PrivacyEvidenceAttestationProfile = PrivacyEvidenceAttestationProfile.LEGACY_HMAC_V1
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "policy_id", _identifier(self.policy_id))
        object.__setattr__(self, "method_provenance_digest", _digest(self.method_provenance_digest))
        if (type(self.max_evidence_age_seconds) is not int or isinstance(self.max_evidence_age_seconds, bool)
                or not 1 <= self.max_evidence_age_seconds <= MAX_EVIDENCE_AGE_SECONDS
                or type(self.attestation_profile) is not PrivacyEvidenceAttestationProfile
                or type(self.requirements) is not tuple
                or any(type(item) is not EvidenceRequirement for item in self.requirements)
                or len(self.requirements) != len(_REQUIRED_KINDS)
                or {item.kind for item in self.requirements} != _REQUIRED_KINDS):
            _fail()
        ordered = tuple(sorted(self.requirements, key=lambda item: item.kind.value))
        if ordered != self.requirements or len({item.issuer_key_id for item in self.requirements}) != len(self.requirements):
            _fail()
        descriptors = [(item.authority_id, item.public_key_fingerprint) for item in self.requirements]
        if ((self.attestation_profile is PrivacyEvidenceAttestationProfile.ED25519_V2
             and any(authority is None or fingerprint is None for authority, fingerprint in descriptors))
                or (self.attestation_profile is PrivacyEvidenceAttestationProfile.LEGACY_HMAC_V1
                    and any(authority is not None or fingerprint is not None for authority, fingerprint in descriptors))):
            _fail()
        object.__setattr__(self, "digest", _hash(self.canonical()))

    def canonical(self) -> dict[str, object]:
        return {"attestation_profile": self.attestation_profile.value,
                "max_evidence_age_seconds": self.max_evidence_age_seconds,
                "method_provenance_digest": self.method_provenance_digest,
                "policy_id": self.policy_id,
                "requirements": [item.canonical() for item in self.requirements]}


@dataclass(frozen=True, slots=True)
class AttestedPrivacyEvidence:
    """One signed opaque report reference and bounded aggregate measurement."""

    kind: PrivacyEvidenceKind
    evidence_reference: str = field(repr=False)
    evidence_digest: str = field(repr=False)
    binding_digest: str
    evidence_policy_digest: str
    method_provenance_digest: str
    issuer_key_id: str
    observed_value: int
    measured_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)
    authority_tenant: str | None = field(default=None, repr=False)
    authority_id: str | None = None
    authority_public_key_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, PrivacyEvidenceKind):
            _fail()
        object.__setattr__(self, "evidence_reference", _reference(self.evidence_reference))
        object.__setattr__(self, "evidence_digest", _digest(self.evidence_digest))
        object.__setattr__(self, "binding_digest", _digest(self.binding_digest))
        object.__setattr__(self, "evidence_policy_digest", _digest(self.evidence_policy_digest))
        object.__setattr__(self, "method_provenance_digest", _digest(self.method_provenance_digest))
        object.__setattr__(self, "issuer_key_id", _identifier(self.issuer_key_id))
        object.__setattr__(self, "observed_value", _score(self.kind, self.observed_value))
        object.__setattr__(self, "measured_at", _time(self.measured_at))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if type(self.signature) is str and self.signature.startswith("privacy-evidence-sig:v2:"):
            object.__setattr__(self, "authority_tenant", _identifier(self.authority_tenant))
            if type(self.authority_id) is not str or not _AUTHORITY_ID.fullmatch(self.authority_id):
                _fail()
            object.__setattr__(self, "authority_public_key_fingerprint", _digest(self.authority_public_key_fingerprint))
        elif self.authority_tenant is not None or self.authority_id is not None or self.authority_public_key_fingerprint is not None:
            _fail()
        if (self.expires_at <= self.measured_at
                or (self.expires_at - self.measured_at).total_seconds() > MAX_EVIDENCE_LIFETIME_SECONDS
                or type(self.signature) is not str or not _SIGNATURE.fullmatch(self.signature)):
            _fail()

    def canonical(self) -> dict[str, object]:
        return {
            "binding_digest": self.binding_digest,
            "authority_id": self.authority_id,
            "authority_public_key_fingerprint": self.authority_public_key_fingerprint,
            "authority_tenant": self.authority_tenant,
            "evidence_digest": self.evidence_digest,
            "evidence_policy_digest": self.evidence_policy_digest,
            "evidence_reference": self.evidence_reference,
            "expires_at": _instant(self.expires_at),
            "issuer_key_id": self.issuer_key_id,
            "kind": self.kind.value,
            "measured_at": _instant(self.measured_at),
            "method_provenance_digest": self.method_provenance_digest,
            "observed_value": self.observed_value,
        }

    @property
    def digest(self) -> str:
        return _hash({**self.canonical(), "signature": self.signature})


class PrivacyEvidenceAuthority:
    """Private HMAC issuer/verifier for one controlled evidence producer."""

    __slots__ = ("_key", "key_id")

    def __init__(self, *, key_id: str, secret: bytes) -> None:
        self.key_id = _identifier(key_id)
        if type(secret) is not bytes or not 32 <= len(secret) <= 64:
            _fail()
        self._key = secret

    def __repr__(self) -> str:
        return f"PrivacyEvidenceAuthority(key_id={self.key_id!r}, secret=<redacted>)"

    def _sign(self, value: object) -> str:
        signature = hmac.new(self._key, b"privacy-evidence-v1:" + _canonical(value), hashlib.sha256).digest()
        return "privacy-evidence-sig:v1:" + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")

    def issue(self, *, kind: PrivacyEvidenceKind, evidence_reference: str, evidence_digest: str,
              binding: PrivacyEvidenceBinding, policy: PrivacyEvidencePolicy, observed_value: int,
              measured_at: datetime, expires_at: datetime) -> AttestedPrivacyEvidence:
        """Sign exact source-safe fields at a trusted evidence-worker boundary."""
        if type(kind) is not PrivacyEvidenceKind or type(binding) is not PrivacyEvidenceBinding or type(policy) is not PrivacyEvidencePolicy:
            _fail()
        provisional = {
            "binding_digest": binding.digest, "evidence_digest": _digest(evidence_digest),
            "evidence_policy_digest": policy.digest, "evidence_reference": _reference(evidence_reference),
            "expires_at": _instant(_time(expires_at)), "issuer_key_id": self.key_id, "kind": kind.value,
            "measured_at": _instant(_time(measured_at)),
            "method_provenance_digest": binding.method_provenance_digest,
            "observed_value": _score(kind, observed_value),
            "authority_id": None, "authority_public_key_fingerprint": None, "authority_tenant": None,
        }
        signature = self._sign(provisional)
        return AttestedPrivacyEvidence(**{**provisional, "kind": kind,
                                          "measured_at": _time(measured_at), "expires_at": _time(expires_at),
                                          "signature": signature})

    def verifies(self, evidence: object, *, at: datetime) -> bool:
        return (type(evidence) is AttestedPrivacyEvidence and evidence.issuer_key_id == self.key_id
                and hmac.compare_digest(evidence.signature, self._sign(evidence.canonical())))


class PrivacyEvidencePublicVerifier:
    """Ed25519 public-key verifier; deliberately incapable of issuing evidence."""

    __slots__ = ("_public_key", "authority_id", "expires_at", "key_id", "public_key_fingerprint", "tenant")

    def __init__(self, *, tenant: str, key_id: str, authority_id: str, public_key_b64: str, expires_at: datetime) -> None:
        self.tenant = _identifier(tenant)
        self.key_id = _identifier(key_id)
        if type(authority_id) is not str or not _AUTHORITY_ID.fullmatch(authority_id):
            _fail()
        self.authority_id = authority_id
        self.expires_at = _time(expires_at)
        if type(public_key_b64) is not str or len(public_key_b64) != 44:
            _fail()
        try:
            raw = base64.b64decode(public_key_b64, validate=True)
            if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != public_key_b64:
                _fail()
            self._public_key = Ed25519PublicKey.from_public_bytes(raw)
            self.public_key_fingerprint = "sha256:" + hashlib.sha256(raw).hexdigest()
        except (ValueError, UnicodeError):
            _fail()

    def __repr__(self) -> str:
        return f"PrivacyEvidencePublicVerifier(key_id={self.key_id!r}, public_key=<redacted>)"

    def verifies(self, evidence: object, *, at: datetime) -> bool:
        if (type(evidence) is not AttestedPrivacyEvidence or evidence.issuer_key_id != self.key_id
                or type(evidence.signature) is not str
                or not evidence.signature.startswith("privacy-evidence-sig:v2:")):
            return False
        try:
            moment = _time(at)
            if (moment >= self.expires_at or evidence.expires_at > self.expires_at or evidence.expires_at <= moment
                    or evidence.measured_at > moment or evidence.authority_tenant != self.tenant
                    or evidence.authority_id != self.authority_id
                    or evidence.authority_public_key_fingerprint != self.public_key_fingerprint):
                return False
            signature = base64.urlsafe_b64decode(evidence.signature.split(":", 2)[2] + "==")
            if len(signature) != 64:
                return False
            self._public_key.verify(signature, b"privacy-evidence-v2:" + _canonical(evidence.canonical()))
            return True
        except (InvalidSignature, ValueError, UnicodeError, PrivacyEvidencePolicyError):
            return False


@dataclass(frozen=True, slots=True)
class PrivacyEvidenceDecision:
    """Immutable source-safe outcome, explicitly without release authority."""

    decision_id: str
    outcome: PrivacyEvidenceOutcome
    reasons: tuple[PrivacyEvidenceReason, ...]
    binding: PrivacyEvidenceBinding = field(repr=False)
    privacy_evidence_policy_digest: str
    evidence_digests: tuple[tuple[PrivacyEvidenceKind, str], ...]
    decided_at: datetime
    posture: str = "NO_RELEASE_AUTHORIZATION"
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "decision_id", _identifier(self.decision_id))
        if (not isinstance(self.outcome, PrivacyEvidenceOutcome)
                or type(self.reasons) is not tuple or not self.reasons
                or any(type(reason) is not PrivacyEvidenceReason for reason in self.reasons)
                or len(set(self.reasons)) != len(self.reasons)
                or type(self.binding) is not PrivacyEvidenceBinding
                or self.posture != "NO_RELEASE_AUTHORIZATION"):
            _fail()
        object.__setattr__(self, "privacy_evidence_policy_digest", _digest(self.privacy_evidence_policy_digest))
        if (type(self.evidence_digests) is not tuple or len(self.evidence_digests) > len(_REQUIRED_KINDS)
                or any(type(item) is not tuple or len(item) != 2 or type(item[0]) is not PrivacyEvidenceKind
                       for item in self.evidence_digests)):
            _fail()
        normalised = tuple(sorted(((kind, _digest(digest)) for kind, digest in self.evidence_digests), key=lambda item: item[0].value))
        if normalised != self.evidence_digests or len({kind for kind, _ in normalised}) != len(normalised):
            _fail()
        object.__setattr__(self, "decided_at", _time(self.decided_at))
        object.__setattr__(self, "reasons", tuple(sorted(self.reasons, key=lambda item: item.value)))
        object.__setattr__(self, "digest", _hash(self.canonical()))

    def canonical(self) -> dict[str, object]:
        return {
            "binding_digest": self.binding.digest,
            "decision_id": self.decision_id,
            "decided_at": _instant(self.decided_at),
            "evidence_digests": [{"digest": digest, "kind": kind.value} for kind, digest in self.evidence_digests],
            "outcome": self.outcome.value,
            "posture": self.posture,
            "privacy_evidence_policy_digest": self.privacy_evidence_policy_digest,
            "reasons": [item.value for item in self.reasons],
        }

    def to_record(self) -> dict[str, object]:
        """A metadata-only decision; no payload, recipient, or release handle."""
        return {**self.canonical(), "digest": self.digest}


def _authority_map(authorities: Iterable[PrivacyEvidenceAuthority | PrivacyEvidencePublicVerifier]) -> dict[str, PrivacyEvidenceAuthority | PrivacyEvidencePublicVerifier]:
    if isinstance(authorities, (str, bytes)):
        _fail()
    try:
        values = tuple(authorities)
    except TypeError:
        _fail()
    if (any(type(value) not in {PrivacyEvidenceAuthority, PrivacyEvidencePublicVerifier} for value in values)
            or len({value.key_id for value in values}) != len(values)):
        _fail()
    return {value.key_id: value for value in values}


def assess_privacy_evidence(*, decision_id: str, binding: PrivacyEvidenceBinding,
                            policy: PrivacyEvidencePolicy, evidence: Iterable[AttestedPrivacyEvidence],
                            authorities: Iterable[PrivacyEvidenceAuthority | PrivacyEvidencePublicVerifier], at: datetime) -> PrivacyEvidenceDecision:
    """Apply exact signed evidence policy without authorizing a release.

    Unverifiable or mismatched evidence quarantines.  Missing, stale, future,
    or expired evidence is insufficient.  No complete branch returns anything
    other than ``INSUFFICIENT_EVIDENCE`` and a human/system authorization
    requirement.
    """
    if type(binding) is not PrivacyEvidenceBinding or type(policy) is not PrivacyEvidencePolicy:
        _fail()
    instant = _time(at)
    authority_by_key = _authority_map(authorities)
    if isinstance(evidence, (str, bytes)):
        _fail()
    try:
        supplied = tuple(evidence)
    except TypeError:
        _fail()
    valid_records = [item for item in supplied if type(item) is AttestedPrivacyEvidence]
    reasons: set[PrivacyEvidenceReason] = set()
    if len(valid_records) != len(supplied):
        reasons.add(PrivacyEvidenceReason.EVIDENCE_UNVERIFIED)
    by_kind: dict[PrivacyEvidenceKind, AttestedPrivacyEvidence] = {}
    for item in valid_records:
        if item.kind in by_kind:
            reasons.add(PrivacyEvidenceReason.DUPLICATE_EVIDENCE_KIND)
        else:
            by_kind[item.kind] = item
    # Persist at most one opaque evidence digest per kind.  A duplicate is a
    # quarantining reason, never an opportunity to create an invalid or
    # misleading decision record with two contenders for one requirement.
    evidence_digests = tuple(sorted(((kind, item.digest) for kind, item in by_kind.items()),
                                    key=lambda item: item[0].value))
    if binding.method_provenance_digest != policy.method_provenance_digest:
        reasons.add(PrivacyEvidenceReason.BINDING_MISMATCH)
    if instant >= binding.candidate_expires_at:
        reasons.add(PrivacyEvidenceReason.CANDIDATE_EXPIRED)
    requirements = {item.kind: item for item in policy.requirements}
    for kind, requirement in requirements.items():
        item = by_kind.get(kind)
        if item is None:
            reasons.add(PrivacyEvidenceReason.MISSING_EVIDENCE)
            continue
        authority = authority_by_key.get(requirement.issuer_key_id)
        if authority is None or not authority.verifies(item, at=instant):
            reasons.add(PrivacyEvidenceReason.EVIDENCE_UNVERIFIED)
            continue
        if (item.binding_digest != binding.digest or item.evidence_policy_digest != policy.digest
                or item.method_provenance_digest != binding.method_provenance_digest
                or item.issuer_key_id != requirement.issuer_key_id):
            reasons.add(PrivacyEvidenceReason.BINDING_MISMATCH)
            continue
        if policy.attestation_profile is PrivacyEvidenceAttestationProfile.ED25519_V2:
            if (type(authority) is not PrivacyEvidencePublicVerifier or item.authority_id != requirement.authority_id
                    or item.authority_public_key_fingerprint != requirement.public_key_fingerprint):
                reasons.add(PrivacyEvidenceReason.BINDING_MISMATCH)
                continue
        elif type(authority) is not PrivacyEvidenceAuthority:
            reasons.add(PrivacyEvidenceReason.EVIDENCE_UNVERIFIED)
            continue
        if item.measured_at > instant:
            reasons.add(PrivacyEvidenceReason.EVIDENCE_TIME_INVALID)
        elif instant >= item.expires_at:
            reasons.add(PrivacyEvidenceReason.EVIDENCE_EXPIRED)
        elif (instant - item.measured_at).total_seconds() > policy.max_evidence_age_seconds:
            reasons.add(PrivacyEvidenceReason.EVIDENCE_STALE)
        elif not requirement.passes(item.observed_value):
            reasons.add(PrivacyEvidenceReason.THRESHOLD_EXCEEDED)
    quarantining = {PrivacyEvidenceReason.BINDING_MISMATCH, PrivacyEvidenceReason.CANDIDATE_EXPIRED,
                     PrivacyEvidenceReason.DUPLICATE_EVIDENCE_KIND, PrivacyEvidenceReason.EVIDENCE_UNVERIFIED,
                     PrivacyEvidenceReason.THRESHOLD_EXCEEDED}
    if reasons & quarantining:
        outcome = PrivacyEvidenceOutcome.QUARANTINED
    elif reasons:
        outcome = PrivacyEvidenceOutcome.INSUFFICIENT_EVIDENCE
    else:
        outcome = PrivacyEvidenceOutcome.INSUFFICIENT_EVIDENCE
        reasons.add(PrivacyEvidenceReason.INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED)
    return PrivacyEvidenceDecision(decision_id=decision_id, outcome=outcome,
                                   reasons=tuple(reasons), binding=binding,
                                   privacy_evidence_policy_digest=policy.digest,
                                   evidence_digests=evidence_digests, decided_at=instant)
