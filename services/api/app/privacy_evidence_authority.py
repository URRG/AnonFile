"""Tenant-scoped, source-safe attestations for privacy-evidence policy inputs.

This is deliberately a worker-side primitive.  It turns a trusted worker's
bounded measurement into an opaque :class:`PrivacyEvidenceReference`, and can
then materialise the policy contract's ``AttestedPrivacyEvidence`` only after
re-verifying that reference.  It has no API, persistence, candidate, release,
or delivery integration.

The policy contract already makes a conservative decision; this module is the
missing boundary that binds the *complete* policy and candidate scope to a
configured tenant authority before that policy sees an evidence record.
"""
from __future__ import annotations

import base64
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import re
from weakref import WeakKeyDictionary, WeakValueDictionary

from app.privacy_evidence_policy import (
    MAX_COUNT,
    MAX_EVIDENCE_LIFETIME_SECONDS,
    PPM,
    AttestedPrivacyEvidence,
    PrivacyEvidenceAuthority,
    PrivacyEvidenceBinding,
    PrivacyEvidenceDecision,
    PrivacyEvidenceKind,
    PrivacyEvidencePolicy,
    PrivacyEvidencePolicyError,
    assess_privacy_evidence,
)


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_REFERENCE = re.compile(r"evidence:v1:[A-Za-z0-9_-]{43}\Z")
_SIGNATURE = re.compile(r"privacy-reference-sig:v1:[A-Za-z0-9_-]{43}\Z")
_AUTHORITY = re.compile(r"privacy-authority:v1:[A-Za-z0-9_-]{43}\Z")
_MAX_AUTHORITY_LIFETIME_SECONDS = 366 * 24 * 60 * 60

# Keys are retained inside this module's worker boundary, never on an authority
# object or in a returned verifier.  Weak registries also make a reference
# unverifiable once its configured authority is no longer held by the process.
_AUTHORITY_KEYS: WeakKeyDictionary["PrivacyEvidenceAttestationAuthority", bytes] = WeakKeyDictionary()
_AUTHORITIES_BY_ID: WeakValueDictionary[str, "PrivacyEvidenceAttestationAuthority"] = WeakValueDictionary()


class PrivacyEvidenceAuthorityError(ValueError):
    """Fixed rejection that never includes source, identifiers, or secrets."""

    def __init__(self) -> None:
        super().__init__("Invalid privacy evidence authority input")


def _fail() -> None:
    raise PrivacyEvidenceAuthorityError()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True,
                          separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _identifier(value: object) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _reference(value: object) -> str:
    if type(value) is not str or not _REFERENCE.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    result = value.astimezone(UTC)
    if result.microsecond:
        _fail()
    return result


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _worker_key(authority: "PrivacyEvidenceAttestationAuthority") -> bytes:
    """Read key material only inside this module's authority boundary."""
    secret = _AUTHORITY_KEYS.get(authority)
    if type(secret) is not bytes:
        _fail()
    return secret


def _score(kind: PrivacyEvidenceKind, value: object) -> int:
    if type(value) is not int or isinstance(value, bool):
        _fail()
    ppm_kinds = {PrivacyEvidenceKind.RESIDUAL_SCAN, PrivacyEvidenceKind.UTILITY,
                 PrivacyEvidenceKind.LINKAGE, PrivacyEvidenceKind.BENCHMARK}
    lower = 1 if kind is PrivacyEvidenceKind.DISCLOSURE_RISK else 0
    upper = PPM if kind in ppm_kinds else MAX_COUNT
    if not lower <= value <= upper:
        _fail()
    return value


@dataclass(frozen=True, slots=True)
class PrivacyEvidenceReference:
    """One authority-signed, opaque evidence claim.

    ``binding`` and ``policy`` contain only already-source-safe policy inputs:
    digests, controlled identifiers, thresholds, and timestamps.  They are
    retained privately in ``repr`` so accidental logs do not expose even those
    scoped metadata values.
    """

    tenant: str
    authority_id: str
    kind: PrivacyEvidenceKind
    evidence_reference: str = field(repr=False)
    evidence_digest: str = field(repr=False)
    binding: PrivacyEvidenceBinding = field(repr=False)
    policy: PrivacyEvidencePolicy = field(repr=False)
    issuer_key_id: str
    observed_value: int
    measured_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)

    def __post_init__(self) -> None:
        if type(self) is not PrivacyEvidenceReference:
            _fail()
        object.__setattr__(self, "tenant", _identifier(self.tenant))
        if type(self.authority_id) is not str or not _AUTHORITY.fullmatch(self.authority_id):
            _fail()
        if type(self.kind) is not PrivacyEvidenceKind:
            _fail()
        object.__setattr__(self, "evidence_reference", _reference(self.evidence_reference))
        object.__setattr__(self, "evidence_digest", _digest(self.evidence_digest))
        if type(self.binding) is not PrivacyEvidenceBinding or type(self.policy) is not PrivacyEvidencePolicy:
            _fail()
        object.__setattr__(self, "issuer_key_id", _identifier(self.issuer_key_id))
        object.__setattr__(self, "observed_value", _score(self.kind, self.observed_value))
        object.__setattr__(self, "measured_at", _time(self.measured_at))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if (self.expires_at <= self.measured_at
                or (self.expires_at - self.measured_at).total_seconds() > MAX_EVIDENCE_LIFETIME_SECONDS
                or type(self.signature) is not str or not _SIGNATURE.fullmatch(self.signature)):
            _fail()

    def canonical(self) -> dict[str, object]:
        """Complete signed scope, without any source/candidate payload."""
        return {
            "authority_id": self.authority_id,
            "binding": self.binding.canonical(),
            "evidence_digest": self.evidence_digest,
            "evidence_reference": self.evidence_reference,
            "expires_at": _instant(self.expires_at),
            "issuer_key_id": self.issuer_key_id,
            "kind": self.kind.value,
            "measured_at": _instant(self.measured_at),
            "observed_value": self.observed_value,
            "policy": self.policy.canonical(),
            "tenant": self.tenant,
        }

    @property
    def digest(self) -> str:
        return "sha256:" + hashlib.sha256(_canonical({**self.canonical(), "signature": self.signature})).hexdigest()

    def to_record(self) -> dict[str, object]:
        """Metadata-only serialization; no secret, payload, or delivery handle."""
        return {**self.canonical(), "digest": self.digest, "signature": self.signature}


@dataclass(frozen=True, slots=True, weakref_slot=True)
class PrivacyEvidenceAttestationAuthority:
    """One active tenant/issuer HMAC boundary for policy evidence.

    The HMAC key is never serialized.  A reference can be converted to the
    existing policy type only by this same authority after exact verification.
    This avoids treating a self-consistent report digest as evidence.
    """

    tenant: str
    issuer_key_id: str
    expires_at: datetime
    secret: InitVar[bytes] = field(repr=False, compare=False)
    authority_id: str = field(init=False)

    def __post_init__(self, secret: bytes) -> None:
        if type(self) is not PrivacyEvidenceAttestationAuthority:
            _fail()
        tenant = _identifier(self.tenant)
        issuer = _identifier(self.issuer_key_id)
        expires = _time(self.expires_at)
        if type(secret) is not bytes or not 32 <= len(secret) <= 64:
            _fail()
        # An unbounded authority lifetime makes a misconfiguration permanent.
        now = datetime.now(UTC).replace(microsecond=0)
        if expires <= now or (expires - now).total_seconds() > _MAX_AUTHORITY_LIFETIME_SECONDS:
            _fail()
        object.__setattr__(self, "tenant", tenant)
        object.__setattr__(self, "issuer_key_id", issuer)
        object.__setattr__(self, "expires_at", expires)
        commitment = base64.urlsafe_b64encode(hmac.new(
            secret,
            _canonical({"schema": "privacy-evidence-authority-key-v1", "tenant": tenant,
                        "issuer_key_id": issuer, "expires_at": _instant(expires)}),
            hashlib.sha256,
        ).digest()).decode("ascii").rstrip("=")
        authority_id = "privacy-authority:v1:" + commitment
        if not _AUTHORITY.fullmatch(authority_id):
            _fail()
        object.__setattr__(self, "authority_id", authority_id)
        _AUTHORITY_KEYS[self] = secret
        _AUTHORITIES_BY_ID[authority_id] = self

    def __repr__(self) -> str:
        return ("PrivacyEvidenceAttestationAuthority(tenant=" + repr(self.tenant)
                + ", issuer_key_id=" + repr(self.issuer_key_id) + ", secret=<redacted>)")

    def is_active(self, *, at: datetime | None = None) -> bool:
        moment = datetime.now(UTC).replace(microsecond=0) if at is None else at
        try:
            return (isinstance(moment, datetime) and moment.tzinfo is not None and moment.utcoffset() is not None
                    and _time(moment) < self.expires_at)
        except PrivacyEvidenceAuthorityError:
            return False

    def _sign(self, value: object) -> str:
        digest = hmac.new(_worker_key(self), b"privacy-evidence-reference-v1:" + _canonical(value),
                          hashlib.sha256).digest()
        return "privacy-reference-sig:v1:" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

    def _validate_scope(self, *, kind: object, binding: object, policy: object,
                        measured_at: object, expires_at: object) -> tuple[PrivacyEvidenceKind, PrivacyEvidenceBinding,
                                                                            PrivacyEvidencePolicy, datetime, datetime]:
        if type(kind) is not PrivacyEvidenceKind or type(binding) is not PrivacyEvidenceBinding or type(policy) is not PrivacyEvidencePolicy:
            _fail()
        measured = _time(measured_at)
        expires = _time(expires_at)
        if (binding.method_provenance_digest != policy.method_provenance_digest
                or expires <= measured
                or (expires - measured).total_seconds() > MAX_EVIDENCE_LIFETIME_SECONDS
                or measured >= binding.candidate_expires_at
                or expires > binding.candidate_expires_at or expires > self.expires_at):
            _fail()
        requirements = {requirement.kind: requirement for requirement in policy.requirements}
        requirement = requirements.get(kind)
        if requirement is None or requirement.issuer_key_id != self.issuer_key_id:
            _fail()
        return kind, binding, policy, measured, expires

    def issue(self, *, kind: PrivacyEvidenceKind, evidence_reference: str, evidence_digest: str,
              binding: PrivacyEvidenceBinding, policy: PrivacyEvidencePolicy, observed_value: int,
              measured_at: datetime, expires_at: datetime, at: datetime | None = None) -> PrivacyEvidenceReference:
        """Issue a complete scope attestation inside a trusted worker boundary."""
        moment = datetime.now(UTC).replace(microsecond=0) if at is None else at
        if not self.is_active(at=moment):
            _fail()
        checked_kind, checked_binding, checked_policy, measured, expires = self._validate_scope(
            kind=kind, binding=binding, policy=policy, measured_at=measured_at, expires_at=expires_at)
        checked_moment = _time(moment)
        if measured > checked_moment or expires <= checked_moment:
            _fail()
        provisional = PrivacyEvidenceReference(
            tenant=self.tenant, authority_id=self.authority_id, kind=checked_kind,
            evidence_reference=_reference(evidence_reference), evidence_digest=_digest(evidence_digest),
            binding=checked_binding, policy=checked_policy, issuer_key_id=self.issuer_key_id,
            observed_value=_score(checked_kind, observed_value), measured_at=measured, expires_at=expires,
            signature="privacy-reference-sig:v1:" + "A" * 43,
        )
        return PrivacyEvidenceReference(**{
            "tenant": provisional.tenant, "authority_id": provisional.authority_id, "kind": provisional.kind,
            "evidence_reference": provisional.evidence_reference, "evidence_digest": provisional.evidence_digest,
            "binding": provisional.binding, "policy": provisional.policy, "issuer_key_id": provisional.issuer_key_id,
            "observed_value": provisional.observed_value, "measured_at": provisional.measured_at,
            "expires_at": provisional.expires_at,
            "signature": self._sign(provisional.canonical()),
        })

    def verifies(self, reference: object, *, at: datetime | None = None) -> bool:
        """Fail closed for foreign tenants, expired authority, or altered scope."""
        try:
            moment = datetime.now(UTC).replace(microsecond=0) if at is None else at
            if type(reference) is not PrivacyEvidenceReference or not self.is_active(at=moment):
                return False
            kind, binding, policy, measured, expires = self._validate_scope(
                kind=reference.kind, binding=reference.binding, policy=reference.policy,
                measured_at=reference.measured_at, expires_at=reference.expires_at)
            if (kind is not reference.kind or binding is not reference.binding or policy is not reference.policy
                    or measured != reference.measured_at or expires != reference.expires_at
                    or reference.tenant != self.tenant or reference.authority_id != self.authority_id
                    or reference.issuer_key_id != self.issuer_key_id
                    or measured > _time(moment) or expires <= _time(moment)):
                return False
            return hmac.compare_digest(reference.signature, self._sign(reference.canonical()))
        except (PrivacyEvidenceAuthorityError, PrivacyEvidencePolicyError, TypeError, ValueError):
            return False

    def _policy_evidence(self, reference: PrivacyEvidenceReference) -> AttestedPrivacyEvidence:
        """Internal bridge; callers receive only the policy decision, never a key capability."""
        provisional = {
            "binding_digest": reference.binding.digest, "evidence_digest": reference.evidence_digest,
            "evidence_policy_digest": reference.policy.digest, "evidence_reference": reference.evidence_reference,
            "expires_at": _instant(reference.expires_at), "issuer_key_id": self.issuer_key_id,
            "kind": reference.kind.value, "measured_at": _instant(reference.measured_at),
            "method_provenance_digest": reference.binding.method_provenance_digest,
            "observed_value": reference.observed_value,
        }
        signature = hmac.new(_worker_key(self), b"privacy-evidence-v1:" + _canonical(provisional),
                             hashlib.sha256).digest()
        return AttestedPrivacyEvidence(
            **{**provisional, "kind": reference.kind, "measured_at": reference.measured_at,
               "expires_at": reference.expires_at,
               "signature": "privacy-evidence-sig:v1:" + base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")},
        )

    def assess_policy(self, *, binding: PrivacyEvidenceBinding, policy: PrivacyEvidencePolicy,
                      references: object, at: datetime) -> PrivacyEvidenceDecision:
        """Assess only references from this tenant within the private authority boundary.

        No verifier, key, HMAC signer, or separately usable policy attestation
        is returned.  Unknown, malformed, foreign, inactive, expired, or
        altered references become unverified evidence in the policy's
        fail-closed decision rather than crossing this boundary as a claim.
        """
        if type(binding) is not PrivacyEvidenceBinding or type(policy) is not PrivacyEvidencePolicy:
            _fail()
        moment = _time(at)
        if not self.is_active(at=moment) or isinstance(references, (str, bytes)):
            _fail()
        try:
            supplied = tuple(references)
        except TypeError:
            _fail()
        evidence: list[object] = []
        verified_authorities: dict[str, PrivacyEvidenceAttestationAuthority] = {}
        for reference in supplied:
            authority = (_AUTHORITIES_BY_ID.get(reference.authority_id)
                         if type(reference) is PrivacyEvidenceReference and reference.tenant == self.tenant else None)
            if (type(authority) is PrivacyEvidenceAttestationAuthority and authority.tenant == self.tenant
                    and authority.verifies(reference, at=moment)):
                evidence.append(authority._policy_evidence(reference))
                verified_authorities[authority.authority_id] = authority
            else:
                evidence.append(object())
        expected_issuers = {requirement.issuer_key_id for requirement in policy.requirements}
        matching = {authority.issuer_key_id: authority for authority in verified_authorities.values()
                    if authority.issuer_key_id in expected_issuers}
        policy_authorities = tuple(PrivacyEvidenceAuthority(key_id=authority.issuer_key_id,
                                                             secret=_worker_key(authority))
                                   for authority in matching.values())
        return assess_privacy_evidence(decision_id="privacy-evidence-authority", binding=binding,
                                       policy=policy, evidence=evidence,
                                       authorities=policy_authorities, at=moment)
