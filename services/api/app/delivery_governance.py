"""Fail-closed, source-safe delivery-governance evidence.

This is a control-plane primitive only.  It accepts opaque references and
bounded assertions, records whether all required assertions verify for one
exact candidate/recipient/purpose/contract binding, and signs the resulting
evidence for tamper detection.  It never receives payload bytes, opens an
export, changes a processing run, or returns a delivery-ready state.

The HMAC authority is deliberately an in-process integration boundary.  A
production deployment must replace its custody with an audited key-management
service and an independently operated approval/delivery workflow.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import hmac
import json
import re
from typing import Iterable


MAX_ASSERTIONS = 8
MAX_ASSERTION_AGE_SECONDS = 366 * 24 * 60 * 60
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RIGHTS_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_SIGNATURE = re.compile(r"hmac-sha256:[0-9a-f]{64}\Z")


class DeliveryGovernanceError(ValueError):
    """Fixed failure that never includes a source value or recipient detail."""

    def __init__(self) -> None:
        super().__init__("Invalid delivery governance input")


class DeliveryReadinessStatus(StrEnum):
    """There is intentionally no READY, APPROVED, EXPORTED, or DELIVERED state."""

    QUARANTINED = "QUARANTINED"
    INDEPENDENT_APPROVAL_REQUIRED = "INDEPENDENT_APPROVAL_REQUIRED"


class DeliveryReadinessReason(StrEnum):
    MISSING_REQUIRED_ASSERTIONS = "MISSING_REQUIRED_ASSERTIONS"
    ASSERTION_BINDING_MISMATCH = "ASSERTION_BINDING_MISMATCH"
    CANDIDATE_EXPIRED = "CANDIDATE_EXPIRED"
    ASSERTION_EXPIRED = "ASSERTION_EXPIRED"
    ASSERTION_TIME_INVALID = "ASSERTION_TIME_INVALID"
    ASSERTION_UNVERIFIED = "ASSERTION_UNVERIFIED"
    INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED = "INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED"


class DeliveryAssertionKind(StrEnum):
    RIGHTS_VALIDATED = "RIGHTS_VALIDATED"
    PRIVACY_EVIDENCE_VALIDATED = "PRIVACY_EVIDENCE_VALIDATED"
    SECURITY_REVIEW_VALIDATED = "SECURITY_REVIEW_VALIDATED"
    CONTRACT_EXECUTED = "CONTRACT_EXECUTED"


_REQUIRED_ASSERTIONS = frozenset(DeliveryAssertionKind)


def _fail() -> None:
    raise DeliveryGovernanceError()


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


def _signature(value: object) -> str:
    if type(value) is not str or not _SIGNATURE.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    return value.astimezone(UTC).replace(microsecond=0)


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


@dataclass(frozen=True, slots=True)
class DeliveryBinding:
    """Opaque identity of the only candidate and counterparty scope in view."""

    candidate_artifact_digest: str
    policy_digest: str
    rights_digest: str
    recipient_reference: str = field(repr=False)
    purpose_code: str
    contract_reference: str = field(repr=False)
    contract_digest: str = field(repr=False)
    candidate_expires_at: datetime
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "candidate_artifact_digest", _digest(self.candidate_artifact_digest))
        object.__setattr__(self, "policy_digest", _digest(self.policy_digest))
        object.__setattr__(self, "rights_digest", _rights_digest(self.rights_digest))
        object.__setattr__(self, "recipient_reference", _digest(self.recipient_reference))
        object.__setattr__(self, "purpose_code", _identifier(self.purpose_code))
        object.__setattr__(self, "contract_reference", _digest(self.contract_reference))
        object.__setattr__(self, "contract_digest", _digest(self.contract_digest))
        object.__setattr__(self, "candidate_expires_at", _time(self.candidate_expires_at))
        object.__setattr__(self, "digest", _hash(self.canonical()))

    def canonical(self) -> dict[str, str]:
        return {
            "candidate_artifact_digest": self.candidate_artifact_digest,
            "candidate_expires_at": _instant(self.candidate_expires_at),
            "contract_digest": self.contract_digest,
            "contract_reference": self.contract_reference,
            "policy_digest": self.policy_digest,
            "purpose_code": self.purpose_code,
            "recipient_reference": self.recipient_reference,
            "rights_digest": self.rights_digest,
        }


@dataclass(frozen=True, slots=True)
class DeliveryAssertion:
    """A signed, opaque assertion from a controlled evidence boundary."""

    assertion_id: str
    kind: DeliveryAssertionKind
    binding_digest: str
    evidence_reference: str = field(repr=False)
    evidence_digest: str = field(repr=False)
    issuer_key_id: str
    issued_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "assertion_id", _identifier(self.assertion_id))
        if not isinstance(self.kind, DeliveryAssertionKind):
            _fail()
        object.__setattr__(self, "binding_digest", _digest(self.binding_digest))
        object.__setattr__(self, "evidence_reference", _digest(self.evidence_reference))
        object.__setattr__(self, "evidence_digest", _digest(self.evidence_digest))
        object.__setattr__(self, "issuer_key_id", _identifier(self.issuer_key_id))
        object.__setattr__(self, "issued_at", _time(self.issued_at))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if (self.expires_at <= self.issued_at
                or (self.expires_at - self.issued_at).total_seconds() > MAX_ASSERTION_AGE_SECONDS):
            _fail()
        object.__setattr__(self, "signature", _signature(self.signature))

    def canonical(self) -> dict[str, str]:
        return {
            "assertion_id": self.assertion_id,
            "binding_digest": self.binding_digest,
            "evidence_digest": self.evidence_digest,
            "evidence_reference": self.evidence_reference,
            "expires_at": _instant(self.expires_at),
            "issued_at": _instant(self.issued_at),
            "issuer_key_id": self.issuer_key_id,
            "kind": self.kind.value,
        }

    def to_record(self) -> dict[str, str]:
        return {**self.canonical(), "signature": self.signature}


class DeliveryEvidenceAuthority:
    """Private HMAC authority for protected control-plane evidence.

    The secret is accepted only as bytes, omitted from ``repr``, and is never
    emitted by any record.  This is not a substitute for KMS-backed custody.
    """

    __slots__ = ("_key", "key_id")

    def __init__(self, *, key_id: str, secret: bytes) -> None:
        self.key_id = _identifier(key_id)
        if type(secret) is not bytes or not 32 <= len(secret) <= 64:
            _fail()
        self._key = secret

    def __repr__(self) -> str:
        return f"DeliveryEvidenceAuthority(key_id={self.key_id!r}, secret=<redacted>)"

    def _sign(self, context: str, value: object) -> str:
        message = context.encode("ascii") + b":" + _canonical(value)
        return "hmac-sha256:" + hmac.new(self._key, message, hashlib.sha256).hexdigest()

    def issue_assertion(self, *, assertion_id: str, kind: DeliveryAssertionKind,
                        binding: DeliveryBinding, evidence_reference: str, evidence_digest: str,
                        issued_at: datetime, expires_at: datetime) -> DeliveryAssertion:
        if not isinstance(binding, DeliveryBinding) or not isinstance(kind, DeliveryAssertionKind):
            _fail()
        provisional = {
            "assertion_id": _identifier(assertion_id), "binding_digest": binding.digest,
            "evidence_digest": _digest(evidence_digest), "evidence_reference": _digest(evidence_reference),
            "expires_at": _instant(_time(expires_at)), "issued_at": _instant(_time(issued_at)),
            "issuer_key_id": self.key_id, "kind": kind.value,
        }
        # Constructing after signing enforces all timestamp constraints in one
        # place and ensures the signature covers exactly the persisted fields.
        return DeliveryAssertion(signature=self._sign("delivery-assertion-v1", provisional),
                                 **{**provisional, "kind": kind,
                                    "issued_at": _time(issued_at), "expires_at": _time(expires_at)})

    def verifies_assertion(self, assertion: object) -> bool:
        return (isinstance(assertion, DeliveryAssertion) and assertion.issuer_key_id == self.key_id
                and hmac.compare_digest(assertion.signature,
                                        self._sign("delivery-assertion-v1", assertion.canonical())))

    def sign_evidence(self, evidence_digest: str) -> str:
        return self._sign("delivery-readiness-v1", {"evidence_digest": _digest(evidence_digest),
                                                      "issuer_key_id": self.key_id})

    def verifies_evidence(self, evidence: object) -> bool:
        return (isinstance(evidence, DeliveryReadinessEvidence)
                and evidence.issuer_key_id == self.key_id and evidence.signature is not None
                and hmac.compare_digest(evidence.signature, self.sign_evidence(evidence.digest)))


@dataclass(frozen=True, slots=True)
class DeliveryReadinessEvidence:
    """Signed outcome evidence which never authorizes an external handoff."""

    delivery_id: str
    binding: DeliveryBinding = field(repr=False)
    assertions: tuple[DeliveryAssertion, ...] = field(repr=False)
    assessed_at: datetime
    expires_at: datetime
    status: DeliveryReadinessStatus
    reasons: tuple[DeliveryReadinessReason, ...]
    issuer_key_id: str | None
    signature: str | None = field(repr=False)
    posture: str = "NO_DELIVERY_AUTHORIZATION"
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "delivery_id", _identifier(self.delivery_id))
        if not isinstance(self.binding, DeliveryBinding):
            _fail()
        if (type(self.assertions) is not tuple or len(self.assertions) > MAX_ASSERTIONS
                or any(not isinstance(item, DeliveryAssertion) for item in self.assertions)
                or len({item.assertion_id for item in self.assertions}) != len(self.assertions)
                or len({item.kind for item in self.assertions}) != len(self.assertions)):
            _fail()
        object.__setattr__(self, "assertions", tuple(sorted(self.assertions, key=lambda item: item.kind.value)))
        object.__setattr__(self, "assessed_at", _time(self.assessed_at))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if (not isinstance(self.status, DeliveryReadinessStatus)
                or (self.status is DeliveryReadinessStatus.INDEPENDENT_APPROVAL_REQUIRED
                    and self.expires_at <= self.assessed_at)):
            _fail()
        if (type(self.reasons) is not tuple or not self.reasons
                or any(not isinstance(item, DeliveryReadinessReason) for item in self.reasons)):
            _fail()
        object.__setattr__(self, "reasons", tuple(sorted(set(self.reasons), key=str)))
        if self.posture != "NO_DELIVERY_AUTHORIZATION":
            _fail()
        if self.issuer_key_id is None:
            if self.signature is not None:
                _fail()
        else:
            object.__setattr__(self, "issuer_key_id", _identifier(self.issuer_key_id))
            if self.signature is not None:
                object.__setattr__(self, "signature", _signature(self.signature))
        object.__setattr__(self, "digest", _hash(self.canonical()))

    def canonical(self) -> dict[str, object]:
        return {
            "assertions": [item.to_record() for item in self.assertions],
            "assessed_at": _instant(self.assessed_at), "binding": self.binding.canonical(),
            "delivery_id": self.delivery_id, "expires_at": _instant(self.expires_at),
            "issuer_key_id": self.issuer_key_id, "posture": self.posture,
            "reasons": [item.value for item in self.reasons], "status": self.status.value,
        }

    def to_record(self) -> dict[str, object]:
        """Return bounded control metadata only: no payload or delivery handle exists."""
        return {**self.canonical(), "digest": self.digest, "signature": self.signature}

    @classmethod
    def from_record(cls, value: object, *, authority: DeliveryEvidenceAuthority) -> "DeliveryReadinessEvidence":
        expected = {"assertions", "assessed_at", "binding", "delivery_id", "digest", "expires_at",
                    "issuer_key_id", "posture", "reasons", "signature", "status"}
        if not isinstance(value, dict) or set(value) != expected or not isinstance(authority, DeliveryEvidenceAuthority):
            _fail()
        try:
            binding_value = value["binding"]
            if not isinstance(binding_value, dict) or set(binding_value) != {
                    "candidate_artifact_digest", "candidate_expires_at", "contract_digest",
                    "contract_reference", "policy_digest", "purpose_code", "recipient_reference",
                    "rights_digest"}:
                _fail()
            binding = DeliveryBinding(
                candidate_artifact_digest=binding_value["candidate_artifact_digest"],
                candidate_expires_at=datetime.fromisoformat(binding_value["candidate_expires_at"].replace("Z", "+00:00")),
                contract_digest=binding_value["contract_digest"], contract_reference=binding_value["contract_reference"],
                policy_digest=binding_value["policy_digest"], purpose_code=binding_value["purpose_code"],
                recipient_reference=binding_value["recipient_reference"], rights_digest=binding_value["rights_digest"])
            items = value["assertions"]
            if type(items) is not list or type(value["reasons"]) is not list:
                _fail()
            expected_assertion = {"assertion_id", "binding_digest", "evidence_digest", "evidence_reference",
                                  "expires_at", "issued_at", "issuer_key_id", "kind", "signature"}
            assertions = []
            for item in items:
                if not isinstance(item, dict) or set(item) != expected_assertion:
                    _fail()
                assertions.append(DeliveryAssertion(
                    assertion_id=item["assertion_id"], kind=DeliveryAssertionKind(item["kind"]),
                    binding_digest=item["binding_digest"], evidence_reference=item["evidence_reference"],
                    evidence_digest=item["evidence_digest"], issuer_key_id=item["issuer_key_id"],
                    issued_at=datetime.fromisoformat(item["issued_at"].replace("Z", "+00:00")),
                    expires_at=datetime.fromisoformat(item["expires_at"].replace("Z", "+00:00")),
                    signature=item["signature"]))
            record = cls(delivery_id=value["delivery_id"], binding=binding, assertions=tuple(assertions),
                         assessed_at=datetime.fromisoformat(value["assessed_at"].replace("Z", "+00:00")),
                         expires_at=datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")),
                         status=DeliveryReadinessStatus(value["status"]),
                         reasons=tuple(DeliveryReadinessReason(item) for item in value["reasons"]),
                         issuer_key_id=value["issuer_key_id"], signature=value["signature"], posture=value["posture"])
            if value["digest"] != record.digest or not authority.verifies_evidence(record):
                _fail()
            return record
        except (KeyError, TypeError, ValueError, OverflowError):
            _fail()


def assess_delivery_readiness(*, delivery_id: str, binding: DeliveryBinding,
                              assertions: Iterable[DeliveryAssertion], at: datetime,
                              authority: DeliveryEvidenceAuthority | None) -> DeliveryReadinessEvidence:
    """Assess exact, signed control evidence without creating delivery authority.

    Even complete verified assertions result only in
    ``INDEPENDENT_APPROVAL_REQUIRED``.  Missing, unverified, future-dated, or
    expired inputs are quarantined and cannot be represented as clean.
    """
    if not isinstance(binding, DeliveryBinding) or isinstance(assertions, (str, bytes)):
        _fail()
    try:
        assertion_values = tuple(assertions)
    except TypeError:
        _fail()
    if len(assertion_values) > MAX_ASSERTIONS or any(not isinstance(item, DeliveryAssertion) for item in assertion_values):
        _fail()
    instant = _time(at)
    reasons: list[DeliveryReadinessReason] = []
    kinds = {item.kind for item in assertion_values}
    if kinds != _REQUIRED_ASSERTIONS:
        reasons.append(DeliveryReadinessReason.MISSING_REQUIRED_ASSERTIONS)
    if instant >= binding.candidate_expires_at:
        reasons.append(DeliveryReadinessReason.CANDIDATE_EXPIRED)
    for assertion in assertion_values:
        if assertion.binding_digest != binding.digest:
            reasons.append(DeliveryReadinessReason.ASSERTION_BINDING_MISMATCH)
        if assertion.issued_at > instant:
            reasons.append(DeliveryReadinessReason.ASSERTION_TIME_INVALID)
        if instant >= assertion.expires_at:
            reasons.append(DeliveryReadinessReason.ASSERTION_EXPIRED)
        if not isinstance(authority, DeliveryEvidenceAuthority) or not authority.verifies_assertion(assertion):
            reasons.append(DeliveryReadinessReason.ASSERTION_UNVERIFIED)
    if reasons:
        status = DeliveryReadinessStatus.QUARANTINED
    else:
        status = DeliveryReadinessStatus.INDEPENDENT_APPROVAL_REQUIRED
        reasons.append(DeliveryReadinessReason.INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED)
    expiry = min((binding.candidate_expires_at, *(item.expires_at for item in assertion_values)), default=binding.candidate_expires_at)
    provisional = DeliveryReadinessEvidence(
        delivery_id=delivery_id, binding=binding, assertions=assertion_values, assessed_at=instant,
        expires_at=expiry, status=status, reasons=tuple(reasons),
        issuer_key_id=authority.key_id if isinstance(authority, DeliveryEvidenceAuthority) else None,
        signature=None)
    if not isinstance(authority, DeliveryEvidenceAuthority):
        return provisional
    return DeliveryReadinessEvidence(
        delivery_id=provisional.delivery_id, binding=provisional.binding, assertions=provisional.assertions,
        assessed_at=provisional.assessed_at, expires_at=provisional.expires_at, status=provisional.status,
        reasons=provisional.reasons, issuer_key_id=authority.key_id,
        signature=authority.sign_evidence(provisional.digest))
