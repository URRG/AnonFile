"""M15 immutable, non-authorizing privacy decision envelope.

This is intentionally a very small persistence boundary.  Policy assessment is
performed by :mod:`privacy_evidence_policy`; this module only signs the exact
opaque case/evidence snapshot selected by the server.  It never contains an
artifact location, source/candidate bytes, recipient value, or delivery data.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import re
import os

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from app.privacy_evidence_policy import (PrivacyEvidenceDecision, PrivacyEvidencePolicyError,
    PrivacyEvidenceBinding, PrivacyEvidenceKind, PrivacyEvidencePolicy,
    EvidenceRequirement, PrivacyEvidenceAttestationProfile, PrivacyEvidenceOutcome, PrivacyEvidenceReason)
from app.privacy_evidence_authority import PrivacyEvidenceAttestationAuthority, PrivacyEvidenceAuthorityError

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_ID = re.compile(r"privacy-decision:v1:[A-Za-z0-9_-]{43}\Z")
_AUTHORITY = re.compile(r"privacy-decision-authority:v1:[A-Za-z0-9_-]{43}\Z")
_SIGNATURE = re.compile(r"privacy-decision-sig:v1:[A-Za-z0-9_-]{86}\Z")


class PrivacyDecisionError(ValueError):
    def __init__(self): super().__init__("Invalid privacy decision input")


def _fail(): raise PrivacyDecisionError()
def _canon(value):
    try: return json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError): _fail()
def _id(value):
    if type(value) is not str or not _IDENTIFIER.fullmatch(value): _fail()
    return value
def _digest(value):
    if type(value) is not str or not _DIGEST.fullmatch(value): _fail()
    return value
def _time(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None: _fail()
    value = value.astimezone(UTC)
    if value.microsecond: _fail()
    return value
def _instant(value): return value.isoformat().replace("+00:00", "Z")
def _private(value):
    if type(value) is not str or len(value) != 44: _fail()
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value: _fail()
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, UnicodeError): _fail()


@dataclass(frozen=True, slots=True)
class PrivacyDecision:
    tenant: str
    decision_id: str
    case_id: str
    case_digest: str
    authority_id: str
    issuer_key_id: str
    decision: PrivacyEvidenceDecision = field(repr=False)
    evidence_references: tuple[tuple[str, str, str], ...] = field(repr=False)
    issued_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)
    posture: str = "NO_RELEASE_AUTHORIZATION"
    digest: str = field(init=False)

    def __post_init__(self):
        if type(self) is not PrivacyDecision: _fail()
        object.__setattr__(self, "tenant", _id(self.tenant))
        if type(self.decision_id) is not str or not _ID.fullmatch(self.decision_id): _fail()
        object.__setattr__(self, "case_id", _id(self.case_id)); object.__setattr__(self, "case_digest", _digest(self.case_digest))
        if type(self.authority_id) is not str or not _AUTHORITY.fullmatch(self.authority_id): _fail()
        object.__setattr__(self, "issuer_key_id", _id(self.issuer_key_id))
        if type(self.decision) is not PrivacyEvidenceDecision: _fail()
        if (type(self.evidence_references) is not tuple or len(self.evidence_references) > 5
                or any(type(x) is not tuple or len(x) != 3 or any(type(v) is not str for v in x) for x in self.evidence_references)
                or tuple(sorted(self.evidence_references)) != self.evidence_references
                or len({x[0] for x in self.evidence_references}) != len(self.evidence_references)
                or any(x[0] not in {kind.value for kind in PrivacyEvidenceKind} or not _IDENTIFIER.fullmatch(x[1]) or not _DIGEST.fullmatch(x[2]) for x in self.evidence_references)):
            _fail()
        object.__setattr__(self, "issued_at", _time(self.issued_at)); object.__setattr__(self, "expires_at", _time(self.expires_at))
        if (self.expires_at <= self.issued_at or self.expires_at > self.decision.binding.candidate_expires_at
                or self.posture != "NO_RELEASE_AUTHORIZATION" or type(self.signature) is not str or not _SIGNATURE.fullmatch(self.signature)):
            _fail()
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(_canon({**self.canonical(), "signature": self.signature})).hexdigest())

    def canonical(self):
        return {"authority_id": self.authority_id, "case_digest": self.case_digest, "case_id": self.case_id,
                "decision": self.decision.canonical(), "decision_id": self.decision_id,
                "decision_binding": self.decision.binding.canonical(),
                "evidence_references": [{"kind": k, "record_id": r, "record_digest": d} for k, r, d in self.evidence_references],
                "expires_at": _instant(self.expires_at), "issued_at": _instant(self.issued_at),
                "issuer_key_id": self.issuer_key_id, "posture": self.posture, "tenant": self.tenant}

    def to_record(self): return {**self.canonical(), "digest": self.digest, "signature": self.signature}

    @classmethod
    def from_record(cls, value):
        """Reconstruct every signed source-safe field after durable storage."""
        try:
            expected={"authority_id","case_digest","case_id","decision","decision_binding","decision_id","digest","evidence_references","expires_at","issued_at","issuer_key_id","posture","signature","tenant"}
            if not isinstance(value,dict) or set(value)!=expected or not isinstance(value["decision"],dict) or not isinstance(value["decision_binding"],dict) or not isinstance(value["evidence_references"],list): _fail()
            parse=lambda x: datetime.fromisoformat(x.replace("Z","+00:00"))
            binding=PrivacyEvidenceBinding(**{**value["decision_binding"],"candidate_expires_at":parse(value["decision_binding"]["candidate_expires_at"])})
            decision=value["decision"]
            evidence=tuple((PrivacyEvidenceKind(x["kind"]), x["digest"]) for x in decision["evidence_digests"])
            rebuilt=PrivacyEvidenceDecision(decision_id=decision["decision_id"], outcome=PrivacyEvidenceOutcome(decision["outcome"]),
                reasons=tuple(PrivacyEvidenceReason(x) for x in decision["reasons"]), binding=binding,
                privacy_evidence_policy_digest=decision["privacy_evidence_policy_digest"], evidence_digests=evidence,
                decided_at=parse(decision["decided_at"]), posture=decision["posture"])
            if rebuilt.canonical()!=decision: _fail()
            result=cls(value["tenant"],value["decision_id"],value["case_id"],value["case_digest"],value["authority_id"],value["issuer_key_id"],rebuilt,
                tuple((x["kind"],x["record_id"],x["record_digest"]) for x in value["evidence_references"]),parse(value["issued_at"]),parse(value["expires_at"]),value["signature"],value["posture"])
            if result.digest != value["digest"]: _fail()
            return result
        except (KeyError,TypeError,ValueError,PrivacyEvidencePolicyError,PrivacyDecisionError): _fail()


@dataclass(frozen=True, slots=True)
class PrivacyDecisionAuthority:
    tenant: str
    issuer_key_id: str
    expires_at: datetime
    private_key_b64: str = field(repr=False, compare=False)
    authority_id: str = field(init=False)
    _key: Ed25519PrivateKey = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        if type(self) is not PrivacyDecisionAuthority: _fail()
        tenant, issuer, expires, key = _id(self.tenant), _id(self.issuer_key_id), _time(self.expires_at), _private(self.private_key_b64)
        now=datetime.now(UTC).replace(microsecond=0)
        if expires <= now or (expires-now).total_seconds() > 366*24*60*60: _fail()
        public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")
        aid = "privacy-decision-authority:v1:" + base64.urlsafe_b64encode(hashlib.sha256(_canon({"schema":"privacy-decision-ed25519-v1","tenant":tenant,"issuer_key_id":issuer,"expires_at":_instant(expires),"public_key":public})).digest()).decode("ascii").rstrip("=")
        object.__setattr__(self, "tenant", tenant); object.__setattr__(self, "issuer_key_id", issuer); object.__setattr__(self, "expires_at", expires); object.__setattr__(self, "_key", key); object.__setattr__(self, "authority_id", aid)

    def is_active(self, *, at=None):
        try: return _time(datetime.now(UTC).replace(microsecond=0) if at is None else at) < self.expires_at
        except PrivacyDecisionError: return False

    def issue(self, *, decision_id, case_id, case_digest, decision, evidence_references, expires_at, at):
        moment, expiry = _time(at), _time(expires_at)
        if not self.is_active(at=moment) or expiry > self.expires_at: _fail()
        provisional = PrivacyDecision(self.tenant, decision_id, case_id, case_digest, self.authority_id, self.issuer_key_id,
            decision, evidence_references, moment, expiry, "privacy-decision-sig:v1:" + "A" * 86)
        signature = "privacy-decision-sig:v1:" + base64.urlsafe_b64encode(self._key.sign(b"privacy-decision-v1:" + _canon(provisional.canonical()))).decode("ascii").rstrip("=")
        return PrivacyDecision(self.tenant, decision_id, case_id, case_digest, self.authority_id, self.issuer_key_id,
            decision, evidence_references, moment, expiry, signature)

    def verifies(self, decision, *, at):
        try:
            moment = _time(at)
            if (type(decision) is not PrivacyDecision or not self.is_active(at=moment) or decision.tenant != self.tenant
                    or decision.authority_id != self.authority_id or decision.issuer_key_id != self.issuer_key_id
                    or decision.expires_at <= moment or decision.expires_at > self.expires_at): return False
            self._key.public_key().verify(base64.urlsafe_b64decode(decision.signature.split(":",2)[2]+"=="), b"privacy-decision-v1:" + _canon(decision.canonical()))
            return True
        except (InvalidSignature, ValueError, UnicodeError, PrivacyDecisionError, PrivacyEvidencePolicyError): return False


@dataclass(frozen=True, slots=True)
class PrivacyDecisionControl:
    """Locally configured signer plus distinct M12 V2 evidence issuers.

    The evidence issuers are deliberately different from native-report
    attestors.  A native report is first re-verified by the repository, then
    this authority converts its aggregate measurement into an M12 V2-scoped
    attestation.  A client never supplies either an issuer or a policy.
    """
    decision_authority: PrivacyDecisionAuthority
    max_evidence_age_seconds: int
    thresholds: tuple[tuple[PrivacyEvidenceKind, int], ...]
    evidence_authorities: tuple[tuple[PrivacyEvidenceKind, PrivacyEvidenceAttestationAuthority], ...] = field(repr=False)

    def __post_init__(self):
        if type(self) is not PrivacyDecisionControl or not 1 <= self.max_evidence_age_seconds <= 2678400: _fail()
        if (len(self.thresholds) != 5 or tuple(sorted(self.thresholds, key=lambda x:x[0].value)) != self.thresholds
                or {x[0] for x in self.thresholds} != set(PrivacyEvidenceKind)
                or len(self.evidence_authorities) != 5 or {x[0] for x in self.evidence_authorities} != set(PrivacyEvidenceKind)
                or len({x[1].issuer_key_id for x in self.evidence_authorities}) != 5): _fail()

    @property
    def tenant(self): return self.decision_authority.tenant
    def is_active(self, *, at=None): return self.decision_authority.is_active(at=at)
    def policy(self, binding):
        if type(binding) is not PrivacyEvidenceBinding: _fail()
        issuers = dict(self.evidence_authorities); thresholds = dict(self.thresholds)
        return PrivacyEvidencePolicy("m15-privacy-evidence", binding.method_provenance_digest,
            self.max_evidence_age_seconds,
            tuple(sorted((EvidenceRequirement(kind, issuers[kind].issuer_key_id, thresholds[kind],
                                              issuers[kind].authority_id, issuers[kind].policy_verifier.public_key_fingerprint)
                          for kind in PrivacyEvidenceKind), key=lambda x:x.kind.value)),
            PrivacyEvidenceAttestationProfile.ED25519_V2)
    def evidence_authority(self, kind):
        result = dict(self.evidence_authorities).get(kind)
        if result is None: _fail()
        return result
    def opaque_reference(self, *, kind, record_id, record_digest):
        """Keyed token: record IDs/digests are not published as policy refs."""
        if type(kind) is not PrivacyEvidenceKind: _fail()
        _id(record_id); _digest(record_digest)
        raw = self.decision_authority._key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                          serialization.NoEncryption())
        token=hmac.new(raw, b"m15-native-reference-v1:\x00" + _canon({"kind":kind.value,"record_id":record_id,"record_digest":record_digest}), hashlib.sha256).digest()
        return "evidence:v1:" + base64.urlsafe_b64encode(token).decode("ascii").rstrip("=")
    def decision_identifier(self, *, case_id, idempotency_key):
        _id(case_id)
        if type(idempotency_key) is not str or not 1 <= len(idempotency_key) <= 200 or not idempotency_key.isascii() or any(x.isspace() for x in idempotency_key): _fail()
        raw=self.decision_authority._key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        return "privacy-decision:v1:" + base64.urlsafe_b64encode(hmac.new(raw,b"m15-decision-id-v1:\x00"+_canon({"case_id":case_id,"key":idempotency_key}),hashlib.sha256).digest()).decode("ascii").rstrip("=")


def load_privacy_decision_controls():
    """Load bounded local M15 configuration.  Missing config means no gate."""
    raw = os.getenv("ANONFLOW_PRIVACY_DECISION_AUTHORITIES", "")
    if not raw: return ()
    if len(raw.encode("utf-8")) > 65536: _fail()
    try:
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result: raise ValueError
                result[key] = value
            return result
        entries = json.loads(raw, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if type(entries) is not list or not entries or len(entries) > 64: _fail()
        output=[]; tenants=set()
        for value in entries:
            if not isinstance(value, dict) or set(value) != {"tenant","issuer_key_id","expires_at","private_key","max_evidence_age_seconds","requirements"}: _fail()
            expiry = datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00"))
            signer = PrivacyDecisionAuthority(value["tenant"], value["issuer_key_id"], expiry, value["private_key"])
            reqs = value["requirements"]
            if type(reqs) is not list or len(reqs) != 5: _fail()
            thresholds=[]; issuers=[]
            for req in reqs:
                if not isinstance(req, dict) or set(req) != {"kind","threshold","issuer_key_id","key"}: _fail()
                kind=PrivacyEvidenceKind(req["kind"]); base64.b64decode(req["key"], validate=True)
                issuer=PrivacyEvidenceAttestationAuthority(value["tenant"], req["issuer_key_id"], expiry, req["key"])
                thresholds.append((kind, req["threshold"])); issuers.append((kind, issuer))
            control=PrivacyDecisionControl(signer, value["max_evidence_age_seconds"], tuple(sorted(thresholds,key=lambda x:x[0].value)), tuple(issuers))
            if control.tenant in tenants: _fail()
            tenants.add(control.tenant); output.append(control)
        return tuple(output)
    except (TypeError, ValueError, UnicodeError, PrivacyDecisionError, PrivacyEvidencePolicyError, PrivacyEvidenceAuthorityError): _fail()


def control_for_tenant(controls, *, tenant, at=None):
    matches=[x for x in controls if x.tenant == tenant and x.is_active(at=at)]
    if len(matches) != 1: _fail()
    return matches[0]
