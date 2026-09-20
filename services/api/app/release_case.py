"""Immutable, source-safe release-case provenance.

This worker-side primitive is deliberately narrower than release approval.  It
creates a signed record that names the one exact candidate, processing run,
policy/rights scope, recipient commitment, purpose, method and contract that a
future independently-operated workflow must assess.  It never opens a
delivery, changes a run, records an approval, or contains source/candidate
bytes, a recipient name, a contract body, a credential, or a delivery handle.
"""
from __future__ import annotations

import base64
from dataclasses import InitVar, dataclass, field
from datetime import UTC, datetime
import hashlib
import hmac
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


MAX_CASE_LIFETIME_SECONDS = 31 * 24 * 60 * 60
MAX_AUTHORITY_LIFETIME_SECONDS = 366 * 24 * 60 * 60
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RIGHTS_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_CASE_ID = re.compile(r"release-case:v1:[A-Za-z0-9_-]{43}\Z")
_AUTHORITY_ID = re.compile(r"release-case-authority:v1:[A-Za-z0-9_-]{43}\Z")
_RECIPIENT_COMMITMENT = re.compile(r"recipient-commitment:v1:[A-Za-z0-9_-]{43}\Z")
_CONTRACT_REFERENCE = re.compile(r"contract-reference:v1:[A-Za-z0-9_-]{43}\Z")
_SIGNATURE = re.compile(r"release-case-sig:v1:[A-Za-z0-9_-]{86}\Z")


class ReleaseCaseError(ValueError):
    """Fixed failure; no source values, names, or key material are reflected."""

    def __init__(self) -> None:
        super().__init__("Invalid release case input")


def _fail() -> None:
    raise ReleaseCaseError()


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


def _rights_digest(value: object) -> str:
    if type(value) is not str or not _RIGHTS_DIGEST.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    result = value.astimezone(UTC)
    if result.microsecond:
        _fail()
    return result


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _private_key(value: object) -> Ed25519PrivateKey:
    if type(value) is not str or len(value) != 44:
        _fail()
    try:
        raw = base64.b64decode(value, validate=True)
        if len(raw) != 32 or base64.b64encode(raw).decode("ascii") != value:
            _fail()
        return Ed25519PrivateKey.from_private_bytes(raw)
    except (ValueError, UnicodeError):
        _fail()


def _commitment_salt(value: object) -> bytes:
    if type(value) is not bytes or len(value) != 32:
        _fail()
    return value


def _recipient(value: object) -> str:
    """One canonical private recipient label, used only to derive an HMAC token."""
    return _identifier(value)


def _recipient_commitment(*, salt: bytes, tenant: str, recipient: str, rights_digest: str,
                          purpose_code: str, processing_mode: str, processing_run_id: str,
                          recipient_commitment_key_id: str) -> str:
    """Domain-separated opaque commitment; never a plain recipient hash."""
    digest = hmac.new(salt, b"release-case-recipient-v1:\x00" + _canonical({
        "processing_mode": processing_mode, "processing_run_id": processing_run_id,
        "purpose_code": purpose_code, "recipient": recipient, "rights_digest": rights_digest,
        "recipient_commitment_key_id": recipient_commitment_key_id, "tenant": tenant,
    }), hashlib.sha256).digest()
    return "recipient-commitment:v1:" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _authority_identity(*, tenant: str, issuer_key_id: str, recipient_commitment_key_id: str,
                        expires_at: datetime, public_key_b64: str) -> str:
    digest = hashlib.sha256(_canonical({
        "expires_at": _instant(expires_at), "issuer_key_id": issuer_key_id,
        "public_key": public_key_b64, "recipient_commitment_key_id": recipient_commitment_key_id,
        "schema": "release-case-authority-ed25519-v1", "tenant": tenant,
    })).digest()
    return "release-case-authority:v1:" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


@dataclass(frozen=True, slots=True)
class ReleaseCaseBinding:
    """Complete exact context, retaining only opaque references and digests."""

    candidate_artifact_digest: str
    processing_run_id: str
    processing_run_digest: str
    processing_request_digest: str
    processing_mode: str
    processing_policy_digest: str
    dataset_provenance_digest: str
    ingestion_provenance_digest: str
    rights_digest: str
    recipient_commitment_key_id: str
    recipient_commitment: str = field(repr=False)
    purpose_code: str
    method_provenance_digest: str
    contract_reference: str = field(repr=False)
    contract_digest: str
    candidate_expires_at: datetime
    processing_run_expires_at: datetime
    rights_expires_at: datetime
    contract_expires_at: datetime
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self) is not ReleaseCaseBinding:
            _fail()
        object.__setattr__(self, "candidate_artifact_digest", _digest(self.candidate_artifact_digest))
        object.__setattr__(self, "processing_run_id", _identifier(self.processing_run_id))
        object.__setattr__(self, "processing_run_digest", _digest(self.processing_run_digest))
        object.__setattr__(self, "processing_request_digest", _digest(self.processing_request_digest))
        object.__setattr__(self, "processing_mode", _identifier(self.processing_mode))
        object.__setattr__(self, "processing_policy_digest", _digest(self.processing_policy_digest))
        object.__setattr__(self, "dataset_provenance_digest", _digest(self.dataset_provenance_digest))
        object.__setattr__(self, "ingestion_provenance_digest", _digest(self.ingestion_provenance_digest))
        object.__setattr__(self, "rights_digest", _rights_digest(self.rights_digest))
        object.__setattr__(self, "recipient_commitment_key_id", _identifier(self.recipient_commitment_key_id))
        if type(self.recipient_commitment) is not str or not _RECIPIENT_COMMITMENT.fullmatch(self.recipient_commitment):
            _fail()
        object.__setattr__(self, "purpose_code", _identifier(self.purpose_code))
        object.__setattr__(self, "method_provenance_digest", _digest(self.method_provenance_digest))
        if type(self.contract_reference) is not str or not _CONTRACT_REFERENCE.fullmatch(self.contract_reference):
            _fail()
        object.__setattr__(self, "contract_digest", _digest(self.contract_digest))
        object.__setattr__(self, "candidate_expires_at", _time(self.candidate_expires_at))
        object.__setattr__(self, "processing_run_expires_at", _time(self.processing_run_expires_at))
        object.__setattr__(self, "rights_expires_at", _time(self.rights_expires_at))
        object.__setattr__(self, "contract_expires_at", _time(self.contract_expires_at))
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(_canonical(self.canonical())).hexdigest())

    def canonical(self) -> dict[str, str]:
        return {
            "candidate_artifact_digest": self.candidate_artifact_digest,
            "candidate_expires_at": _instant(self.candidate_expires_at),
            "contract_digest": self.contract_digest,
            "contract_expires_at": _instant(self.contract_expires_at),
            "contract_reference": self.contract_reference,
            "dataset_provenance_digest": self.dataset_provenance_digest,
            "ingestion_provenance_digest": self.ingestion_provenance_digest,
            "method_provenance_digest": self.method_provenance_digest,
            "processing_policy_digest": self.processing_policy_digest,
            "processing_run_digest": self.processing_run_digest,
            "processing_run_expires_at": _instant(self.processing_run_expires_at),
            "processing_run_id": self.processing_run_id,
            "processing_request_digest": self.processing_request_digest,
            "processing_mode": self.processing_mode,
            "purpose_code": self.purpose_code,
            "recipient_commitment": self.recipient_commitment,
            "recipient_commitment_key_id": self.recipient_commitment_key_id,
            "rights_digest": self.rights_digest,
            "rights_expires_at": _instant(self.rights_expires_at),
        }


@dataclass(frozen=True, slots=True)
class ReleaseCase:
    """Ed25519-signed provenance record; it grants no release authority."""

    tenant: str
    case_id: str
    authority_id: str
    issuer_key_id: str
    binding: ReleaseCaseBinding = field(repr=False)
    issued_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)
    posture: str = "NO_RELEASE_AUTHORIZATION"
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if type(self) is not ReleaseCase:
            _fail()
        object.__setattr__(self, "tenant", _identifier(self.tenant))
        if type(self.case_id) is not str or not _CASE_ID.fullmatch(self.case_id):
            _fail()
        if type(self.authority_id) is not str or not _AUTHORITY_ID.fullmatch(self.authority_id):
            _fail()
        object.__setattr__(self, "issuer_key_id", _identifier(self.issuer_key_id))
        if type(self.binding) is not ReleaseCaseBinding:
            _fail()
        object.__setattr__(self, "issued_at", _time(self.issued_at))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if (self.expires_at <= self.issued_at or self.expires_at > min(
                self.binding.candidate_expires_at, self.binding.processing_run_expires_at,
                self.binding.rights_expires_at, self.binding.contract_expires_at)
                or (self.expires_at - self.issued_at).total_seconds() > MAX_CASE_LIFETIME_SECONDS
                or self.posture != "NO_RELEASE_AUTHORIZATION" or type(self.signature) is not str
                or not _SIGNATURE.fullmatch(self.signature)):
            _fail()
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(
            _canonical({**self.canonical(), "signature": self.signature})).hexdigest())

    def canonical(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id, "binding": self.binding.canonical(), "case_id": self.case_id,
            "expires_at": _instant(self.expires_at), "issued_at": _instant(self.issued_at),
            "issuer_key_id": self.issuer_key_id, "posture": self.posture, "tenant": self.tenant,
        }

    def to_record(self) -> dict[str, object]:
        """Metadata-only record, with no source bytes, recipient, or delivery handle."""
        return {**self.canonical(), "digest": self.digest, "signature": self.signature}


class ReleaseCasePublicVerifier:
    """Public-key-only verifier, deliberately incapable of issuing cases."""

    __slots__ = ("_public_key", "authority_id", "expires_at", "issuer_key_id", "public_key_fingerprint",
                 "recipient_commitment_key_id", "tenant")

    def __init__(self, *, tenant: str, issuer_key_id: str, authority_id: str,
                 recipient_commitment_key_id: str, public_key_b64: str, expires_at: datetime) -> None:
        self.tenant = _identifier(tenant)
        self.issuer_key_id = _identifier(issuer_key_id)
        self.recipient_commitment_key_id = _identifier(recipient_commitment_key_id)
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
            if authority_id != _authority_identity(
                    tenant=self.tenant, issuer_key_id=self.issuer_key_id,
                    recipient_commitment_key_id=self.recipient_commitment_key_id,
                    expires_at=self.expires_at, public_key_b64=public_key_b64):
                _fail()
        except (ValueError, UnicodeError):
            _fail()

    def __repr__(self) -> str:
        return f"ReleaseCasePublicVerifier(issuer_key_id={self.issuer_key_id!r}, public_key=<redacted>)"

    def verifies(self, record: object, *, at: datetime) -> bool:
        try:
            moment = _time(at)
            if (type(record) is not ReleaseCase or moment >= self.expires_at or record.expires_at <= moment
                    or record.issued_at > moment or record.expires_at > self.expires_at
                    or record.tenant != self.tenant or record.issuer_key_id != self.issuer_key_id
                    or record.authority_id != self.authority_id
                    or record.binding.recipient_commitment_key_id != self.recipient_commitment_key_id):
                return False
            signature = base64.urlsafe_b64decode(record.signature.split(":", 2)[2] + "==")
            if len(signature) != 64:
                return False
            self._public_key.verify(signature, b"release-case-v1:" + _canonical(record.canonical()))
            return True
        except (InvalidSignature, ValueError, UnicodeError, ReleaseCaseError):
            return False


@dataclass(frozen=True, slots=True)
class ReleaseCaseAuthority:
    """Tenant-scoped Ed25519 issuer that commits private recipient input with HMAC."""

    tenant: str
    issuer_key_id: str
    expires_at: datetime
    recipient_commitment_key_id: str
    private_key_b64: InitVar[str] = field(repr=False, compare=False)
    recipient_commitment_salt: InitVar[bytes] = field(repr=False, compare=False)
    authority_id: str = field(init=False)
    _private_key: Ed25519PrivateKey = field(init=False, repr=False, compare=False)
    _recipient_salt: bytes = field(init=False, repr=False, compare=False)
    _public_key_b64: str = field(init=False, repr=False, compare=False)

    def __post_init__(self, private_key_b64: str, recipient_commitment_salt: bytes) -> None:
        if type(self) is not ReleaseCaseAuthority:
            _fail()
        tenant, issuer, commitment_key_id, expiry = (_identifier(self.tenant), _identifier(self.issuer_key_id),
                                                      _identifier(self.recipient_commitment_key_id), _time(self.expires_at))
        key, salt = _private_key(private_key_b64), _commitment_salt(recipient_commitment_salt)
        now = datetime.now(UTC).replace(microsecond=0)
        if expiry <= now or (expiry - now).total_seconds() > MAX_AUTHORITY_LIFETIME_SECONDS:
            _fail()
        public_raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        public_key_b64 = base64.b64encode(public_raw).decode("ascii")
        authority_id = _authority_identity(tenant=tenant, issuer_key_id=issuer,
                                           recipient_commitment_key_id=commitment_key_id, expires_at=expiry,
                                           public_key_b64=public_key_b64)
        if not _AUTHORITY_ID.fullmatch(authority_id):
            _fail()
        object.__setattr__(self, "tenant", tenant)
        object.__setattr__(self, "issuer_key_id", issuer)
        object.__setattr__(self, "recipient_commitment_key_id", commitment_key_id)
        object.__setattr__(self, "expires_at", expiry)
        object.__setattr__(self, "authority_id", authority_id)
        object.__setattr__(self, "_private_key", key)
        object.__setattr__(self, "_recipient_salt", salt)
        object.__setattr__(self, "_public_key_b64", public_key_b64)

    def __repr__(self) -> str:
        return ("ReleaseCaseAuthority(tenant=" + repr(self.tenant) + ", issuer_key_id="
                + repr(self.issuer_key_id) + ", private_key=<redacted>, recipient_salt=<redacted>)")

    def is_active(self, *, at: datetime | None = None) -> bool:
        try:
            moment = datetime.now(UTC).replace(microsecond=0) if at is None else _time(at)
            return moment < self.expires_at
        except ReleaseCaseError:
            return False

    @property
    def public_verifier(self) -> ReleaseCasePublicVerifier:
        return ReleaseCasePublicVerifier(tenant=self.tenant, issuer_key_id=self.issuer_key_id,
                                         authority_id=self.authority_id,
                                         recipient_commitment_key_id=self.recipient_commitment_key_id,
                                         public_key_b64=self._public_key_b64,
                                         expires_at=self.expires_at)

    def issue(self, *, case_id: str, candidate_artifact_digest: str, processing_run_id: str,
              processing_run_digest: str, processing_request_digest: str, processing_mode: str,
              processing_policy_digest: str, dataset_provenance_digest: str, ingestion_provenance_digest: str, rights_digest: str,
              recipient: str, purpose_code: str, method_provenance_digest: str,
              contract_reference: str, contract_digest: str, candidate_expires_at: datetime,
              processing_run_expires_at: datetime, rights_expires_at: datetime, contract_expires_at: datetime,
              issued_at: datetime, expires_at: datetime, at: datetime | None = None) -> ReleaseCase:
        """Sign exact scope inside a trusted worker; no raw recipient is retained."""
        moment = datetime.now(UTC).replace(microsecond=0) if at is None else _time(at)
        if not self.is_active(at=moment):
            _fail()
        recipient_value = _recipient(recipient)
        run_id, rights, purpose, mode = (_identifier(processing_run_id), _rights_digest(rights_digest),
                                         _identifier(purpose_code), _identifier(processing_mode))
        binding = ReleaseCaseBinding(
            candidate_artifact_digest=candidate_artifact_digest, processing_run_id=run_id,
            processing_run_digest=processing_run_digest, processing_request_digest=processing_request_digest,
            processing_mode=mode, processing_policy_digest=processing_policy_digest,
            dataset_provenance_digest=dataset_provenance_digest, ingestion_provenance_digest=ingestion_provenance_digest,
            rights_digest=rights, recipient_commitment_key_id=self.recipient_commitment_key_id,
            recipient_commitment=_recipient_commitment(
                salt=self._recipient_salt, tenant=self.tenant, recipient=recipient_value, rights_digest=rights,
                purpose_code=purpose, processing_mode=mode, processing_run_id=run_id,
                recipient_commitment_key_id=self.recipient_commitment_key_id),
            purpose_code=purpose, method_provenance_digest=method_provenance_digest,
            contract_reference=contract_reference, contract_digest=contract_digest,
            candidate_expires_at=candidate_expires_at, processing_run_expires_at=processing_run_expires_at,
            rights_expires_at=rights_expires_at, contract_expires_at=contract_expires_at,
        )
        issued, expiry = _time(issued_at), _time(expires_at)
        if (issued > moment or expiry <= moment or expiry > min(
                self.expires_at, binding.candidate_expires_at, binding.processing_run_expires_at,
                binding.rights_expires_at, binding.contract_expires_at)):
            _fail()
        provisional = ReleaseCase(tenant=self.tenant, case_id=case_id, authority_id=self.authority_id,
                                  issuer_key_id=self.issuer_key_id, binding=binding, issued_at=issued,
                                  expires_at=expiry, signature="release-case-sig:v1:" + "A" * 86)
        signature = base64.urlsafe_b64encode(self._private_key.sign(
            b"release-case-v1:" + _canonical(provisional.canonical()))).decode("ascii").rstrip("=")
        return ReleaseCase(tenant=provisional.tenant, case_id=provisional.case_id,
                           authority_id=provisional.authority_id, issuer_key_id=provisional.issuer_key_id,
                           binding=provisional.binding, issued_at=provisional.issued_at,
                           expires_at=provisional.expires_at, signature="release-case-sig:v1:" + signature)

    def verifies(self, record: object, *, at: datetime) -> bool:
        """Verify exact authority and recipient commitment as well as its signature."""
        if not self.public_verifier.verifies(record, at=at):
            return False
        try:
            # This detects an internal caller that substituted a valid-looking
            # opaque recipient token rather than using this authority's HMAC boundary.
            return type(record) is ReleaseCase and bool(_RECIPIENT_COMMITMENT.fullmatch(record.binding.recipient_commitment))
        except ReleaseCaseError:
            return False
