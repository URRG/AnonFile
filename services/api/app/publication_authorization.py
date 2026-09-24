"""Externally-issued authorization attestations for one publication binding.

This contract only authenticates a narrowly scoped assertion from a pinned
public key.  It does *not* evaluate rights, inspect M18/M21 controls, or make
an object available.  The integration which admits an attestation must perform
those live checks separately and use this verifier as one fail-closed input.
"""
from __future__ import annotations

import base64
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.postgres_publication_intents import PublicationIntent, _plan_digest
from app.publication_payload_binding import PublicationPayloadBinding


_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_PUBLICATION = re.compile(r"publicationref:v1:" + _OPAQUE + r"\Z")
_RECORD = re.compile(r"metarecord:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_RIGHTS_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_CASE = re.compile(r"release-case:v1:" + _OPAQUE + r"\Z")
_DECISION = re.compile(r"privacy-decision:v1:" + _OPAQUE + r"\Z")
_RECIPIENT = re.compile(r"recipient-commitment:v1:" + _OPAQUE + r"\Z")
_SIGNATURE = re.compile(r"publication-authorization-sig:v1:[A-Za-z0-9_-]{86}\Z")
_DOMAIN = b"anonflow-publication-authorization-attestation:v1:\x00"
_MAX_LIFETIME = timedelta(minutes=5)


class PublicationAuthorizationError(ValueError):
    """A malformed, untrusted, expired, or mismatched attestation."""

    def __init__(self) -> None:
        super().__init__("publication authorization unavailable")


def _fail() -> None:
    raise PublicationAuthorizationError() from None


def _canonical(value: object) -> bytes:
    try:
        return _DOMAIN + json.dumps(value, ensure_ascii=True, allow_nan=False,
                                    sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    value = value.astimezone(UTC)
    if value.microsecond:
        _fail()
    return value


def _signature(value: object) -> bytes:
    if type(value) is not str or not _SIGNATURE.fullmatch(value):
        _fail()
    try:
        encoded = value.rsplit(":", 1)[1]
        result = base64.urlsafe_b64decode(encoded + "==")
        if len(result) != 64 or base64.urlsafe_b64encode(result).decode("ascii").rstrip("=") != encoded:
            _fail()
        return result
    except (ValueError, UnicodeError):
        _fail()


@dataclass(frozen=True, slots=True)
class PublicationAuthorizationAttestation:
    """One opaque, exact-scope grant signed outside the publication worker."""

    tenant_ref: str
    publication_ref: str
    plan_digest: str
    target_ref: str
    metadata_kind: str
    binding_digest: str
    release_case_id: str
    release_case_digest: str
    privacy_decision_id: str
    privacy_decision_digest: str
    approval_digests: tuple[str, str]
    rights_digest: str
    contract_digest: str
    recipient_commitment: str
    purpose_code: str
    issuer_key_id: str
    issued_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT); _text(self.publication_ref, _PUBLICATION)
        for name in ("plan_digest", "binding_digest", "release_case_digest",
                     "privacy_decision_digest", "contract_digest"):
            _text(getattr(self, name), _DIGEST)
        _text(self.target_ref, _RECORD); _text(self.metadata_kind, _IDENTIFIER)
        _text(self.release_case_id, _CASE); _text(self.privacy_decision_id, _DECISION)
        _text(self.rights_digest, _RIGHTS_DIGEST); _text(self.recipient_commitment, _RECIPIENT)
        _text(self.purpose_code, _IDENTIFIER); _text(self.issuer_key_id, _IDENTIFIER)
        if (type(self.approval_digests) is not tuple or len(self.approval_digests) != 2
                or len(set(self.approval_digests)) != 2):
            _fail()
        for digest in self.approval_digests:
            _text(digest, _DIGEST)
        object.__setattr__(self, "approval_digests", tuple(sorted(self.approval_digests)))
        object.__setattr__(self, "issued_at", _time(self.issued_at))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if self.expires_at <= self.issued_at or self.expires_at - self.issued_at > _MAX_LIFETIME:
            _fail()
        _signature(self.signature)
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(
            _canonical({**self.canonical(), "signature": self.signature})).hexdigest())

    def canonical(self) -> dict[str, object]:
        return {
            "approval_digests": list(self.approval_digests), "binding_digest": self.binding_digest,
            "contract_digest": self.contract_digest, "expires_at": _instant(self.expires_at),
            "issued_at": _instant(self.issued_at), "issuer_key_id": self.issuer_key_id,
            "metadata_kind": self.metadata_kind, "plan_digest": self.plan_digest,
            "privacy_decision_digest": self.privacy_decision_digest,
            "privacy_decision_id": self.privacy_decision_id, "publication_ref": self.publication_ref,
            "purpose_code": self.purpose_code, "recipient_commitment": self.recipient_commitment,
            "release_case_digest": self.release_case_digest, "release_case_id": self.release_case_id,
            "rights_digest": self.rights_digest, "target_ref": self.target_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_record(self) -> dict[str, object]:
        return {**self.canonical(), "digest": self.digest, "signature": self.signature}

    @classmethod
    def from_record(cls, value: object) -> "PublicationAuthorizationAttestation":
        expected = {"approval_digests", "binding_digest", "contract_digest", "digest", "expires_at",
                    "issued_at", "issuer_key_id", "metadata_kind", "plan_digest",
                    "privacy_decision_digest", "privacy_decision_id", "publication_ref", "purpose_code",
                    "recipient_commitment", "release_case_digest", "release_case_id", "rights_digest",
                    "signature", "target_ref", "tenant_ref"}
        try:
            if type(value) is not dict or set(value) != expected:
                _fail()
            result = cls(
                approval_digests=tuple(value["approval_digests"]), binding_digest=value["binding_digest"],
                contract_digest=value["contract_digest"], expires_at=datetime.fromisoformat(value["expires_at"].replace("Z", "+00:00")),
                issued_at=datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00")),
                issuer_key_id=value["issuer_key_id"], metadata_kind=value["metadata_kind"],
                plan_digest=value["plan_digest"], privacy_decision_digest=value["privacy_decision_digest"],
                privacy_decision_id=value["privacy_decision_id"], publication_ref=value["publication_ref"],
                purpose_code=value["purpose_code"], recipient_commitment=value["recipient_commitment"],
                release_case_digest=value["release_case_digest"], release_case_id=value["release_case_id"],
                rights_digest=value["rights_digest"], signature=value["signature"], target_ref=value["target_ref"],
                tenant_ref=value["tenant_ref"])
            # Signature verification operates on the canonical representation;
            # accepting an alternate wire spelling here would make storage
            # malleable even if it normalized to the same signed bytes.
            if result.to_record() != value:
                _fail()
            return result
        except (AttributeError, KeyError, TypeError, ValueError, PublicationAuthorizationError):
            _fail()


class PinnedPublicationAuthorizationVerifier:
    """Verify an attestation only against explicit Ed25519 public-key pins."""

    def __init__(self, keys: Mapping[str, bytes]) -> None:
        if not isinstance(keys, Mapping) or not keys or len(keys) > 64:
            _fail()
        parsed: dict[str, Ed25519PublicKey] = {}
        for key_id, raw in keys.items():
            _text(key_id, _IDENTIFIER)
            if type(raw) is not bytes or len(raw) != 32 or key_id in parsed:
                _fail()
            try:
                parsed[key_id] = Ed25519PublicKey.from_public_bytes(raw)
            except ValueError:
                _fail()
        self._keys = parsed

    def verify(self, *, attestation: PublicationAuthorizationAttestation,
               intent: PublicationIntent, binding: PublicationPayloadBinding,
               at: datetime) -> bool:
        """Return false for any malformed, stale, untrusted, or scope-drifted grant."""
        try:
            moment = _time(at)
            if (type(attestation) is not PublicationAuthorizationAttestation
                    or type(intent) is not PublicationIntent
                    or type(binding) is not PublicationPayloadBinding
                    or attestation.issued_at > moment or attestation.expires_at <= moment):
                return False
            key = self._keys.get(attestation.issuer_key_id)
            if key is None:
                return False
            if (attestation.tenant_ref != intent.tenant_ref != binding.tenant_ref
                    or attestation.publication_ref != intent.publication_ref != binding.publication_ref
                    or attestation.plan_digest != _plan_digest(intent) != binding.plan_digest
                    or attestation.target_ref != intent.target_ref
                    or attestation.metadata_kind != intent.metadata_kind
                    or attestation.binding_digest != binding.binding_digest):
                return False
            key.verify(_signature(attestation.signature), _canonical(attestation.canonical()))
            return True
        except (InvalidSignature, ValueError, TypeError, PublicationAuthorizationError):
            return False
