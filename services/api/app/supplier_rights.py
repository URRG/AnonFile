"""Supplier-signed, exact-scope data-rights assertions.

This module verifies cryptographic statements only.  A valid statement does
not establish legal validity, authorize storage or release, or load a signing
key.  In particular, a ``TrustedSigningKey`` constructed by a caller is not an
authority record: a future PostgreSQL admission transaction must use
``PostgresTrustedSigningKeyAuthority.lock_active`` on the registry-loaded key
and keep that lock through its own durable mutation.
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import hashlib
import json
import re

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.postgres_trusted_signing_keys import TrustedSigningKey


_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_ACTOR = re.compile(r"actorref:v1:" + _OPAQUE + r"\Z")
_KEY = re.compile(r"signingkeyref:v1:" + _OPAQUE + r"\Z")
_SUPPLIER_ORG = re.compile(r"supplierorgref:v1:" + _OPAQUE + r"\Z")
_BUYER_ORG = re.compile(r"buyerorgref:v1:" + _OPAQUE + r"\Z")
_SOURCE = re.compile(r"supplierdatasetref:v1:" + _OPAQUE + r"\Z")
_CUSTODY = re.compile(r"custodyref:v1:" + _OPAQUE + r"\Z")
_RECIPIENT = re.compile(r"recipientref:v1:" + _OPAQUE + r"\Z")
_CONTRACT = re.compile(r"suppliercontractref:v1:" + _OPAQUE + r"\Z")
_NONCE = re.compile(r"supplierrightsnonce:v1:" + _OPAQUE + r"\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_SIGNATURE = re.compile(r"supplier-rights-sig:v1:[A-Za-z0-9_-]{86}\Z")
_DOMAIN = b"anonflow-supplier-rights-statement:v1:\x00"
_SCHEMA = "supplier-rights-statement-ed25519-v1"
_MAX_LIFETIME = timedelta(days=31)


class SupplierRightsError(ValueError):
    """Fixed error for an invalid or untrusted supplier statement."""

    def __init__(self) -> None:
        super().__init__("supplier rights assertion unavailable")


def _fail() -> None:
    raise SupplierRightsError() from None


def _text(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    try:
        result = value.astimezone(UTC)
    except (OverflowError, ValueError):
        _fail()
    if result.microsecond:
        _fail()
    return result


def _instant(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _canonical(value: object) -> bytes:
    try:
        return _DOMAIN + json.dumps(value, ensure_ascii=True, allow_nan=False,
                                    sort_keys=True, separators=(",", ":")).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _signature(value: object) -> bytes:
    text = _text(value, _SIGNATURE)
    encoded = text.rsplit(":", 1)[1]
    try:
        raw = base64.urlsafe_b64decode(encoded + "==")
    except (binascii.Error, ValueError, UnicodeError):
        _fail()
    if len(raw) != 64 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded:
        _fail()
    return raw


def _public_key(value: object) -> Ed25519PublicKey:
    text = _text(value, re.compile(r"ed25519pub:v1:" + _OPAQUE + r"\Z"))
    encoded = text.removeprefix("ed25519pub:v1:")
    try:
        raw = base64.urlsafe_b64decode(encoded + "=")
        if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded:
            _fail()
        return Ed25519PublicKey.from_public_bytes(raw)
    except (binascii.Error, ValueError, UnicodeError):
        _fail()


@dataclass(frozen=True, slots=True)
class SupplierRightsAssertion:
    """One supplier's signed assertion for one exact dataset and recipient."""

    tenant_ref: str
    supplier_actor_ref: str
    supplier_key_ref: str
    supplier_org_ref: str
    source_dataset_ref: str
    source_dataset_digest: str
    custody_ref: str
    custody_intent_digest: str
    buyer_org_ref: str
    recipient_ref: str
    purpose_code: str
    processing_mode: str
    onward_transfer_permitted: bool
    contract_ref: str
    contract_digest: str
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    nonce: str
    signature: str = field(repr=False)
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        _text(self.tenant_ref, _TENANT)
        _text(self.supplier_actor_ref, _ACTOR)
        _text(self.supplier_key_ref, _KEY)
        _text(self.supplier_org_ref, _SUPPLIER_ORG)
        _text(self.source_dataset_ref, _SOURCE)
        _text(self.source_dataset_digest, _DIGEST)
        _text(self.custody_ref, _CUSTODY)
        _text(self.custody_intent_digest, _DIGEST)
        _text(self.buyer_org_ref, _BUYER_ORG)
        _text(self.recipient_ref, _RECIPIENT)
        _text(self.purpose_code, _IDENTIFIER)
        _text(self.processing_mode, _IDENTIFIER)
        # M48a is deliberately deny-only. A later statement version can add
        # an exact conditions digest before an affirmative transfer is modeled.
        if self.onward_transfer_permitted is not False:
            _fail()
        _text(self.contract_ref, _CONTRACT)
        _text(self.contract_digest, _DIGEST)
        object.__setattr__(self, "issued_at", _time(self.issued_at))
        object.__setattr__(self, "not_before", _time(self.not_before))
        object.__setattr__(self, "expires_at", _time(self.expires_at))
        if (self.not_before < self.issued_at or self.expires_at <= self.not_before
                or self.expires_at - self.issued_at > _MAX_LIFETIME):
            _fail()
        _text(self.nonce, _NONCE)
        _signature(self.signature)
        object.__setattr__(self, "digest", "sha256:" + hashlib.sha256(
            _canonical({**self.canonical(), "signature": self.signature})).hexdigest())

    def canonical(self) -> dict[str, object]:
        return {
            "buyer_org_ref": self.buyer_org_ref,
            "contract_digest": self.contract_digest,
            "contract_ref": self.contract_ref,
            "custody_intent_digest": self.custody_intent_digest,
            "custody_ref": self.custody_ref,
            "expires_at": _instant(self.expires_at),
            "issued_at": _instant(self.issued_at),
            "nonce": self.nonce,
            "not_before": _instant(self.not_before),
            "onward_transfer_permitted": self.onward_transfer_permitted,
            "processing_mode": self.processing_mode,
            "purpose_code": self.purpose_code,
            "recipient_ref": self.recipient_ref,
            "schema": _SCHEMA,
            "source_dataset_digest": self.source_dataset_digest,
            "source_dataset_ref": self.source_dataset_ref,
            "supplier_actor_ref": self.supplier_actor_ref,
            "supplier_key_ref": self.supplier_key_ref,
            "supplier_org_ref": self.supplier_org_ref,
            "tenant_ref": self.tenant_ref,
        }

    def to_record(self) -> dict[str, object]:
        return {**self.canonical(), "digest": self.digest, "signature": self.signature}


class SupplierRightsVerifier:
    """Verify against one supplied key object; it is not registry authority."""

    def verify(self, assertion: object, *, trusted_key: object, at: datetime) -> bool:
        """Return false unless key identity, key validity, scope, and signature match.

        Callers must not treat this result as a database authorization.  The
        supplied key can be constructed from untrusted input and therefore a
        later admission path must lock and re-read the active registry key.
        """
        try:
            moment = _time(at)
            if type(assertion) is not SupplierRightsAssertion or type(trusted_key) is not TrustedSigningKey:
                return False
            if (trusted_key.role != "SUPPLIER_RIGHTS_ATTESTER"
                    or trusted_key.tenant_ref != assertion.tenant_ref
                    or trusted_key.actor_ref != assertion.supplier_actor_ref
                    or trusted_key.key_ref != assertion.supplier_key_ref
                    or not trusted_key.not_before <= moment < trusted_key.expires_at
                    or not assertion.not_before <= moment < assertion.expires_at
                    or assertion.issued_at > moment):
                return False
            _public_key(trusted_key.public_key).verify(
                _signature(assertion.signature), _canonical(assertion.canonical()))
            return True
        except (InvalidSignature, SupplierRightsError, ValueError, TypeError):
            return False
