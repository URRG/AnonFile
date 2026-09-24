"""Fail-closed encrypted-object envelope and byte-transport boundary.

This module intentionally has no concrete object-store or KMS client.  It
turns an injected, per-object plaintext data key into one canonical encrypted
envelope and stores only that envelope through an injected byte transport.
Control-plane metadata receives an :class:`EncryptedObjectReference`, never
the plaintext, data key, wrapped data key, nonce, tag, or ciphertext bytes.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from base64 import urlsafe_b64decode, urlsafe_b64encode
from hashlib import sha256
import json
from os import urandom
import re
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.production_substrate import EncryptedObjectReference, ProductionSubstrateContractError


_TENANT = re.compile(r"tenantref:v1:[A-Za-z0-9_-]{43}\Z")
_OBJECT = re.compile(r"objectref:v1:[A-Za-z0-9_-]{43}\Z")
_KEY = re.compile(r"keyref:v1:[a-z0-9][a-z0-9._:-]{0,95}\Z")
_WRAPPED_KEY = re.compile(r"[\x21-\x7e]{1,16384}\Z")
_VERSION = 1
_NONCE_BYTES = 12
_TAG_BYTES = 16
_MAX_PLAINTEXT_BYTES = 32 * 1024 * 1024
# Base64 expands a maximum plaintext plus 16-byte GCM tag to less than 45 MiB.
# A 48 MiB envelope permits that expansion plus worst-case JSON escaping of the
# bounded wrapped key, while staying below the companion transport's 64 MiB cap.
_MAX_ENVELOPE_BYTES = 48 * 1024 * 1024


class EncryptedObjectStoreError(ValueError):
    """Fixed error that deliberately includes no payload or key material."""

    def __init__(self) -> None:
        super().__init__("Encrypted object operation failed")


def _fail() -> None:
    raise EncryptedObjectStoreError() from None


def _opaque(value: object, expression: re.Pattern[str]) -> str:
    if type(value) is not str or not expression.fullmatch(value):
        _fail()
    return value


def _b64_encode(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64_decode(value: object) -> bytes:
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9_-]*", value):
        _fail()
    try:
        return urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii"))
    except (ValueError, UnicodeError):
        _fail()


def _aad(*, tenant_ref: str, object_ref: str, key_ref: str) -> bytes:
    """Canonical, domain-separated context for key wrapping and AES-GCM."""
    return json.dumps(["anonflow-encrypted-object", _VERSION, tenant_ref, object_ref, key_ref],
                      ensure_ascii=True, separators=(",", ":")).encode("ascii")


def _canonical_envelope(*, wrapped_key: str, nonce: bytes, ciphertext: bytes) -> bytes:
    if not _WRAPPED_KEY.fullmatch(wrapped_key) or len(nonce) != _NONCE_BYTES or len(ciphertext) < _TAG_BYTES:
        _fail()
    encoded = json.dumps({"ciphertext": _b64_encode(ciphertext), "nonce": _b64_encode(nonce),
                          "version": _VERSION, "wrapped_key": wrapped_key}, ensure_ascii=True,
                         sort_keys=True, separators=(",", ":")).encode("ascii")
    if len(encoded) > _MAX_ENVELOPE_BYTES:
        _fail()
    return encoded


@dataclass(frozen=True, slots=True)
class GeneratedDataKey:
    """Ephemeral plaintext data key plus its provider-wrapped representation.

    This value must remain within the worker call stack.  It is never embedded
    in ``EncryptedObjectReference`` or returned by the object store.
    """

    plaintext_key: bytes = field(repr=False)
    wrapped_key: str

    def __post_init__(self) -> None:
        if type(self.plaintext_key) is not bytes or len(self.plaintext_key) != 32:
            _fail()
        if type(self.wrapped_key) is not str or not _WRAPPED_KEY.fullmatch(self.wrapped_key):
            _fail()


class DataKeyProvider(Protocol):
    """KMS boundary for one context-bound AES-256 data key.

    ``context`` is the canonical associated-data value.  A production OpenBao
    adapter must bind it during both generation and unwrap; an implementation
    that ignores it violates this contract.
    """

    def generate(self, *, key_ref: str, context: bytes) -> GeneratedDataKey: ...

    def unwrap(self, *, key_ref: str, wrapped_key: str, context: bytes) -> bytes: ...


class EncryptedByteTransport(Protocol):
    """Opaque object-ref to exact-envelope byte transport.

    ``put`` must atomically create (never overwrite) exactly the supplied
    bytes before returning. ``get`` must return exactly the expected-digest
    object or raise. Both calls receive the validated tenant/object scope and
    expected digest so a concrete transport cannot silently cross a tenant
    prefix or substitute a different object.
    """

    def put(self, *, tenant_ref: str, object_ref: str, envelope: bytes, ciphertext_digest: str) -> None: ...

    def get(self, *, tenant_ref: str, object_ref: str, ciphertext_digest: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class _Envelope:
    wrapped_key: str
    nonce: bytes
    ciphertext: bytes


def _parse_envelope(value: object) -> _Envelope:
    if type(value) is not bytes or not 0 < len(value) <= _MAX_ENVELOPE_BYTES:
        _fail()
    try:
        decoded = json.loads(value.decode("ascii"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        _fail()
    if type(decoded) is not dict or set(decoded) != {"version", "wrapped_key", "nonce", "ciphertext"}:
        _fail()
    if decoded.get("version") != _VERSION or type(decoded["wrapped_key"]) is not str:
        _fail()
    nonce, ciphertext = _b64_decode(decoded["nonce"]), _b64_decode(decoded["ciphertext"])
    canonical = _canonical_envelope(wrapped_key=decoded["wrapped_key"], nonce=nonce, ciphertext=ciphertext)
    if canonical != value:
        _fail()
    return _Envelope(decoded["wrapped_key"], nonce, ciphertext)


class EncryptedObjectStore:
    """Encrypt and authenticate byte objects before passing them to transport."""

    def __init__(self, *, data_keys: DataKeyProvider, transport: EncryptedByteTransport) -> None:
        # Runtime protocol checks are intentionally avoided: structural checks
        # cannot establish the provider's key-custody or transport durability.
        self._data_keys = data_keys
        self._transport = transport

    @staticmethod
    def _reference(*, tenant_ref: str, object_ref: str, key_ref: str, envelope: bytes) -> EncryptedObjectReference:
        try:
            return EncryptedObjectReference(tenant_ref=tenant_ref, object_ref=object_ref, key_ref=key_ref,
                                            ciphertext_digest="sha256:" + sha256(envelope).hexdigest(),
                                            ciphertext_size_bytes=len(envelope))
        except ProductionSubstrateContractError:
            _fail()

    def put(self, *, tenant_ref: object, object_ref: object, key_ref: object, plaintext: object) -> EncryptedObjectReference:
        tenant, object_id, key = _opaque(tenant_ref, _TENANT), _opaque(object_ref, _OBJECT), _opaque(key_ref, _KEY)
        if type(plaintext) is not bytes or len(plaintext) > _MAX_PLAINTEXT_BYTES:
            _fail()
        context = _aad(tenant_ref=tenant, object_ref=object_id, key_ref=key)
        try:
            generated = self._data_keys.generate(key_ref=key, context=context)
            # Providers may expose their own immutable return type (for
            # example an OpenBao adapter).  Copy only the two exact primitive
            # values we need into this boundary's validated ephemeral shape.
            generated = GeneratedDataKey(generated.plaintext_key, generated.wrapped_key)
            fresh_nonce = urandom(_NONCE_BYTES)
            ciphertext = AESGCM(generated.plaintext_key).encrypt(fresh_nonce, plaintext, context)
            envelope = _canonical_envelope(wrapped_key=generated.wrapped_key, nonce=fresh_nonce, ciphertext=ciphertext)
            reference = self._reference(tenant_ref=tenant, object_ref=object_id, key_ref=key, envelope=envelope)
            self._transport.put(tenant_ref=tenant, object_ref=object_id, envelope=envelope,
                                ciphertext_digest=reference.ciphertext_digest)
            return reference
        except EncryptedObjectStoreError:
            raise
        except Exception:
            _fail()

    def get(self, *, tenant_ref: object, reference: object) -> bytes:
        tenant = _opaque(tenant_ref, _TENANT)
        if type(reference) is not EncryptedObjectReference or reference.tenant_ref != tenant:
            _fail()
        context = _aad(tenant_ref=tenant, object_ref=reference.object_ref, key_ref=reference.key_ref)
        try:
            envelope_bytes = self._transport.get(tenant_ref=tenant, object_ref=reference.object_ref,
                                                 ciphertext_digest=reference.ciphertext_digest)
            if type(envelope_bytes) is not bytes:
                _fail()
            if (len(envelope_bytes) != reference.ciphertext_size_bytes
                    or "sha256:" + sha256(envelope_bytes).hexdigest() != reference.ciphertext_digest):
                _fail()
            envelope = _parse_envelope(envelope_bytes)
            plaintext_key = self._data_keys.unwrap(key_ref=reference.key_ref,
                                                    wrapped_key=envelope.wrapped_key, context=context)
            if type(plaintext_key) is not bytes or len(plaintext_key) != 32:
                _fail()
            return AESGCM(plaintext_key).decrypt(envelope.nonce, envelope.ciphertext, context)
        except EncryptedObjectStoreError:
            raise
        except (InvalidTag, ValueError, TypeError, UnicodeError):
            _fail()
        except Exception:
            _fail()
