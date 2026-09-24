"""Worker-only composition of the bounded OpenBao, envelope, and S3 seams.

This module deliberately supplies no route or repository integration.  Its
single public object accepts a short-lived OpenBao token *per operation* and
keeps that token inside a call-scoped ``DataKeyProvider`` adapter.  Object
metadata contains the M31 reference only; the opaque S3 object key never
leaves this boundary.
"""
from __future__ import annotations

from hashlib import sha256
import re

from app.encrypted_object_store import (DataKeyProvider, EncryptedByteTransport,
                                        EncryptedObjectStore, EncryptedObjectStoreError,
                                        GeneratedDataKey)
from app.openbao_datakey import OpenBaoTransitDataKey, TransitDataKey
from app.production_substrate import EncryptedObjectReference
from app.s3_ciphertext_transport import (FetchedCiphertext, S3CiphertextTransport,
                                         StoredCiphertext, opaque_object_key)


_DIGEST = re.compile(r"sha256:([0-9a-f]{64})\Z")


class WorkerEncryptedObjectsError(ValueError):
    """A fixed composition failure which contains no data, key, or token."""

    def __init__(self) -> None:
        super().__init__("Worker encrypted object operation failed")


def _fail() -> None:
    # This helper is routinely called while translating an adapter exception.
    # Suppress that exception's context so a rendered traceback cannot disclose
    # a provider body, ciphertext detail, or bearer token.
    raise WorkerEncryptedObjectsError() from None


def _raw_digest(value: object) -> str:
    match = _DIGEST.fullmatch(value) if type(value) is str else None
    if match is None:
        _fail()
    return match.group(1)


class _ScopedOpenBaoDataKeys(DataKeyProvider):
    """One operation's non-exported OpenBao token binding.

    The wrapper is constructed inside ``put``/``get`` only.  It has no
    persistence facility and its repr cannot reveal the bearer token.
    """

    __slots__ = ("_openbao", "_token")

    def __init__(self, openbao: OpenBaoTransitDataKey, token: object) -> None:
        if type(openbao) is not OpenBaoTransitDataKey or not _valid_token(token):
            _fail()
        self._openbao = openbao
        self._token = token

    def __repr__(self) -> str:
        return "<scoped OpenBao data-key provider>"

    def generate(self, *, key_ref: str, context: bytes) -> GeneratedDataKey:
        try:
            generated = self._openbao.generate(key_ref=key_ref, context=context, token=self._token)
            if type(generated) is not TransitDataKey:
                _fail()
            return GeneratedDataKey(generated.plaintext_key, generated.wrapped_key)
        except WorkerEncryptedObjectsError:
            raise
        except Exception:
            _fail()

    def unwrap(self, *, key_ref: str, wrapped_key: str, context: bytes) -> bytes:
        try:
            plaintext = self._openbao.unwrap(key_ref=key_ref, wrapped_key=wrapped_key,
                                             context=context, token=self._token)
            if type(plaintext) is not bytes or len(plaintext) != 32:
                _fail()
            return plaintext
        except WorkerEncryptedObjectsError:
            raise
        except Exception:
            _fail()


class _S3EnvelopeTransport(EncryptedByteTransport):
    """Map M31's full digest contract to the M32 ciphertext-only adapter."""

    __slots__ = ("_ciphertexts",)

    def __init__(self, ciphertexts: S3CiphertextTransport) -> None:
        if type(ciphertexts) is not S3CiphertextTransport:
            _fail()
        self._ciphertexts = ciphertexts

    def put(self, *, tenant_ref: str, object_ref: str, envelope: bytes, ciphertext_digest: str) -> None:
        digest = _raw_digest(ciphertext_digest)
        if type(envelope) is not bytes or sha256(envelope).hexdigest() != digest:
            _fail()
        try:
            stored = self._ciphertexts.store(tenant_id=tenant_ref, object_id=object_ref,
                                             ciphertext=envelope, ciphertext_sha256=digest)
            expected_key = opaque_object_key(self._ciphertexts._config, tenant_ref, object_ref)
            if (type(stored) is not StoredCiphertext or stored.key != expected_key
                    or stored.sha256 != digest or stored.byte_count != len(envelope)):
                _fail()
        except WorkerEncryptedObjectsError:
            raise
        except Exception:
            _fail()

    def get(self, *, tenant_ref: str, object_ref: str, ciphertext_digest: str) -> bytes:
        digest = _raw_digest(ciphertext_digest)
        try:
            fetched = self._ciphertexts.load(tenant_id=tenant_ref, object_id=object_ref,
                                             ciphertext_sha256=digest)
            expected_key = opaque_object_key(self._ciphertexts._config, tenant_ref, object_ref)
            if (type(fetched) is not FetchedCiphertext or fetched.key != expected_key
                    or fetched.sha256 != digest or type(fetched.ciphertext) is not bytes
                    or sha256(fetched.ciphertext).hexdigest() != digest):
                _fail()
            return fetched.ciphertext
        except WorkerEncryptedObjectsError:
            raise
        except Exception:
            _fail()


def _valid_token(value: object) -> bool:
    return (type(value) is str and 0 < len(value) <= 4096
            and all(33 <= ord(character) <= 126 for character in value))


class WorkerEncryptedObjects:
    """The bounded worker ``put``/``get`` interface for encrypted bytes.

    Construction takes deployment-owned, already configured M30/M32 adapters.
    Each public operation takes its own short-lived OpenBao token; neither
    tokens nor plaintext data keys are held by this long-lived composition
    object or returned to callers.
    """

    __slots__ = ("_openbao", "_ciphertexts")

    def __init__(self, *, openbao: OpenBaoTransitDataKey,
                 ciphertexts: S3CiphertextTransport) -> None:
        if type(openbao) is not OpenBaoTransitDataKey or type(ciphertexts) is not S3CiphertextTransport:
            _fail()
        self._openbao = openbao
        self._ciphertexts = ciphertexts

    def put(self, *, tenant_ref: object, object_ref: object, key_ref: object,
            plaintext: object, openbao_token: object) -> EncryptedObjectReference:
        try:
            # Keep the bearer token only in these active call frames.  In
            # particular, do not expose a token-bound store to a caller.
            store = EncryptedObjectStore(data_keys=_ScopedOpenBaoDataKeys(self._openbao, openbao_token),
                                         transport=_S3EnvelopeTransport(self._ciphertexts))
            return store.put(tenant_ref=tenant_ref, object_ref=object_ref, key_ref=key_ref,
                             plaintext=plaintext)
        except (WorkerEncryptedObjectsError, EncryptedObjectStoreError):
            raise
        except Exception:
            _fail()

    def get(self, *, tenant_ref: object, reference: object, openbao_token: object) -> bytes:
        try:
            # See ``put``: this temporary store cannot escape the operation.
            store = EncryptedObjectStore(data_keys=_ScopedOpenBaoDataKeys(self._openbao, openbao_token),
                                         transport=_S3EnvelopeTransport(self._ciphertexts))
            return store.get(tenant_ref=tenant_ref, reference=reference)
        except (WorkerEncryptedObjectsError, EncryptedObjectStoreError):
            raise
        except Exception:
            _fail()
