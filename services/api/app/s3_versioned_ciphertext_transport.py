"""Version-pinned sibling of the bounded M32 ciphertext transport.

This adapter is intentionally separate from M32.  It requires a provider
``VersionId`` for every successful write and uses that exact opaque identifier
for every later read or recovery.  A provider version identifier is an object
identity, *not* a claim that the version is immutable, retained, or protected
by Object Lock.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import re
from typing import Any, Mapping, Protocol

from app.s3_ciphertext_transport import (CiphertextTransportError, ObjectAlreadyExistsError,
                                         S3CiphertextTransport, S3CiphertextTransportConfig,
                                         opaque_object_key)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PUBLICATION = re.compile(r"publicationref:v1:[A-Za-z0-9_-]{43}\Z")
_VERSION_ID = re.compile(r"[!-~]{1,1024}\Z")
_PROFILE_ID = re.compile(r"s3-versioned-v1:[a-z0-9][a-z0-9._-]{0,63}\Z")
_OBJECT_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}/[0-9a-f]{64}/[0-9a-f]{64}\Z")
_MAX_RESPONSE_KEYS = 20


class VersionedCiphertextTransportError(CiphertextTransportError):
    """Fixed failure for a missing, malformed, or mismatched object version."""


class _S3VersionedClient(Protocol):
    def put_object(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def get_object(self, **kwargs: Any) -> Mapping[str, Any]: ...


def _version_id(value: object) -> str:
    if type(value) is not str or value == "null" or not _VERSION_ID.fullmatch(value):
        raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable")
    return value


def _response_shape(response: object) -> Mapping[str, Any] | None:
    if not isinstance(response, Mapping) or len(response) > _MAX_RESPONSE_KEYS:
        return None
    metadata = response.get("ResponseMetadata")
    if not isinstance(metadata, Mapping) or metadata.get("HTTPStatusCode") != 200:
        return None
    for key, value in response.items():
        if type(key) is not str or len(key) > 64:
            return None
        if isinstance(value, str) and len(value) > 1024:
            return None
        if isinstance(value, Mapping) and (len(value) > _MAX_RESPONSE_KEYS or any(
                type(nested_key) is not str or len(nested_key) > 64
                or (isinstance(nested_value, str) and len(nested_value) > 1024)
                for nested_key, nested_value in value.items())):
            return None
    return response


def _close_body(response: object) -> None:
    if isinstance(response, Mapping):
        close = getattr(response.get("Body"), "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass


def _conditional_conflict(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return False
    metadata, error = response.get("ResponseMetadata"), response.get("Error")
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    return status in (409, 412) or code in {"ConditionalRequestConflict", "PreconditionFailed"}


@dataclass(frozen=True, slots=True)
class S3VersionedCiphertextTransportConfig:
    """Fixed M32-compatible endpoint/bucket plus an explicit versioned profile."""

    endpoint_url: str
    bucket: str
    profile_id: str
    key_namespace: str = "anonflow-ciphertext-v1"
    max_ciphertext_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        try:
            base = S3CiphertextTransportConfig(self.endpoint_url, self.bucket, self.key_namespace,
                                               self.max_ciphertext_bytes)
        except ValueError:
            raise ValueError("invalid versioned S3 ciphertext transport configuration") from None
        if type(self.profile_id) is not str or not _PROFILE_ID.fullmatch(self.profile_id):
            raise ValueError("invalid versioned S3 ciphertext transport configuration")
        object.__setattr__(self, "endpoint_url", base.endpoint_url)

    def base_config(self) -> S3CiphertextTransportConfig:
        return S3CiphertextTransportConfig(self.endpoint_url, self.bucket, self.key_namespace,
                                           self.max_ciphertext_bytes)


@dataclass(frozen=True, slots=True)
class VersionedStoredCiphertext:
    """Ciphertext identity including the exact provider-returned version."""

    key: str
    sha256: str
    byte_count: int
    publication_ref: str
    profile_id: str
    provider_version_id: str

    def __post_init__(self) -> None:
        if (type(self.key) is not str or not _OBJECT_KEY.fullmatch(self.key) or type(self.sha256) is not str
                or not _SHA256.fullmatch(self.sha256) or type(self.byte_count) is not int
                or isinstance(self.byte_count, bool) or self.byte_count < 1
                or type(self.publication_ref) is not str or not _PUBLICATION.fullmatch(self.publication_ref)):
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable")
        if type(self.profile_id) is not str or not _PROFILE_ID.fullmatch(self.profile_id):
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable")
        _version_id(self.provider_version_id)


@dataclass(frozen=True, slots=True)
class VersionedFetchedCiphertext:
    """Verified ciphertext from one caller-pinned provider version."""

    key: str
    sha256: str
    ciphertext: bytes = field(repr=False)
    publication_ref: str
    profile_id: str
    provider_version_id: str

    def __post_init__(self) -> None:
        if (type(self.key) is not str or not _OBJECT_KEY.fullmatch(self.key) or type(self.sha256) is not str
                or not _SHA256.fullmatch(self.sha256) or type(self.ciphertext) is not bytes
                or type(self.publication_ref) is not str or not _PUBLICATION.fullmatch(self.publication_ref)):
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable")
        if type(self.profile_id) is not str or not _PROFILE_ID.fullmatch(self.profile_id):
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable")
        _version_id(self.provider_version_id)


class S3VersionedCiphertextTransport:
    """Create once, then read only a returned provider version identity."""

    def __init__(self, config: S3VersionedCiphertextTransportConfig, client: _S3VersionedClient) -> None:
        if type(config) is not S3VersionedCiphertextTransportConfig:
            raise ValueError("invalid versioned S3 client")
        # Reuse M32's exact TLS endpoint/client validation.  Do not accept a
        # client merely because a string with trailing slashes appears similar.
        try:
            S3CiphertextTransport(config.base_config(), client)
        except ValueError:
            raise ValueError("invalid versioned S3 client") from None
        self._config = config
        self._client = client

    def store(self, *, tenant_id: str, object_id: str, publication_ref: str,
              ciphertext: bytes, ciphertext_sha256: str) -> VersionedStoredCiphertext:
        if type(ciphertext) is not bytes or not 0 < len(ciphertext) <= self._config.max_ciphertext_bytes:
            raise ValueError("invalid ciphertext")
        if type(ciphertext_sha256) is not str or not _SHA256.fullmatch(ciphertext_sha256):
            raise ValueError("invalid ciphertext digest")
        if hashlib.sha256(ciphertext).hexdigest() != ciphertext_sha256:
            raise ValueError("ciphertext digest mismatch")
        if type(publication_ref) is not str or not _PUBLICATION.fullmatch(publication_ref):
            raise ValueError("invalid publication reference")
        key = opaque_object_key(self._config.base_config(), tenant_id, object_id)
        try:
            response = self._client.put_object(
                Bucket=self._config.bucket, Key=key, Body=ciphertext, ContentLength=len(ciphertext),
                ContentType="application/octet-stream",
                Metadata={"anonflow-publication-ref": publication_ref, "anonflow-sha256": ciphertext_sha256},
                ACL="private", IfNoneMatch="*",
            )
        except Exception as exc:
            if _conditional_conflict(exc):
                raise ObjectAlreadyExistsError("ciphertext object already exists") from None
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable") from None
        shaped = _response_shape(response)
        if shaped is None:
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable")
        try:
            version = _version_id(shaped.get("VersionId"))
        except VersionedCiphertextTransportError:
            raise
        return VersionedStoredCiphertext(key, ciphertext_sha256, len(ciphertext), publication_ref,
                                        self._config.profile_id, version)

    def load(self, *, tenant_id: str, object_id: str,
             identity: VersionedStoredCiphertext) -> VersionedFetchedCiphertext:
        """Read only a complete, server-owned stored-version identity."""
        return self._fetch(tenant_id=tenant_id, object_id=object_id, identity=identity)

    def recover(self, *, tenant_id: str, object_id: str,
                identity: VersionedStoredCiphertext) -> VersionedFetchedCiphertext:
        """Re-read a known version; this is not ambiguous-write recovery."""
        return self._fetch(tenant_id=tenant_id, object_id=object_id, identity=identity)

    def _fetch(self, *, tenant_id: str, object_id: str,
               identity: VersionedStoredCiphertext) -> VersionedFetchedCiphertext:
        if type(identity) is not VersionedStoredCiphertext:
            raise ValueError("invalid versioned ciphertext identity")
        key = opaque_object_key(self._config.base_config(), tenant_id, object_id)
        if identity.profile_id != self._config.profile_id or identity.key != key:
            raise ValueError("invalid versioned ciphertext identity")
        publication_ref, expected_digest, expected_size, version = (
            identity.publication_ref, identity.sha256, identity.byte_count,
            identity.provider_version_id,
        )
        try:
            response = self._client.get_object(Bucket=self._config.bucket, Key=key, VersionId=version)
        except Exception:
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable") from None
        shaped = _response_shape(response)
        if shaped is None:
            _close_body(response)
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable")
        try:
            response_version = _version_id(shaped.get("VersionId"))
            content_length, metadata, body = shaped.get("ContentLength"), shaped.get("Metadata"), shaped.get("Body")
            digest = metadata.get("anonflow-sha256") if isinstance(metadata, Mapping) else None
            valid = (response_version == version and type(content_length) is int
                     and 0 <= content_length <= self._config.max_ciphertext_bytes
                     and content_length == expected_size
                     and isinstance(metadata, Mapping)
                     and metadata == {"anonflow-publication-ref": publication_ref, "anonflow-sha256": digest}
                     and type(digest) is str and bool(_SHA256.fullmatch(digest))
                     and (expected_digest is None or digest == expected_digest)
                     and callable(getattr(body, "read", None)) and callable(getattr(body, "close", None)))
        except Exception:
            valid = False
        if not valid:
            _close_body(response)
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable")
        try:
            value = body.read(self._config.max_ciphertext_bytes + 1)
        except Exception:
            raise VersionedCiphertextTransportError("versioned ciphertext storage unavailable") from None
        finally:
            _close_body(response)
        if (type(value) is not bytes or len(value) != content_length
                or hashlib.sha256(value).hexdigest() != digest):
            raise VersionedCiphertextTransportError("versioned ciphertext integrity check failed")
        return VersionedFetchedCiphertext(key, digest, value, publication_ref,
                                         self._config.profile_id, version)
