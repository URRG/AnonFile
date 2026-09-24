"""A deliberately small, ciphertext-only S3-compatible object boundary.

The injected SDK client is configured by the deployment with one endpoint,
credential and bucket.  Callers cannot supply paths, endpoints, buckets,
metadata, ACLs, or conditional-write options.  This module does not encrypt,
decrypt, unwrap, or otherwise handle plaintext or cryptographic keys.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import re
from typing import Any, Mapping, Protocol
from urllib.parse import urlsplit, urlunsplit


_NAMESPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_TENANT_REF = re.compile(r"tenantref:v1:[A-Za-z0-9_-]{43}\Z")
_OBJECT_REF = re.compile(r"objectref:v1:[A-Za-z0-9_-]{43}\Z")
_PUBLICATION_REF = re.compile(r"publicationref:v1:[A-Za-z0-9_-]{43}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MAX_RESPONSE_KEYS = 16


class CiphertextTransportError(RuntimeError):
    """A fixed failure which intentionally carries no service response."""


class ObjectAlreadyExistsError(CiphertextTransportError):
    """The create-only request met an existing or racing object."""


class _S3Client(Protocol):
    def put_object(self, **kwargs: Any) -> Mapping[str, Any]: ...
    def get_object(self, **kwargs: Any) -> Mapping[str, Any]: ...


@dataclass(frozen=True)
class S3CiphertextTransportConfig:
    """Deployment-owned S3 endpoint and storage namespace configuration."""

    endpoint_url: str
    bucket: str
    key_namespace: str = "anonflow-ciphertext-v1"
    max_ciphertext_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.endpoint_url) if type(self.endpoint_url) is str else None
            port = parsed.port if parsed is not None else None
        except ValueError:
            parsed, port = None, None
        endpoint_ok = (parsed is not None and parsed.scheme == "https" and bool(parsed.hostname)
                       and parsed.username is None and parsed.password is None
                       and not parsed.query and not parsed.fragment and parsed.path in ("", "/")
                       and (port is None or 1 <= port <= 65535))
        valid = (endpoint_ok and _valid_bucket(self.bucket) and type(self.key_namespace) is str
                 and bool(_NAMESPACE.fullmatch(self.key_namespace))
                 and type(self.max_ciphertext_bytes) is int and not isinstance(self.max_ciphertext_bytes, bool)
                 and 1 <= self.max_ciphertext_bytes <= 64 * 1024 * 1024)
        if not valid:
            raise ValueError("invalid S3 ciphertext transport configuration")
        object.__setattr__(self, "endpoint_url", _normalized_endpoint(self.endpoint_url))


def _valid_bucket(value: object) -> bool:
    # The portable intersection for DNS-compatible S3 bucket names.  A fixed
    # bucket also prevents an object caller from selecting a destination.
    if type(value) is not str or not 3 <= len(value) <= 63:
        return False
    return bool(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value)) and ".." not in value


def opaque_object_key(config: S3CiphertextTransportConfig, tenant_id: str, object_id: str) -> str:
    """Derive the only permitted key; user identifiers never become paths."""
    if not _valid_scope(tenant_id, object_id):
        raise ValueError("invalid ciphertext object scope")
    tenant_digest = hashlib.sha256(tenant_id.encode("ascii")).hexdigest()
    object_digest = hashlib.sha256(object_id.encode("ascii")).hexdigest()
    return f"{config.key_namespace}/{tenant_digest}/{object_digest}"


def _valid_scope(tenant_id: object, object_id: object) -> bool:
    return (type(tenant_id) is str and bool(_TENANT_REF.fullmatch(tenant_id))
            and type(object_id) is str and bool(_OBJECT_REF.fullmatch(object_id)))


def _normalized_endpoint(value: str) -> str:
    parsed = urlsplit(value)
    return urlunsplit(("https", parsed.netloc, "", "", ""))


@dataclass(frozen=True)
class StoredCiphertext:
    """Opaque location and independently verified ciphertext digest."""

    key: str
    sha256: str
    byte_count: int
    publication_ref: str


@dataclass(frozen=True)
class FetchedCiphertext:
    """Verified ciphertext returned from the fixed opaque location."""

    key: str
    sha256: str
    ciphertext: bytes
    publication_ref: str


class S3CiphertextTransport:
    """Create ciphertext exactly once using the S3 conditional-write primitive."""

    def __init__(self, config: S3CiphertextTransportConfig, client: _S3Client) -> None:
        endpoint = getattr(getattr(client, "meta", None), "endpoint_url", None)
        if (not callable(getattr(client, "put_object", None)) or not callable(getattr(client, "get_object", None))
                or type(endpoint) is not str or _normalized_client_endpoint(endpoint) != config.endpoint_url):
            raise ValueError("invalid S3 client")
        self._config = config
        self._client = client

    def store(self, *, tenant_id: str, object_id: str, publication_ref: str, ciphertext: bytes,
              ciphertext_sha256: str) -> StoredCiphertext:
        """Store bounded ciphertext with ``IfNoneMatch='*'`` and no fallback.

        The supplied digest is checked against the exact bytes here.  ETags
        are intentionally ignored: S3 does not define them as content hashes
        for all uploads (notably multipart and encrypted uploads).
        """
        if type(ciphertext) is not bytes or not 0 < len(ciphertext) <= self._config.max_ciphertext_bytes:
            raise ValueError("invalid ciphertext")
        if type(ciphertext_sha256) is not str or not _SHA256.fullmatch(ciphertext_sha256):
            raise ValueError("invalid ciphertext digest")
        calculated = hashlib.sha256(ciphertext).hexdigest()
        if calculated != ciphertext_sha256:
            raise ValueError("ciphertext digest mismatch")
        key = opaque_object_key(self._config, tenant_id, object_id)
        if type(publication_ref) is not str or not _PUBLICATION_REF.fullmatch(publication_ref):
            raise ValueError("invalid publication reference")
        try:
            response = self._client.put_object(
                Bucket=self._config.bucket,
                Key=key,
                Body=ciphertext,
                ContentLength=len(ciphertext),
                ContentType="application/octet-stream",
                Metadata={"anonflow-publication-ref": publication_ref, "anonflow-sha256": ciphertext_sha256},
                ACL="private",
                IfNoneMatch="*",
            )
        except Exception as exc:
            if _is_conditional_conflict(exc):
                raise ObjectAlreadyExistsError("ciphertext object already exists") from None
            raise CiphertextTransportError("ciphertext storage unavailable") from None
        if not _valid_put_response(response):
            raise CiphertextTransportError("ciphertext storage unavailable")
        return StoredCiphertext(key=key, sha256=ciphertext_sha256, byte_count=len(ciphertext), publication_ref=publication_ref)

    def load(self, *, tenant_id: str, object_id: str, publication_ref: str, ciphertext_sha256: str) -> FetchedCiphertext:
        """Read and verify only a bounded ciphertext object at its derived key."""
        if type(ciphertext_sha256) is not str or not _SHA256.fullmatch(ciphertext_sha256):
            raise ValueError("invalid ciphertext digest")
        key = opaque_object_key(self._config, tenant_id, object_id)
        if type(publication_ref) is not str or not _PUBLICATION_REF.fullmatch(publication_ref):
            raise ValueError("invalid publication reference")
        try:
            response = self._client.get_object(Bucket=self._config.bucket, Key=key)
        except Exception:
            raise CiphertextTransportError("ciphertext storage unavailable") from None
        if not _valid_get_response(response, ciphertext_sha256, publication_ref, self._config.max_ciphertext_bytes):
            _close_body(response)
            raise CiphertextTransportError("ciphertext storage unavailable")
        body = response["Body"]
        try:
            value = body.read(self._config.max_ciphertext_bytes + 1)
        except Exception:
            raise CiphertextTransportError("ciphertext storage unavailable") from None
        finally:
            _close_body(response)
        if type(value) is not bytes or len(value) != response["ContentLength"] or len(value) > self._config.max_ciphertext_bytes:
            raise CiphertextTransportError("ciphertext storage unavailable")
        if hashlib.sha256(value).hexdigest() != ciphertext_sha256:
            raise CiphertextTransportError("ciphertext integrity check failed")
        return FetchedCiphertext(key=key, sha256=ciphertext_sha256, ciphertext=value, publication_ref=publication_ref)

    def recover(self, *, tenant_id: str, object_id: str, publication_ref: str) -> FetchedCiphertext:
        """Read a pre-existing object only when its exact publication marker proves ownership."""
        if type(publication_ref) is not str or not _PUBLICATION_REF.fullmatch(publication_ref):
            raise ValueError("invalid publication reference")
        key = opaque_object_key(self._config, tenant_id, object_id)
        try:
            response = self._client.get_object(Bucket=self._config.bucket, Key=key)
        except Exception:
            raise CiphertextTransportError("ciphertext storage unavailable") from None
        if not _valid_recovery_response(response, publication_ref, self._config.max_ciphertext_bytes):
            _close_body(response)
            raise CiphertextTransportError("ciphertext storage unavailable")
        assert isinstance(response, Mapping)
        body = response["Body"]
        digest = response["Metadata"]["anonflow-sha256"]
        try:
            value = body.read(self._config.max_ciphertext_bytes + 1)
        except Exception:
            raise CiphertextTransportError("ciphertext storage unavailable") from None
        finally:
            _close_body(response)
        if (type(value) is not bytes or len(value) != response["ContentLength"]
                or len(value) > self._config.max_ciphertext_bytes
                or hashlib.sha256(value).hexdigest() != digest):
            raise CiphertextTransportError("ciphertext integrity check failed")
        return FetchedCiphertext(key=key, sha256=digest, ciphertext=value, publication_ref=publication_ref)


def _is_conditional_conflict(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, Mapping):
        return False
    metadata = response.get("ResponseMetadata")
    error = response.get("Error")
    status = metadata.get("HTTPStatusCode") if isinstance(metadata, Mapping) else None
    code = error.get("Code") if isinstance(error, Mapping) else None
    return status in (409, 412) or code in {"ConditionalRequestConflict", "PreconditionFailed"}


def _valid_put_response(response: object) -> bool:
    """Accept only a small normal botocore success envelope, never an ETag."""
    if not isinstance(response, Mapping) or len(response) > _MAX_RESPONSE_KEYS:
        return False
    metadata = response.get("ResponseMetadata")
    if not isinstance(metadata, Mapping) or metadata.get("HTTPStatusCode") != 200:
        return False
    # Bound attacker-controlled SDK fields.  No value is used as an integrity
    # assertion; the caller's SHA-256 was verified before the request.
    for key, value in response.items():
        if type(key) is not str or len(key) > 64:
            return False
        if isinstance(value, str) and len(value) > 1024:
            return False
        if isinstance(value, Mapping) and (len(value) > _MAX_RESPONSE_KEYS or any(
                type(k) is not str or len(k) > 64 or (isinstance(v, str) and len(v) > 1024)
                for k, v in value.items())):
            return False
    return True


def _normalized_client_endpoint(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment
            or parsed.path not in ("", "/") or (port is not None and not 1 <= port <= 65535)):
        return None
    return urlunsplit(("https", parsed.netloc, "", "", ""))


def _valid_get_response(response: object, expected_digest: str, expected_publication: str, maximum: int) -> bool:
    if not _valid_response_shape(response, expected_status=200):
        return False
    assert isinstance(response, Mapping)
    content_length = response.get("ContentLength")
    metadata = response.get("Metadata")
    body = response.get("Body")
    return (type(content_length) is int and 0 <= content_length <= maximum
            and isinstance(metadata, Mapping) and metadata == {"anonflow-publication-ref": expected_publication,
                                                                 "anonflow-sha256": expected_digest}
            and callable(getattr(body, "read", None)) and callable(getattr(body, "close", None)))


def _valid_recovery_response(response: object, expected_publication: str, maximum: int) -> bool:
    if not _valid_response_shape(response, expected_status=200):
        return False
    assert isinstance(response, Mapping)
    content_length, metadata, body = response.get("ContentLength"), response.get("Metadata"), response.get("Body")
    digest = metadata.get("anonflow-sha256") if isinstance(metadata, Mapping) else None
    return (type(content_length) is int and 0 <= content_length <= maximum
            and isinstance(metadata, Mapping) and metadata == {"anonflow-publication-ref": expected_publication,
                                                                "anonflow-sha256": digest}
            and type(digest) is str and bool(_SHA256.fullmatch(digest))
            and callable(getattr(body, "read", None)) and callable(getattr(body, "close", None)))


def _valid_response_shape(response: object, *, expected_status: int) -> bool:
    if not isinstance(response, Mapping) or len(response) > _MAX_RESPONSE_KEYS:
        return False
    metadata = response.get("ResponseMetadata")
    if not isinstance(metadata, Mapping) or metadata.get("HTTPStatusCode") != expected_status:
        return False
    # A partial status can never be a full ciphertext object.
    if metadata.get("HTTPStatusCode") == 206:
        return False
    for key, value in response.items():
        if type(key) is not str or len(key) > 64:
            return False
        if isinstance(value, str) and len(value) > 1024:
            return False
        if isinstance(value, Mapping) and (len(value) > _MAX_RESPONSE_KEYS or any(
                type(k) is not str or len(k) > 64 or (isinstance(v, str) and len(v) > 1024)
                for k, v in value.items())):
            return False
    return True


def _close_body(response: object) -> None:
    if isinstance(response, Mapping):
        body = response.get("Body")
        close = getattr(body, "close", None)
        if callable(close):
            try:
                close()
            except Exception:
                pass
