"""Deployment-owned construction for the ciphertext-only S3 client.

This module deliberately accepts endpoint and credential configuration only at
process construction, never from request data.  The explicit credentials are
passed to a new boto3 Session, so the SDK credential-provider chain is never
selected by this boundary.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
import re
from pathlib import Path
from typing import Any, Callable

from app.s3_ciphertext_transport import S3CiphertextTransport, S3CiphertextTransportConfig


_REGION = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_ACCESS_KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}\Z")
_SECRET = re.compile(r"[^\s\x00]{8,256}\Z")
_CONNECT_TIMEOUT_SECONDS = 3
_READ_TIMEOUT_SECONDS = 10
_TOTAL_ATTEMPTS = 2


class S3ClientFactoryError(RuntimeError):
    """Fixed construction failure which does not expose endpoint or secrets."""


@dataclass(frozen=True, repr=False)
class S3StaticCredentials:
    """An explicit deployment-injected access key pair.

    Rotation and issuance are outside this module.  Both values are redacted
    from ``repr`` and must never be logged by callers.
    """

    access_key_id: str
    secret_access_key: str

    def __post_init__(self) -> None:
        if (type(self.access_key_id) is not str or not _ACCESS_KEY.fullmatch(self.access_key_id)
                or type(self.secret_access_key) is not str or not _SECRET.fullmatch(self.secret_access_key)):
            raise ValueError("invalid S3 client credentials")

    def __repr__(self) -> str:
        return "S3StaticCredentials(<redacted>)"


@dataclass(frozen=True, repr=False)
class S3ClientFactoryConfig:
    """Fixed settings for one private, self-hosted S3-compatible endpoint."""

    endpoint_url: str
    bucket: str
    region_name: str
    ca_bundle: str
    credentials: S3StaticCredentials
    key_namespace: str = "anonflow-ciphertext-v1"
    max_ciphertext_bytes: int = 64 * 1024 * 1024

    def __post_init__(self) -> None:
        try:
            transport = S3CiphertextTransportConfig(
                endpoint_url=self.endpoint_url,
                bucket=self.bucket,
                key_namespace=self.key_namespace,
                max_ciphertext_bytes=self.max_ciphertext_bytes,
            )
        except (TypeError, ValueError):
            raise ValueError("invalid S3 client factory configuration") from None
        valid = (type(self.region_name) is str and bool(_REGION.fullmatch(self.region_name))
                 and type(self.ca_bundle) is str and bool(self.ca_bundle)
                 and "\x00" not in self.ca_bundle and os.path.isabs(self.ca_bundle)
                 and type(self.credentials) is S3StaticCredentials)
        if not valid:
            raise ValueError("invalid S3 client factory configuration")
        # Use the M32-normalized form everywhere, including the SDK call and
        # the transport's endpoint identity comparison.
        object.__setattr__(self, "endpoint_url", transport.endpoint_url)

    def transport_config(self) -> S3CiphertextTransportConfig:
        """Return an independently validated M32 configuration."""
        return S3CiphertextTransportConfig(
            endpoint_url=self.endpoint_url,
            bucket=self.bucket,
            key_namespace=self.key_namespace,
            max_ciphertext_bytes=self.max_ciphertext_bytes,
        )

    def __repr__(self) -> str:
        return "S3ClientFactoryConfig(<redacted>)"


def _dependencies() -> tuple[Callable[..., Any], Callable[..., Any]]:
    """Load optional SDK dependencies only when this deployment feature is used."""
    from boto3.session import Session
    from botocore.config import Config
    return Session, Config


def build_s3_ciphertext_transport(config: S3ClientFactoryConfig) -> S3CiphertextTransport:
    """Build the sole client used by M32, or fail closed.

    ``verify`` always names a deployment-owned CA bundle; ``False`` and the
    platform default trust store are never selectable through this API.  The
    explicit Session credentials suppress boto3's ambient provider chain.
    Path-style addressing keeps a self-hosted endpoint fixed rather than
    deriving request-controlled bucket hostnames.
    """
    if type(config) is not S3ClientFactoryConfig:
        raise S3ClientFactoryError("S3 client construction unavailable")
    try:
        if not Path(config.ca_bundle).is_file():
            raise ValueError
        Session, Config = _dependencies()
        session = Session(
            aws_access_key_id=config.credentials.access_key_id,
            aws_secret_access_key=config.credentials.secret_access_key,
        )
        client = session.client(
            "s3",
            region_name=config.region_name,
            endpoint_url=config.endpoint_url,
            verify=config.ca_bundle,
            config=Config(
                signature_version="s3v4",
                connect_timeout=_CONNECT_TIMEOUT_SECONDS,
                read_timeout=_READ_TIMEOUT_SECONDS,
                retries={"mode": "standard", "total_max_attempts": _TOTAL_ATTEMPTS},
                s3={"addressing_style": "path"},
            ),
        )
        return S3CiphertextTransport(config.transport_config(), client)
    except Exception:
        raise S3ClientFactoryError("S3 client construction unavailable") from None
