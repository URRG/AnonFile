"""CI-only proof of M46 version-pinned reads against the pinned MinIO server.

This is a version-identity check only.  It does not enable or assert Object
Lock, retention, or WORM behavior.
"""
from __future__ import annotations

import hashlib
import os

import boto3
from botocore.config import Config
import pytest

from app.s3_versioned_ciphertext_transport import (
    S3VersionedCiphertextTransport, S3VersionedCiphertextTransportConfig,
)


pytestmark = pytest.mark.skipif(
    os.environ.get("S3_CIPHERTEXT_INTEGRATION") != "1",
    reason="requires the disposable TLS S3-compatible integration server",
)

TENANT = "tenantref:v1:" + "V" * 43
OBJECT = "objectref:v1:" + "W" * 43
PUBLICATION = "publicationref:v1:" + "P" * 43
BUCKET = "m46-versioned-ciphertext-ci"


def _environment(*names: str) -> dict[str, str]:
    return {name: os.environ[name] for name in names}


def _client(values: dict[str, str]):
    return boto3.client(
        "s3", endpoint_url=values["S3_CIPHERTEXT_INTEGRATION_ENDPOINT"],
        aws_access_key_id=values["S3_CIPHERTEXT_INTEGRATION_ACCESS_KEY"],
        aws_secret_access_key=values["S3_CIPHERTEXT_INTEGRATION_SECRET_KEY"],
        verify=values["S3_CIPHERTEXT_INTEGRATION_CA_FILE"], region_name="us-east-1",
        config=Config(signature_version="s3v4", retries={"max_attempts": 0},
                      s3={"addressing_style": "path"}),
    )


def test_versioned_s3_adapter_reads_the_exact_original_provider_version():
    values = _environment("S3_CIPHERTEXT_INTEGRATION_ENDPOINT", "S3_CIPHERTEXT_INTEGRATION_CA_FILE",
                          "S3_CIPHERTEXT_INTEGRATION_ACCESS_KEY", "S3_CIPHERTEXT_INTEGRATION_SECRET_KEY")
    client = _client(values)
    client.create_bucket(Bucket=BUCKET)
    client.put_bucket_versioning(Bucket=BUCKET, VersioningConfiguration={"Status": "Enabled"})
    transport = S3VersionedCiphertextTransport(S3VersionedCiphertextTransportConfig(
        values["S3_CIPHERTEXT_INTEGRATION_ENDPOINT"], BUCKET, "s3-versioned-v1:ci-minio"), client)
    first = b"m46-original-version"
    digest = hashlib.sha256(first).hexdigest()
    stored = transport.store(tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION,
                             ciphertext=first, ciphertext_sha256=digest)
    assert stored.provider_version_id not in ("", "null")
    assert stored.profile_id == "s3-versioned-v1:ci-minio"

    # A privileged later write receives a new current version.  M46 does not
    # say that write is forbidden; it proves the returned original ID remains
    # addressable and the adapter does not silently read the current version.
    client.put_object(Bucket=BUCKET, Key=stored.key, Body=b"m46-later-version",
                      ContentLength=len(b"m46-later-version"), ContentType="application/octet-stream",
                      Metadata={"anonflow-publication-ref": PUBLICATION,
                                "anonflow-sha256": hashlib.sha256(b"m46-later-version").hexdigest()},
                      ACL="private")
    fetched = transport.load(tenant_id=TENANT, object_id=OBJECT, identity=stored)
    assert fetched.ciphertext == first
    assert fetched.provider_version_id == stored.provider_version_id
    assert fetched.profile_id == stored.profile_id
