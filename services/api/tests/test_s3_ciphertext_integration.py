"""Opt-in interoperability check for the M32 S3 ciphertext boundary.

The workflow starts one exact, disposable MinIO configuration over verified
TLS.  It tests that configuration only; it is not a provider certification.
"""
from __future__ import annotations

import hashlib
import os
from concurrent.futures import ThreadPoolExecutor

import boto3
from botocore.config import Config
import pytest

from app.s3_ciphertext_transport import (
    CiphertextTransportError,
    ObjectAlreadyExistsError,
    S3CiphertextTransport,
    S3CiphertextTransportConfig,
)


pytestmark = pytest.mark.skipif(
    os.environ.get("S3_CIPHERTEXT_INTEGRATION") != "1",
    reason="requires the disposable TLS S3 integration server",
)

TENANT = "tenantref:v1:" + "A" * 43
OTHER_TENANT = "tenantref:v1:" + "C" * 43
OBJECT = "objectref:v1:" + "B" * 43
OTHER_OBJECT = "objectref:v1:" + "D" * 43
RACING_OBJECT = "objectref:v1:" + "E" * 43
BUCKET = "m34-ciphertext-ci"


def _client():
    required = {
        name: os.environ[name]
        for name in (
            "S3_CIPHERTEXT_INTEGRATION_ENDPOINT",
            "S3_CIPHERTEXT_INTEGRATION_CA_FILE",
            "S3_CIPHERTEXT_INTEGRATION_ACCESS_KEY",
            "S3_CIPHERTEXT_INTEGRATION_SECRET_KEY",
        )
    }
    return boto3.client(
        "s3",
        endpoint_url=required["S3_CIPHERTEXT_INTEGRATION_ENDPOINT"],
        aws_access_key_id=required["S3_CIPHERTEXT_INTEGRATION_ACCESS_KEY"],
        aws_secret_access_key=required["S3_CIPHERTEXT_INTEGRATION_SECRET_KEY"],
        verify=required["S3_CIPHERTEXT_INTEGRATION_CA_FILE"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", retries={"max_attempts": 0}, s3={"addressing_style": "path"}),
    )


def _transport(client):
    return S3CiphertextTransport(
        S3CiphertextTransportConfig(endpoint_url=os.environ["S3_CIPHERTEXT_INTEGRATION_ENDPOINT"], bucket=BUCKET),
        client,
    )


def test_s3_ciphertext_transport_against_pinned_server():
    client = _client()
    client.create_bucket(Bucket=BUCKET)
    transport = _transport(client)
    ciphertext = b"m34-ci-ciphertext-one"
    digest = hashlib.sha256(ciphertext).hexdigest()

    stored = transport.store(tenant_id=TENANT, object_id=OBJECT, ciphertext=ciphertext, ciphertext_sha256=digest)
    assert transport.load(tenant_id=TENANT, object_id=OBJECT, ciphertext_sha256=digest).ciphertext == ciphertext

    # A repeat must be rejected and must leave the first exact bytes intact.
    with pytest.raises(ObjectAlreadyExistsError):
        transport.store(tenant_id=TENANT, object_id=OBJECT, ciphertext=b"replacement", ciphertext_sha256=hashlib.sha256(b"replacement").hexdigest())
    assert transport.load(tenant_id=TENANT, object_id=OBJECT, ciphertext_sha256=digest).ciphertext == ciphertext

    # Concurrent create-only calls against an absent derived key admit exactly one.
    race_bytes = b"m34-ci-racing-ciphertext"
    race_digest = hashlib.sha256(race_bytes).hexdigest()

    def create_once():
        try:
            _transport(_client()).store(tenant_id=TENANT, object_id=RACING_OBJECT, ciphertext=race_bytes, ciphertext_sha256=race_digest)
            return "stored"
        except ObjectAlreadyExistsError:
            return "exists"

    with ThreadPoolExecutor(max_workers=8) as executor:
        outcomes = list(executor.map(lambda _: create_once(), range(8)))
    assert outcomes.count("stored") == 1
    assert outcomes.count("exists") == 7
    assert transport.load(tenant_id=TENANT, object_id=RACING_OBJECT, ciphertext_sha256=race_digest).ciphertext == race_bytes

    # Different valid scopes derive different locations; they cannot read ours.
    with pytest.raises(CiphertextTransportError):
        transport.load(tenant_id=OTHER_TENANT, object_id=OBJECT, ciphertext_sha256=digest)
    with pytest.raises(CiphertextTransportError):
        transport.load(tenant_id=TENANT, object_id=OTHER_OBJECT, ciphertext_sha256=digest)

    # Simulate an out-of-band overwrite by privileged infrastructure.  The
    # application must reject altered bytes even if metadata is left unchanged.
    altered = b"m34-ci-tampered-ciphertext"
    client.put_object(
        Bucket=BUCKET,
        Key=stored.key,
        Body=altered,
        ContentLength=len(altered),
        ContentType="application/octet-stream",
        Metadata={"anonflow-sha256": digest},
        ACL="private",
    )
    with pytest.raises(CiphertextTransportError, match="integrity check failed"):
        transport.load(tenant_id=TENANT, object_id=OBJECT, ciphertext_sha256=digest)
