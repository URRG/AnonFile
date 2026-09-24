"""CI-only live TLS interoperability test for the M33 worker composition.

The corresponding script provisions disposable OpenBao and MinIO instances.
This is deliberately opt-in: it is not a production deployment test.
"""
from __future__ import annotations

import json
import os

import boto3
from botocore.config import Config
import pytest

from app.encrypted_object_store import EncryptedObjectStoreError
from app.openbao_datakey import OpenBaoDataKeyConfig, OpenBaoDataKeyError, OpenBaoTransitDataKey
from app.publication_payload_binding import PublicationPayloadBinding, payload_digest
from app.s3_ciphertext_transport import S3CiphertextTransport, S3CiphertextTransportConfig, opaque_object_key
from app.worker_encrypted_objects import WorkerEncryptedObjects, WorkerEncryptedObjectsError


pytestmark = pytest.mark.skipif(
    os.environ.get("M36_LIVE_OBJECT_PATH") != "1",
    reason="requires disposable TLS OpenBao and S3-compatible integration servers",
)

TENANT = "tenantref:v1:" + "M" * 43
OTHER_TENANT = "tenantref:v1:" + "N" * 43
OBJECT = "objectref:v1:" + "W" * 43
PUBLICATION = "publicationref:v1:" + "P" * 43
KEY_REF = "keyref:v1:m36-worker-envelope"
BUCKET = "m36-worker-objects-ci"
MARKER = b"m36 synthetic private customer record marker"
PLAN = "sha256:" + "a" * 64


def binding(payload: bytes, *, tenant: str = TENANT, object_ref: str = OBJECT,
            publication: str = PUBLICATION, key_ref: str = KEY_REF) -> PublicationPayloadBinding:
    return PublicationPayloadBinding.create(tenant_ref=tenant, object_ref=object_ref, publication_ref=publication,
                                            key_ref=key_ref, plan_digest=PLAN, payload_digest=payload_digest(payload),
                                            payload_size_bytes=len(payload), serialization_id="binary-v1")


def _environment(*names: str) -> dict[str, str]:
    return {name: os.environ[name] for name in names}


def _s3_client(values: dict[str, str]):
    return boto3.client(
        "s3",
        endpoint_url=values["M36_S3_ENDPOINT"],
        aws_access_key_id=values["M36_S3_ACCESS_KEY"],
        aws_secret_access_key=values["M36_S3_SECRET_KEY"],
        verify=values["M36_S3_CA_FILE"],
        region_name="us-east-1",
        config=Config(signature_version="s3v4", retries={"max_attempts": 0},
                      s3={"addressing_style": "path"}),
    )


def test_worker_object_path_against_live_openbao_and_s3():
    values = _environment(
        "M36_OPENBAO_ENDPOINT", "M36_OPENBAO_CA_FILE", "M36_OPENBAO_TOKEN",
        "M36_OPENBAO_NO_DECRYPT_TOKEN", "M36_OPENBAO_KEY_VERSION", "M36_S3_ENDPOINT",
        "M36_S3_CA_FILE", "M36_S3_ACCESS_KEY", "M36_S3_SECRET_KEY",
    )
    version = int(values["M36_OPENBAO_KEY_VERSION"])
    data_keys = OpenBaoTransitDataKey(OpenBaoDataKeyConfig(
        values["M36_OPENBAO_ENDPOINT"], "transit", "m36-worker-envelope", KEY_REF, version,
    ))
    client = _s3_client(values)
    client.create_bucket(Bucket=BUCKET)
    ciphertexts = S3CiphertextTransport(
        S3CiphertextTransportConfig(values["M36_S3_ENDPOINT"], BUCKET), client,
    )
    worker = WorkerEncryptedObjects(openbao=data_keys, ciphertexts=ciphertexts)
    bound = binding(MARKER)

    reference = worker.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY_REF,
                           binding=bound, plaintext=MARKER, openbao_token=values["M36_OPENBAO_TOKEN"])
    assert worker.get(tenant_ref=TENANT, reference=reference,
                      binding=bound, openbao_token=values["M36_OPENBAO_TOKEN"]) == MARKER

    # A restarted worker can recover the exact object only through the same
    # publication-bound S3 marker and M31/OpenBao authentication path.  This
    # is deliberately real TLS OpenBao + MinIO coverage, not a transport fake.
    restarted = WorkerEncryptedObjects(openbao=data_keys, ciphertexts=ciphertexts)
    recovered_reference = restarted.recover(
        tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
        key_ref=KEY_REF, binding=bound, openbao_token=values["M36_OPENBAO_TOKEN"],
    )
    assert recovered_reference == reference
    assert restarted.get(tenant_ref=TENANT, reference=recovered_reference,
                         binding=bound, openbao_token=values["M36_OPENBAO_TOKEN"]) == MARKER
    assert restarted.put_or_recover(
        tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
        key_ref=KEY_REF, binding=bound, plaintext=MARKER, openbao_token=values["M36_OPENBAO_TOKEN"],
    ) == reference
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        restarted.put_or_recover(
            tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
            key_ref=KEY_REF, binding=binding(b"m41 altered retry plaintext"), plaintext=b"m41 altered retry plaintext",
            openbao_token=values["M36_OPENBAO_TOKEN"],
        )
    wrong_publication = "publicationref:v1:" + "Q" * 43
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        restarted.recover(
            tenant_ref=TENANT, object_ref=OBJECT, publication_ref=wrong_publication,
            key_ref=KEY_REF, binding=binding(MARKER, publication=wrong_publication), openbao_token=values["M36_OPENBAO_TOKEN"],
        )
    assert restarted.get(tenant_ref=TENANT, reference=reference,
                         binding=bound, openbao_token=values["M36_OPENBAO_TOKEN"]) == MARKER

    # Read through privileged test infrastructure only.  The real S3 body is
    # a canonical encrypted envelope, never the marker supplied to the worker.
    key = opaque_object_key(ciphertexts._config, TENANT, OBJECT)
    raw_response = client.get_object(Bucket=BUCKET, Key=key)
    try:
        stored_envelope = raw_response["Body"].read()
    finally:
        raw_response["Body"].close()
    assert MARKER not in stored_envelope
    assert json.loads(stored_envelope)["version"] == 3

    # A reference cannot be used to cross a tenant boundary, and a second
    # create-only put cannot replace the established encrypted object.
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        worker.get(tenant_ref=OTHER_TENANT, reference=reference,
                   binding=bound, openbao_token=values["M36_OPENBAO_TOKEN"])
    before_wrong_payload = client.list_objects_v2(Bucket=BUCKET).get("KeyCount", 0)
    equal_size_wrong_payload = MARKER[:-1] + (b"!" if MARKER[-1:] != b"!" else b"?")
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        worker.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY_REF,
                   binding=bound, plaintext=equal_size_wrong_payload, openbao_token=values["M36_OPENBAO_TOKEN"])
    assert client.list_objects_v2(Bucket=BUCKET).get("KeyCount", 0) == before_wrong_payload
    assert worker.get(tenant_ref=TENANT, reference=reference,
                      binding=bound, openbao_token=values["M36_OPENBAO_TOKEN"]) == MARKER

    envelope = json.loads(stored_envelope)
    # Transit must bind its wrapped key to the M31 AAD.  A valid short-lived
    # token cannot unwrap it under another context.
    with pytest.raises(OpenBaoDataKeyError, match="^data-key unwrap unavailable$"):
        data_keys.unwrap(key_ref=KEY_REF, wrapped_key=envelope["wrapped_key"],
                         context=b"m36-wrong-associated-data", token=values["M36_OPENBAO_TOKEN"])
    # A separate exact policy token has metadata read but no decrypt capability.
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        worker.get(tenant_ref=TENANT, reference=reference,
                   binding=bound, openbao_token=values["M36_OPENBAO_NO_DECRYPT_TOKEN"])

    # Simulate a privileged out-of-band corruption.  M32's hash check must
    # reject it before the envelope can be decrypted.
    client.put_object(Bucket=BUCKET, Key=key, Body=b"m36-corrupted-envelope",
                      ContentLength=len(b"m36-corrupted-envelope"),
                      ContentType="application/octet-stream",
                      Metadata={"anonflow-publication-ref": PUBLICATION,
                                "anonflow-sha256": reference.ciphertext_digest.removeprefix("sha256:")},
                      ACL="private")
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        worker.get(tenant_ref=TENANT, reference=reference,
                   binding=bound, openbao_token=values["M36_OPENBAO_TOKEN"])
