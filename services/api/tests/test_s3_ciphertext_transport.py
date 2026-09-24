import hashlib

import pytest

from app.s3_ciphertext_transport import (CiphertextTransportError, ObjectAlreadyExistsError,
                                         S3CiphertextTransport, S3CiphertextTransportConfig,
                                         opaque_object_key)


class ConditionalError(Exception):
    def __init__(self, status):
        self.response = {"ResponseMetadata": {"HTTPStatusCode": status}, "Error": {"Code": "PreconditionFailed"}}


class FakeS3:
    def __init__(self, response=None, error=None, endpoint_url="https://objects.example"):
        self.response = response if response is not None else {"ETag": '"not-a-hash"', "ResponseMetadata": {"HTTPStatusCode": 200}}
        self.error = error
        self.calls = []
        self.meta = type("Meta", (), {"endpoint_url": endpoint_url})()

    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response

    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        return self.response


class StreamingBody:
    def __init__(self, value):
        self.value, self.read_amount, self.closed = value, None, False
    def read(self, amount):
        self.read_amount = amount
        return self.value
    def close(self):
        self.closed = True


def config(**changes):
    values = {"endpoint_url": "https://objects.example", "bucket": "anonflow-ciphertexts"}
    values.update(changes)
    return S3CiphertextTransportConfig(**values)


TENANT = "tenantref:v1:" + "T" * 43
OBJECT = "objectref:v1:" + "O" * 43
PUBLICATION = "publicationref:v1:" + "P" * 43


def test_create_only_upload_has_fixed_private_destination_and_ignores_etag():
    fake = FakeS3()
    ciphertext = b"already encrypted by another boundary"
    digest = hashlib.sha256(ciphertext).hexdigest()
    stored = S3CiphertextTransport(config(), fake).store(tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION, ciphertext=ciphertext, ciphertext_sha256=digest)
    call = fake.calls[0]
    assert stored.sha256 == digest and stored.byte_count == len(ciphertext)
    assert call == {"Bucket": "anonflow-ciphertexts", "Key": stored.key, "Body": ciphertext,
                    "ContentLength": len(ciphertext), "ContentType": "application/octet-stream",
                    "Metadata": {"anonflow-publication-ref": PUBLICATION, "anonflow-sha256": digest}, "ACL": "private", "IfNoneMatch": "*"}
    assert TENANT not in stored.key and OBJECT not in stored.key


def test_scope_derivation_is_exact_and_never_accepts_paths_or_wrong_scope():
    cfg = config()
    assert opaque_object_key(cfg, TENANT, OBJECT) != opaque_object_key(cfg, "tenantref:v1:" + "U" * 43, OBJECT)
    assert opaque_object_key(cfg, TENANT, OBJECT) != opaque_object_key(cfg, TENANT, "objectref:v1:" + "P" * 43)
    with pytest.raises(ValueError, match="scope"):
        opaque_object_key(cfg, "tenantref:v1:" + "T" * 42 + "/", OBJECT)
    with pytest.raises(ValueError, match="scope"):
        opaque_object_key(cfg, OBJECT, TENANT)


@pytest.mark.parametrize("status", [409, 412])
def test_conditional_conflicts_are_not_retried_or_replaced(status):
    ciphertext = b"ciphertext"
    fake = FakeS3(error=ConditionalError(status))
    with pytest.raises(ObjectAlreadyExistsError, match="already exists"):
        S3CiphertextTransport(config(), fake).store(tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION, ciphertext=ciphertext, ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest())
    assert len(fake.calls) == 1


@pytest.mark.parametrize("ciphertext,digest", [(b"", "0" * 64), (b"one", "0" * 64), ("not-bytes", "0" * 64)])
def test_invalid_or_mismatched_ciphertext_never_reaches_sdk(ciphertext, digest):
    fake = FakeS3()
    with pytest.raises(ValueError):
        S3CiphertextTransport(config(), fake).store(tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION, ciphertext=ciphertext, ciphertext_sha256=digest)
    assert not fake.calls


@pytest.mark.parametrize("response", [
    {}, {"ResponseMetadata": {"HTTPStatusCode": 201}},
    {"ResponseMetadata": {"HTTPStatusCode": 200}, **{f"x{i}": "a" for i in range(16)}},
    {"ResponseMetadata": {"HTTPStatusCode": 200}, "ETag": "x" * 1025},
])
def test_malformed_or_unbounded_responses_fail_closed(response):
    fake = FakeS3(response=response)
    ciphertext = b"ciphertext"
    with pytest.raises(CiphertextTransportError, match="unavailable"):
        S3CiphertextTransport(config(), fake).store(tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION, ciphertext=ciphertext, ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest())


def test_load_checks_declared_length_metadata_digest_and_closes_stream():
    ciphertext = b"encrypted payload"
    digest = hashlib.sha256(ciphertext).hexdigest()
    body = StreamingBody(ciphertext)
    fake = FakeS3(response={"ContentLength": len(ciphertext), "Metadata": {"anonflow-publication-ref": PUBLICATION, "anonflow-sha256": digest},
                            "Body": body, "ResponseMetadata": {"HTTPStatusCode": 200}})
    loaded = S3CiphertextTransport(config(), fake).load(tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION, ciphertext_sha256=digest)
    assert loaded.ciphertext == ciphertext and body.closed
    assert body.read_amount == config().max_ciphertext_bytes + 1
    assert fake.calls == [{"Bucket": "anonflow-ciphertexts", "Key": loaded.key}]


def test_recover_requires_exact_publication_marker_and_rechecks_body_digest():
    ciphertext = b"publication-bound-envelope"
    digest = hashlib.sha256(ciphertext).hexdigest()
    body = StreamingBody(ciphertext)
    response = {"ContentLength": len(ciphertext),
                "Metadata": {"anonflow-publication-ref": PUBLICATION, "anonflow-sha256": digest},
                "Body": body, "ResponseMetadata": {"HTTPStatusCode": 200}}
    recovered = S3CiphertextTransport(config(), FakeS3(response=response)).recover(
        tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION)
    assert recovered.ciphertext == ciphertext and recovered.sha256 == digest and body.closed

    wrong_marker = {**response, "Body": StreamingBody(ciphertext),
                    "Metadata": {"anonflow-publication-ref": "publicationref:v1:" + "Q" * 43,
                                 "anonflow-sha256": digest}}
    with pytest.raises(CiphertextTransportError):
        S3CiphertextTransport(config(), FakeS3(response=wrong_marker)).recover(
            tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION)

    tampered = {**response, "Body": StreamingBody(b"changed"), "ContentLength": len(b"changed")}
    with pytest.raises(CiphertextTransportError, match="integrity check failed"):
        S3CiphertextTransport(config(), FakeS3(response=tampered)).recover(
            tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION)


@pytest.mark.parametrize("response", [
    {"ContentLength": 4, "Metadata": {"anonflow-sha256": "0" * 64}, "Body": StreamingBody(b"four"), "ResponseMetadata": {"HTTPStatusCode": 206}},
    {"ContentLength": 4, "Metadata": {}, "Body": StreamingBody(b"four"), "ResponseMetadata": {"HTTPStatusCode": 200}},
    {"ContentLength": 3, "Metadata": {"anonflow-sha256": "0" * 64}, "Body": StreamingBody(b"four"), "ResponseMetadata": {"HTTPStatusCode": 200}},
])
def test_load_rejects_partial_invalid_metadata_or_short_length_and_closes_stream(response):
    body = response["Body"]
    with pytest.raises(CiphertextTransportError):
        S3CiphertextTransport(config(), FakeS3(response=response)).load(tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION, ciphertext_sha256="0" * 64)
    assert body.closed


@pytest.mark.parametrize("endpoint,bucket", [
    ("http://objects.example", "anonflow-ciphertexts"), ("https://user@objects.example", "anonflow-ciphertexts"),
    ("https://objects.example/path", "anonflow-ciphertexts"), ("https://objects.example", "UPPER"),
])
def test_config_requires_fixed_tls_endpoint_and_portable_bucket(endpoint, bucket):
    with pytest.raises(ValueError):
        config(endpoint_url=endpoint, bucket=bucket)


def test_config_rejects_non_string_key_namespace_without_leaking_type_errors():
    with pytest.raises(ValueError, match="configuration"):
        config(key_namespace=7)


@pytest.mark.parametrize("endpoint", ["http://objects.example", "https://other.example", "https://objects.example/path"])
def test_client_endpoint_must_exactly_match_configured_tls_endpoint(endpoint):
    with pytest.raises(ValueError, match="S3 client"):
        S3CiphertextTransport(config(), FakeS3(endpoint_url=endpoint))
