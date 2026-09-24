import hashlib

import pytest

from app.s3_ciphertext_transport import ObjectAlreadyExistsError, opaque_object_key
from app.s3_versioned_ciphertext_transport import (
    S3VersionedCiphertextTransport, S3VersionedCiphertextTransportConfig,
    VersionedFetchedCiphertext, VersionedStoredCiphertext,
    VersionedCiphertextTransportError,
)


TENANT = "tenantref:v1:" + "T" * 43
OBJECT = "objectref:v1:" + "O" * 43
PUBLICATION = "publicationref:v1:" + "P" * 43
VERSION = "opaque-provider-version-1"


class ConditionalError(Exception):
    response = {
        "ResponseMetadata": {"HTTPStatusCode": 412},
        "Error": {"Code": "PreconditionFailed"},
    }


class Body:
    def __init__(self, value):
        self.value = value
        self.closed = False

    def read(self, amount):
        return self.value

    def close(self):
        self.closed = True


class FakeS3:
    def __init__(self, *, put=None, get=None, error=None):
        self.meta = type("Meta", (), {"endpoint_url": "https://objects.example"})()
        self.put = put
        self.get = get
        self.error = error
        self.calls = []

    def put_object(self, **kwargs):
        self.calls.append(("put", kwargs))
        if self.error:
            raise self.error
        return self.put

    def get_object(self, **kwargs):
        self.calls.append(("get", kwargs))
        if self.error:
            raise self.error
        return self.get


def config(**changes):
    values = {"endpoint_url": "https://objects.example", "bucket": "anonflow-ciphertexts",
              "profile_id": "s3-versioned-v1:ci-minio"}
    values.update(changes)
    return S3VersionedCiphertextTransportConfig(**values)


def get_response(value=b"ciphertext", *, version=VERSION, digest=None, publication=PUBLICATION):
    digest = digest or hashlib.sha256(value).hexdigest()
    return {
        "ResponseMetadata": {"HTTPStatusCode": 200},
        "VersionId": version,
        "ContentLength": len(value),
        "Metadata": {"anonflow-publication-ref": publication, "anonflow-sha256": digest},
        "Body": Body(value),
    }


def identity(*, version=VERSION, profile_id="s3-versioned-v1:ci-minio",
             key=None, publication=PUBLICATION, digest=None):
    value = b"ciphertext"
    return VersionedStoredCiphertext(
        key=key or opaque_object_key(config().base_config(), TENANT, OBJECT),
        sha256=digest or hashlib.sha256(value).hexdigest(), byte_count=len(value),
        publication_ref=publication, profile_id=profile_id, provider_version_id=version,
    )


def test_put_requires_non_null_provider_version_and_preserves_m32_create_only_shape():
    value, digest = b"ciphertext", hashlib.sha256(b"ciphertext").hexdigest()
    fake = FakeS3(put={"ResponseMetadata": {"HTTPStatusCode": 200}, "VersionId": VERSION})
    stored = S3VersionedCiphertextTransport(config(), fake).store(
        tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION,
        ciphertext=value, ciphertext_sha256=digest)
    assert stored.provider_version_id == VERSION
    assert stored.profile_id == "s3-versioned-v1:ci-minio"
    assert fake.calls == [("put", {
        "Bucket": "anonflow-ciphertexts", "Key": stored.key, "Body": value,
        "ContentLength": len(value), "ContentType": "application/octet-stream",
        "Metadata": {"anonflow-publication-ref": PUBLICATION, "anonflow-sha256": digest},
        "ACL": "private", "IfNoneMatch": "*",
    })]


@pytest.mark.parametrize("version", [None, "null", "", "bad space", "x" * 1025])
def test_put_missing_or_malformed_provider_version_fails_closed(version):
    value = b"ciphertext"
    fake = FakeS3(put={"ResponseMetadata": {"HTTPStatusCode": 200}, "VersionId": version})
    with pytest.raises(VersionedCiphertextTransportError, match="unavailable"):
        S3VersionedCiphertextTransport(config(), fake).store(
            tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION, ciphertext=value,
            ciphertext_sha256=hashlib.sha256(value).hexdigest())


def test_load_pins_exact_provider_version_and_rejects_response_version_mismatch():
    response = get_response(version=VERSION)
    fake = FakeS3(get=response)
    adapter = S3VersionedCiphertextTransport(config(), fake)
    loaded = adapter.load(tenant_id=TENANT, object_id=OBJECT, identity=identity())
    assert loaded.provider_version_id == VERSION
    assert loaded.profile_id == "s3-versioned-v1:ci-minio"
    assert fake.calls[0][1]["VersionId"] == VERSION

    different = get_response(version="opaque-provider-version-2")
    with pytest.raises(VersionedCiphertextTransportError, match="unavailable"):
        S3VersionedCiphertextTransport(config(), FakeS3(get=different)).load(
            tenant_id=TENANT, object_id=OBJECT, identity=identity())
    assert different["Body"].closed


def test_recovery_never_adopts_current_or_wrong_provider_version():
    response = get_response(version="opaque-provider-version-current")
    with pytest.raises(VersionedCiphertextTransportError, match="unavailable"):
        S3VersionedCiphertextTransport(config(), FakeS3(get=response)).recover(
            tenant_id=TENANT, object_id=OBJECT, identity=identity())
    assert response["Body"].closed


@pytest.mark.parametrize("changed", [
    {"profile_id": "s3-versioned-v1:other-profile"},
    {"key": "anonflow-ciphertext-v1/" + "c" * 64 + "/" + "d" * 64},
])
def test_reads_reject_identity_from_a_different_profile_or_key_before_sdk_io(changed):
    fake = FakeS3(get=get_response())
    values = {
        "key": identity().key,
        "sha256": identity().sha256,
        "byte_count": identity().byte_count,
        "publication_ref": identity().publication_ref,
        "profile_id": identity().profile_id,
        "provider_version_id": identity().provider_version_id,
    }
    values.update(changed)
    with pytest.raises(ValueError, match="identity"):
        S3VersionedCiphertextTransport(config(), fake).load(
            tenant_id=TENANT, object_id=OBJECT, identity=VersionedStoredCiphertext(**values))
    assert fake.calls == []


def test_read_rejects_an_identity_size_that_does_not_match_the_pinned_version():
    stored = identity()
    altered_size = VersionedStoredCiphertext(
        key=stored.key, sha256=stored.sha256, byte_count=stored.byte_count + 1,
        publication_ref=stored.publication_ref, profile_id=stored.profile_id,
        provider_version_id=stored.provider_version_id,
    )
    with pytest.raises(VersionedCiphertextTransportError, match="unavailable"):
        S3VersionedCiphertextTransport(config(), FakeS3(get=get_response())).load(
            tenant_id=TENANT, object_id=OBJECT, identity=altered_size)


def test_fetched_ciphertext_representation_excludes_its_bytes():
    marker = b"M46 private ciphertext marker"
    fetched = VersionedFetchedCiphertext(
        key=opaque_object_key(config().base_config(), TENANT, OBJECT),
        sha256=hashlib.sha256(marker).hexdigest(), ciphertext=marker,
        publication_ref=PUBLICATION, profile_id="s3-versioned-v1:ci-minio",
        provider_version_id=VERSION,
    )
    assert marker.decode("ascii") not in repr(fetched)


def test_conditional_conflict_stays_an_existing_object_error():
    value = b"ciphertext"
    with pytest.raises(ObjectAlreadyExistsError):
        S3VersionedCiphertextTransport(config(), FakeS3(error=ConditionalError())).store(
            tenant_id=TENANT, object_id=OBJECT, publication_ref=PUBLICATION, ciphertext=value,
            ciphertext_sha256=hashlib.sha256(value).hexdigest())


@pytest.mark.parametrize("profile", ["not-a-profile", "s3-versioned-v1:Upper", "s3-versioned-v1:" + "x" * 65])
def test_profile_is_deployment_owned_and_strict(profile):
    with pytest.raises(ValueError, match="configuration"):
        config(profile_id=profile)


@pytest.mark.parametrize("constructor,kwargs", [
    (VersionedStoredCiphertext, {
        "key": "invalid-key", "sha256": "a" * 64, "byte_count": 1,
        "publication_ref": PUBLICATION, "profile_id": "s3-versioned-v1:ci-minio",
        "provider_version_id": VERSION,
    }),
    (VersionedFetchedCiphertext, {
        "key": "anonflow-ciphertext-v1/" + "a" * 64 + "/" + "b" * 64,
        "sha256": "a" * 64, "ciphertext": b"one", "publication_ref": PUBLICATION,
        "profile_id": "not-a-profile", "provider_version_id": VERSION,
    }),
])
def test_return_values_reject_unbound_key_or_profile_shapes(constructor, kwargs):
    with pytest.raises(VersionedCiphertextTransportError, match="unavailable"):
        constructor(**kwargs)
