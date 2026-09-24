from pathlib import Path

import pytest

from app.s3_ciphertext_transport import S3CiphertextTransport
from app import s3_client_factory
from app.s3_client_factory import (S3ClientFactoryConfig, S3ClientFactoryError,
                                   S3StaticCredentials, build_s3_ciphertext_transport)


class CapturingSession:
    def __init__(self, **kwargs):
        self.session_kwargs = kwargs
        self.client_kwargs = None

    def client(self, service_name, **kwargs):
        self.client_kwargs = {"service_name": service_name, **kwargs}
        return type("Client", (), {"meta": type("Meta", (), {"endpoint_url": kwargs["endpoint_url"]})(),
                                    "put_object": lambda self, **_kwargs: {},
                                    "get_object": lambda self, **_kwargs: {}})()


class CapturingConfig:
    def __init__(self, **kwargs):
        self.kwargs = kwargs


def credentials():
    return S3StaticCredentials("test-access-key", "test-secret-value")


def config(base_ca_bundle: Path, **changes):
    values = {
        "endpoint_url": "https://objects.internal.example/",
        "bucket": "anonflow-ciphertexts",
        "region_name": "local-1",
        "ca_bundle": str(base_ca_bundle),
        "credentials": credentials(),
    }
    values.update(changes)
    return S3ClientFactoryConfig(**values)


def test_builds_validated_transport_with_explicit_sdk_configuration(monkeypatch, tmp_path):
    ca_bundle = tmp_path / "objects-ca.pem"
    ca_bundle.write_text("test certificate")
    sessions = []

    def session_factory(**kwargs):
        session = CapturingSession(**kwargs)
        sessions.append(session)
        return session

    monkeypatch.setattr(s3_client_factory, "_dependencies", lambda: (session_factory, CapturingConfig))
    transport = build_s3_ciphertext_transport(config(ca_bundle))

    assert isinstance(transport, S3CiphertextTransport)
    assert sessions[0].session_kwargs == {
        "aws_access_key_id": "test-access-key", "aws_secret_access_key": "test-secret-value",
    }
    call = sessions[0].client_kwargs
    assert call["service_name"] == "s3"
    assert call["region_name"] == "local-1"
    assert call["endpoint_url"] == "https://objects.internal.example"
    assert call["verify"] == str(ca_bundle)
    assert isinstance(call["config"], CapturingConfig)
    assert call["config"].kwargs == {
        "signature_version": "s3v4", "connect_timeout": 3, "read_timeout": 10,
        "retries": {"mode": "standard", "total_max_attempts": 2},
        "s3": {"addressing_style": "path"},
    }


@pytest.mark.parametrize("changes", [
    {"endpoint_url": "http://objects.internal.example"},
    {"endpoint_url": "https://user@objects.internal.example"},
    {"endpoint_url": "https://objects.internal.example/path"},
    {"bucket": "UPPER"}, {"region_name": "bad region"},
    {"ca_bundle": "relative-ca.pem"}, {"credentials": object()},
])
def test_configuration_rejects_untrusted_or_ambient_shapes_without_detail(tmp_path, changes):
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("test certificate")
    with pytest.raises(ValueError, match="^invalid S3 client factory configuration$"):
        config(ca_bundle, **changes)


def test_credentials_and_configuration_representations_never_expose_sensitive_values(tmp_path):
    ca_bundle = tmp_path / "sensitive-ca.pem"
    ca_bundle.write_text("test certificate")
    secret = S3StaticCredentials("private-access-key", "private-secret-value")
    value = config(ca_bundle, endpoint_url="https://private.objects.example", credentials=secret)
    rendered = repr(secret) + repr(value)
    for forbidden in ("private-access-key", "private-secret-value", "private.objects.example", str(ca_bundle)):
        assert forbidden not in rendered


def test_missing_ca_file_fails_closed_without_leaking_its_path(tmp_path):
    missing = tmp_path / "not-present.pem"
    with pytest.raises(S3ClientFactoryError, match="^S3 client construction unavailable$") as error:
        build_s3_ciphertext_transport(config(missing))
    assert str(missing) not in str(error.value)


def test_sdk_or_client_validation_failure_fails_closed_without_endpoint_or_secret(monkeypatch, tmp_path):
    ca_bundle = tmp_path / "ca.pem"
    ca_bundle.write_text("test certificate")

    def broken_session(**kwargs):
        raise RuntimeError("https://private.objects.example test-secret-value")

    monkeypatch.setattr(s3_client_factory, "_dependencies", lambda: (broken_session, CapturingConfig))
    with pytest.raises(S3ClientFactoryError, match="^S3 client construction unavailable$") as error:
        build_s3_ciphertext_transport(config(ca_bundle, endpoint_url="https://private.objects.example"))
    assert "private.objects.example" not in str(error.value)
    assert "test-secret-value" not in str(error.value)


def test_invalid_credential_shape_is_fixed_and_redacted():
    with pytest.raises(ValueError, match="^invalid S3 client credentials$") as error:
        S3StaticCredentials("access", "contains whitespace ")
    assert "access" not in str(error.value)
