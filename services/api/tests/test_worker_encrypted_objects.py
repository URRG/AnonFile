"""Composition tests: OpenBao's short-lived token reaches no persistent state."""
from __future__ import annotations

import base64
from hashlib import sha256
import json
import traceback

import pytest

from app.encrypted_object_store import EncryptedObjectStoreError
from app.openbao_datakey import OpenBaoDataKeyConfig, OpenBaoTransitDataKey
from app.s3_ciphertext_transport import S3CiphertextTransport, S3CiphertextTransportConfig
from app.worker_encrypted_objects import (WorkerEncryptedObjects, WorkerEncryptedObjectsError,
                                          _S3EnvelopeTransport, _ScopedOpenBaoDataKeys)


TENANT = "tenantref:v1:" + "T" * 43
OTHER_TENANT = "tenantref:v1:" + "U" * 43
OBJECT = "objectref:v1:" + "O" * 43
KEY = "keyref:v1:production-data-key"
PUBLICATION = "publicationref:v1:" + "P" * 43
WRAPPED = "vault:v7:" + base64.b64encode(b"w" * 60).decode("ascii")


class Response:
    def __init__(self, body):
        self.status, self._body = 200, body
    def read(self, amount):
        return self._body
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False


class OpenBaoFake:
    """M30's HTTP seam with context-bound keys, never a fake M30 adapter."""
    def __init__(self):
        self.requests, self.keys = [], {}
    def open(self, request, timeout):
        self.requests.append(request)
        path = request.full_url.rsplit("/", 2)[-2]
        if path == "keys":
            data = {"type": "aes256-gcm96", "derived": False, "exportable": False,
                    "allow_plaintext_backup": False, "deletion_allowed": False,
                    "supports_encryption": True, "supports_decryption": True,
                    "latest_version": 7, "min_decryption_version": 1, "min_encryption_version": 7}
        else:
            payload = json.loads(request.data)
            context = payload["associated_data"]
            if path == "plaintext":
                plaintext = bytes([len(self.keys) + 1]) * 32
                wrapped = "vault:v7:" + base64.b64encode(bytes([len(self.keys) + 1]) * 60).decode("ascii")
                self.keys[(wrapped, context)] = plaintext
                data = {"plaintext": base64.b64encode(plaintext).decode("ascii"), "ciphertext": wrapped,
                        "key_version": 7}
            elif path == "decrypt":
                data = {"plaintext": base64.b64encode(self.keys[(payload["ciphertext"], context)]).decode("ascii")}
            else:
                raise AssertionError(path)
        return Response(json.dumps({"data": data}).encode("ascii"))


class Body:
    def __init__(self, value): self.value, self.closed = value, False
    def read(self, amount): return self.value
    def close(self): self.closed = True


class S3Fake:
    def __init__(self):
        self.meta = type("Meta", (), {"endpoint_url": "https://objects.example"})()
        self.objects, self.calls = {}, []
        self.accept_then_raise = False
    def put_object(self, **kwargs):
        self.calls.append(kwargs)
        if kwargs["Key"] in self.objects:
            error = Exception("duplicate")
            error.response = {"ResponseMetadata": {"HTTPStatusCode": 412}, "Error": {"Code": "PreconditionFailed"}}
            raise error
        self.objects[kwargs["Key"]] = (kwargs["Body"], kwargs["Metadata"])
        if self.accept_then_raise:
            self.accept_then_raise = False
            raise RuntimeError("response lost after object acceptance")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}
    def get_object(self, **kwargs):
        self.calls.append(kwargs)
        value, metadata = self.objects[kwargs["Key"]]
        return {"ContentLength": len(value), "Metadata": metadata, "Body": Body(value),
                "ResponseMetadata": {"HTTPStatusCode": 200}}


def composed():
    bao_http, s3_sdk = OpenBaoFake(), S3Fake()
    bao = OpenBaoTransitDataKey(OpenBaoDataKeyConfig("https://bao.example", "transit", "envelope-key", KEY, 7),
                                transport=bao_http)
    s3 = S3CiphertextTransport(S3CiphertextTransportConfig("https://objects.example", "anonflow-ciphertexts"), s3_sdk)
    return WorkerEncryptedObjects(openbao=bao, ciphertexts=s3), bao_http, s3, s3_sdk


def test_put_get_uses_explicit_operation_tokens_and_sends_only_envelope_to_s3():
    value, bao_http, s3, s3_sdk = composed()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"customer private record",
                          openbao_token="put-token")
    assert value.get(tenant_ref=TENANT, reference=reference, openbao_token="get-token") == b"customer private record"
    tokens = [request.get_header("X-vault-token") for request in bao_http.requests]
    assert tokens == ["put-token", "put-token", "get-token", "get-token"]
    put_call = next(call for call in s3_sdk.calls if "Body" in call)
    assert put_call["Body"] != b"customer private record"
    assert b"customer private record" not in put_call["Body"]
    assert reference.ciphertext_digest.startswith("sha256:")
    assert "put-token" not in repr(value) and "customer private record" not in repr(reference)
    assert s3_sdk.calls[0]["Key"] not in repr(reference)
    assert type(s3) is S3CiphertextTransport


def test_tenant_aad_and_duplicate_fail_closed_without_a_token_or_object_key_leak():
    value, _, _, s3_sdk = composed()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"private", openbao_token="token-1")
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        value.get(tenant_ref=OTHER_TENANT, reference=reference, openbao_token="token-2")
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"different", openbao_token="token-3")
    assert len([call for call in s3_sdk.calls if "Body" in call]) == 2


def test_response_lost_after_create_recovers_only_same_publication_in_a_fresh_worker():
    value, _, s3, s3_sdk = composed()
    s3_sdk.accept_then_raise = True
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
                  key_ref=KEY, plaintext=b"private", openbao_token="lost-response-token")

    fresh = WorkerEncryptedObjects(openbao=value._openbao, ciphertexts=s3)
    reference = fresh.put_or_recover(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
                                     key_ref=KEY, plaintext=b"private",
                                     openbao_token="recovery-token")
    assert fresh.get(tenant_ref=TENANT, reference=reference, openbao_token="recovery-token") == b"private"

    with pytest.raises(WorkerEncryptedObjectsError, match="^Worker encrypted object operation failed$"):
        fresh.put_or_recover(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
                             key_ref=KEY, plaintext=b"different retry plaintext",
                             openbao_token="recovery-token")

    wrong_publication = "publicationref:v1:" + "Q" * 43
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        fresh.recover(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=wrong_publication,
                      key_ref=KEY, openbao_token="recovery-token")
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        fresh.recover(tenant_ref=OTHER_TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
                      key_ref=KEY, openbao_token="recovery-token")


def test_recovery_rejects_a_tampered_envelope_before_returning_a_reference():
    value, _, s3, s3_sdk = composed()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
                          key_ref=KEY, plaintext=b"private", openbao_token="token")
    key = next(iter(s3_sdk.objects))
    envelope, metadata = s3_sdk.objects[key]
    s3_sdk.objects[key] = (b"!" + envelope[1:], metadata)
    fresh = WorkerEncryptedObjects(openbao=value._openbao, ciphertexts=s3)
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        fresh.recover(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION,
                      key_ref=KEY, openbao_token="token")
    assert reference.publication_ref == PUBLICATION


def test_wrong_key_cannot_authenticate_even_when_the_s3_object_and_digest_are_valid():
    value, bao_http, _, _ = composed()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"private", openbao_token="token")
    # The fake is M30's HTTP transport: a different AAD-bound key cannot
    # authenticate the envelope, even while its storage digest remains valid.
    key = next(iter(bao_http.keys))
    bao_http.keys[key] = b"x" * 32
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        value.get(tenant_ref=TENANT, reference=reference, openbao_token="token")


def test_bad_token_fake_dependencies_and_adapter_result_substitution_fail_closed():
    value, _, s3, _ = composed()
    with pytest.raises(WorkerEncryptedObjectsError, match="^Worker encrypted object operation failed$"):
        value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"private", openbao_token="bad token")
    with pytest.raises(WorkerEncryptedObjectsError):
        WorkerEncryptedObjects(openbao=object(), ciphertexts=s3)
    with pytest.raises(WorkerEncryptedObjectsError):
        WorkerEncryptedObjects(openbao=value._openbao, ciphertexts=object())
    scoped = _ScopedOpenBaoDataKeys(value._openbao, "very-secret-token")
    assert "very-secret-token" not in repr(scoped)

    def forged_store(**kwargs):
        return object()
    s3.store = forged_store
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"private", openbao_token="token")


def test_substituted_s3_load_result_is_rejected_before_it_reaches_the_envelope_parser():
    value, _, s3, _ = composed()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"private", openbao_token="token")

    def forged_load(**kwargs):
        return object()
    s3.load = forged_load
    with pytest.raises(EncryptedObjectStoreError, match="^Encrypted object operation failed$"):
        value.get(tenant_ref=TENANT, reference=reference, openbao_token="token")


def test_scoped_adapter_tracebacks_do_not_include_malicious_provider_or_transport_details():
    value, _, s3, _ = composed()
    secret = "token=super-secret plaintext=private"

    def broken_generate(**kwargs):
        raise RuntimeError(secret)
    value._openbao.generate = broken_generate
    with pytest.raises(WorkerEncryptedObjectsError) as provider_error:
        _ScopedOpenBaoDataKeys(value._openbao, "token").generate(key_ref=KEY, context=b"aad")
    assert secret not in "".join(traceback.format_exception(provider_error.value))

    def broken_store(**kwargs):
        raise RuntimeError(secret)
    s3.store = broken_store
    with pytest.raises(WorkerEncryptedObjectsError) as transport_error:
        _S3EnvelopeTransport(s3).put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, envelope=b"envelope",
                                     ciphertext_digest="sha256:" + sha256(b"envelope").hexdigest())
    assert secret not in "".join(traceback.format_exception(transport_error.value))
