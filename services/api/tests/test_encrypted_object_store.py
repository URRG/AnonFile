"""Adversarial tests for the M31 encrypted-object envelope boundary."""
from dataclasses import replace
from hashlib import sha256
from os import urandom
import traceback

import pytest

from app.encrypted_object_store import (DataKeyProvider, EncryptedByteTransport, EncryptedObjectStore,
    EncryptedObjectStoreError, GeneratedDataKey, _MAX_ENVELOPE_BYTES, _MAX_PLAINTEXT_BYTES, _TAG_BYTES)


TENANT = "tenantref:v1:" + "A" * 43
OTHER_TENANT = "tenantref:v1:" + "Z" * 43
OBJECT = "objectref:v1:" + "B" * 43
OTHER_OBJECT = "objectref:v1:" + "C" * 43
KEY = "keyref:v1:production-data-key"
OTHER_KEY = "keyref:v1:other-data-key"
PUBLICATION = "publicationref:v1:" + "P" * 43


class Keys(DataKeyProvider):
    def __init__(self):
        self.keys = {}
        self.contexts = []

    def generate(self, *, key_ref, context):
        key = urandom(32)
        wrapped = "wrapped:" + str(len(self.keys) + 1)
        self.keys[(key_ref, wrapped, context)] = key
        self.contexts.append(context)
        return GeneratedDataKey(key, wrapped)

    def unwrap(self, *, key_ref, wrapped_key, context):
        self.contexts.append(context)
        return self.keys[(key_ref, wrapped_key, context)]


class Memory(EncryptedByteTransport):
    def __init__(self):
        self.values = {}

    def put(self, *, tenant_ref, object_ref, publication_ref, envelope, ciphertext_digest):
        identity = (tenant_ref, object_ref)
        if identity in self.values or ciphertext_digest != "sha256:" + sha256(envelope).hexdigest():
            raise RuntimeError("overwrite rejected")
        self.values[identity] = envelope

    def get(self, *, tenant_ref, object_ref, publication_ref, ciphertext_digest):
        envelope = self.values[(tenant_ref, object_ref)]
        if ciphertext_digest != "sha256:" + sha256(envelope).hexdigest():
            raise RuntimeError("digest mismatch")
        return envelope

    def recover(self, *, tenant_ref, object_ref, publication_ref):
        envelope = self.values[(tenant_ref, object_ref)]
        return envelope, "sha256:" + sha256(envelope).hexdigest()


def store():
    return EncryptedObjectStore(data_keys=Keys(), transport=Memory())


def fails(call):
    with pytest.raises(EncryptedObjectStoreError) as captured:
        call()
    assert str(captured.value) == "Encrypted object operation failed"


def test_round_trip_returns_only_reference_and_keeps_key_material_out_of_metadata():
    secret = b"secret-dek-marker-32-bytes-12345"
    assert len(secret) == 32
    assert "secret-dek-marker" not in repr(GeneratedDataKey(secret, "wrapped:test"))
    value = store()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"private source")
    assert value.get(tenant_ref=TENANT, reference=reference) == b"private source"
    assert reference.tenant_ref == TENANT and reference.object_ref == OBJECT and reference.key_ref == KEY
    assert reference.encryption_algorithm == "AES-256-GCM"
    assert "private" not in repr(reference) and "wrapped" not in repr(reference)


def test_context_binds_tenant_object_and_key_and_wrong_tenant_or_key_fails_closed():
    value = store()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"x")
    fails(lambda: value.get(tenant_ref=OTHER_TENANT, reference=reference))
    fails(lambda: value.get(tenant_ref=TENANT, reference=replace(reference, key_ref=OTHER_KEY)))
    fails(lambda: value.get(tenant_ref=TENANT, reference=replace(reference, object_ref=OTHER_OBJECT)))


def test_create_only_transport_rejects_a_second_put_for_the_same_tenant_object():
    value = store()
    value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"first")
    fails(lambda: value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"second"))


@pytest.mark.parametrize("mutation", [
    lambda blob: b"!" + blob[1:],
    lambda blob: blob[:-1],
    lambda blob: blob.replace(b'"nonce":', b'"noNce":'),
])
def test_digest_and_canonical_envelope_reject_tampering(mutation):
    value = store()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"x")
    identity = (TENANT, OBJECT)
    value._transport.values[identity] = mutation(value._transport.values[identity])
    fails(lambda: value.get(tenant_ref=TENANT, reference=reference))


def test_nonce_tag_ciphertext_and_wrapped_key_tampering_are_all_rejected_even_with_matching_digest():
    value = store()
    reference = value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"x")
    identity = (TENANT, OBJECT)
    original = value._transport.values[identity]
    for old, new in ((b'"nonce":"', b'"nonce":"A'), (b'"ciphertext":"', b'"ciphertext":"A'),
                     (b'wrapped:1', b'wrapped:9')):
        modified = original.replace(old, new, 1)
        updated = replace(reference, ciphertext_digest="sha256:" + __import__("hashlib").sha256(modified).hexdigest(),
                          ciphertext_size_bytes=len(modified))
        value._transport.values[identity] = modified
        fails(lambda: value.get(tenant_ref=TENANT, reference=updated))
    value._transport.values[identity] = original


def test_invalid_input_and_transport_or_provider_failure_have_one_non_leaking_error():
    value = store()
    fails(lambda: value.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext="private"))
    fails(lambda: value.put(tenant_ref=TENANT, object_ref="bucket/private", publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"x"))


def test_size_contract_has_space_for_base64_tag_and_worst_case_wrapped_key_escaping():
    # Prove the configured maximum without allocating a 32 MiB test input.
    worst_ciphertext_b64 = 4 * ((_MAX_PLAINTEXT_BYTES + _TAG_BYTES + 2) // 3)
    worst_wrapped_key_json = 2 * 16_384
    assert worst_ciphertext_b64 + worst_wrapped_key_json + 256 <= _MAX_ENVELOPE_BYTES < 64 * 1024 * 1024


def test_provider_and_transport_exceptions_do_not_leak_plaintext_or_key_material():
    class BrokenKeys(Keys):
        def generate(self, *, key_ref, context):
            raise RuntimeError("key=super-secret source=private source")

    class BrokenTransport(Memory):
        def get(self, *, tenant_ref, object_ref, publication_ref, ciphertext_digest):
            raise RuntimeError("object held private source")

    failed_put = EncryptedObjectStore(data_keys=BrokenKeys(), transport=Memory())
    failed_get = EncryptedObjectStore(data_keys=Keys(), transport=BrokenTransport())
    fails(lambda: failed_put.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"private source"))
    payload = b"private source"
    try:
        failed_put.put(tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=payload)
    except EncryptedObjectStoreError as exc:
        rendered = "".join(traceback.format_exception(exc))
        assert "super-secret" not in rendered and "private source" not in rendered
        assert exc.__suppress_context__
    reference = EncryptedObjectStore(data_keys=failed_get._data_keys, transport=Memory()).put(
        tenant_ref=TENANT, object_ref=OBJECT, publication_ref=PUBLICATION, key_ref=KEY, plaintext=b"private source")
    fails(lambda: failed_get.get(tenant_ref=TENANT, reference=reference))
