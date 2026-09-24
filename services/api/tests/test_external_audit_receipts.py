"""Adversarial tests for independently signed external audit receipts."""
import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.external_audit_receipts import (AnchorServiceKey, ExternalAuditReceipt,
    ExternalAuditReceiptError, ExternalAuditReceiptStore, ExternalAuditReceiptVerifier)

NOW = datetime(2026, 9, 24, 12, tzinfo=UTC)
TENANT = "tenantref:v1:" + "A" * 43
CHECKPOINT_1 = "sha256:" + "1" * 64
CHECKPOINT_2 = "sha256:" + "2" * 64
SERVICE = "external-audit-anchor:v1:independent-time-service"


def setup():
    private = Ed25519PrivateKey.from_private_bytes(b"x" * 32)
    public = base64.b64encode(private.public_key().public_bytes_raw()).decode()
    key = AnchorServiceKey(service_id=SERVICE, key_id="receipt-key-2026", public_key_b64=public)
    return private, key, ExternalAuditReceiptVerifier((key,))


def receipt(private, key, sequence=1, checkpoint=CHECKPOINT_1, previous=None, when=NOW):
    fields = {"tenant_ref": TENANT, "checkpoint_digest": checkpoint, "sequence": sequence,
              "anchored_at": when, "service_id": key.service_id, "key_id": key.key_id,
              "public_key_fingerprint": key.public_key_fingerprint,
              "receipt_id": "auditreceipt:v1:" + ("B" if sequence == 1 else "C") * 43,
              "previous_receipt_digest": previous, "signature": "external-audit-receipt-sig:v1:" + "A" * 86}
    provisional = ExternalAuditReceipt(**fields)
    signature = private.sign(b"external-audit-receipt-v1:" + __import__("json").dumps(provisional.canonical(), sort_keys=True, separators=(",", ":")).encode())
    return replace(provisional, signature="external-audit-receipt-sig:v1:" + base64.urlsafe_b64encode(signature).decode().rstrip("="))


def test_pinned_external_signature_binds_exact_checkpoint_tenant_and_metadata():
    private, key, verifier = setup()
    item = receipt(private, key)
    assert verifier.verify(item, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)
    for changed in (replace(item, checkpoint_digest=CHECKPOINT_2), replace(item, tenant_ref="tenantref:v1:" + "Z" * 43), replace(item, sequence=2), replace(item, anchored_at=NOW + timedelta(seconds=1))):
        assert not verifier.verify(changed, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)


def test_unknown_key_wrong_fingerprint_bad_signature_and_future_receipt_fail_closed():
    private, key, verifier = setup()
    item = receipt(private, key)
    assert not ExternalAuditReceiptVerifier((AnchorServiceKey(service_id=SERVICE, key_id="other", public_key_b64=key.public_key_b64),)).verify(item, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)
    assert not verifier.verify(replace(item, public_key_fingerprint="sha256:" + "0" * 64), tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)
    encoded = item.signature.rsplit(":", 1)[1]
    corrupted = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    assert not verifier.verify(replace(item, signature="external-audit-receipt-sig:v1:" + corrupted), tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)
    future = receipt(private, key, when=NOW + timedelta(seconds=1))
    assert not verifier.verify(future, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)


def test_signature_requires_canonical_base64url_encoding_without_unused_bit_aliases():
    private, key, _ = setup(); item = receipt(private, key)
    encoded = item.signature.rsplit(":", 1)[1]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    # A 64-byte signature leaves four unused bits in its final base64url
    # sextet.  Toggle one: permissive decoders recover the same bytes.
    alternate = encoded[:-1] + alphabet[alphabet.index(encoded[-1]) ^ 1]
    assert base64.urlsafe_b64decode(encoded + "==") == base64.urlsafe_b64decode(alternate + "==")
    with pytest.raises(ExternalAuditReceiptError):
        replace(item, signature="external-audit-receipt-sig:v1:" + alternate)


def test_link_rejects_an_anchor_time_that_precedes_its_verified_predecessor():
    private, key, verifier = setup(); first = receipt(private, key, when=NOW)
    second = receipt(private, key, 2, CHECKPOINT_2, first.digest, NOW - timedelta(seconds=1))
    assert not verifier.verify(second, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_2, at=NOW,
                               previous=first)


def test_safe_record_parse_rejects_extra_fields_and_digest_tampering():
    private, key, _ = setup(); item = receipt(private, key); record = item.to_record()
    assert ExternalAuditReceipt.from_record(record) == item
    record["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ExternalAuditReceiptError): ExternalAuditReceipt.from_record(record)
    record = item.to_record(); record["payload"] = b"never"
    with pytest.raises(ExternalAuditReceiptError): ExternalAuditReceipt.from_record(record)


def test_durable_store_rejects_replay_rollback_and_wrong_checkpoint_across_restart(tmp_path):
    private, key, verifier = setup(); first = receipt(private, key)
    database = tmp_path / "receipts.sqlite3"
    store = ExternalAuditReceiptStore(database, verifier)
    assert store.accept(first, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW) == first
    with pytest.raises(ExternalAuditReceiptError): store.accept(first, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)
    second = receipt(private, key, 2, CHECKPOINT_2, first.digest)
    assert store.accept(second, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_2, at=NOW) == second
    store.close(); store = ExternalAuditReceiptStore(database, verifier)
    assert store.head(TENANT, at=NOW) == second
    with pytest.raises(ExternalAuditReceiptError): store.accept(first, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)
    with pytest.raises(ExternalAuditReceiptError): store.accept(second, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)
    store.close()


def test_persisted_chain_is_reverified_before_it_can_be_used_as_a_parent(tmp_path):
    private, key, verifier = setup(); first = receipt(private, key)
    store = ExternalAuditReceiptStore(tmp_path / "receipts.sqlite3", verifier)
    store.accept(first, tenant_ref=TENANT, checkpoint_digest=CHECKPOINT_1, at=NOW)
    # Simulate an attacker with database write access who can recompute record
    # digests but cannot make an independent anchor-service signature.
    encoded = first.signature.rsplit(":", 1)[1]
    corrupted = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    forged = replace(first, signature="external-audit-receipt-sig:v1:" + corrupted)
    store._connection.execute("UPDATE external_audit_receipts SET record=?", (__import__("json").dumps(forged.to_record()),))
    with pytest.raises(ExternalAuditReceiptError): store.head(TENANT, at=NOW)
    store.close()
