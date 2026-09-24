"""Adversarial tests for the M23 local checkpoint / receipt verification bridge."""
import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.audit_anchors import AuditAnchorAuthority
from app.audit_receipt_bridge import AuditCheckpointReceiptBridge, AuditReceiptBridgeError
from app.external_audit_receipts import (AnchorServiceKey, ExternalAuditReceipt,
    ExternalAuditReceiptStore, ExternalAuditReceiptVerifier)


NOW = datetime(2026, 9, 24, 12, tzinfo=UTC)
TENANT = "tenantref:v1:" + "A" * 43
OTHER_TENANT = "tenantref:v1:" + "B" * 43
HEAD_1 = "audithead:v1:" + "C" * 43
HEAD_2 = "audithead:v1:" + "D" * 43
CHECKPOINT_1 = "auditcp:v1:" + "E" * 43
CHECKPOINT_2 = "auditcp:v1:" + "F" * 43
SERVICE = "external-audit-anchor:v1:independent-time-service"


def setup(tmp_path):
    authority = AuditAnchorAuthority(tenant_ref=TENANT,
        authority_id="audit-authority-v1:control-plane", key=b"k" * 32)
    private = Ed25519PrivateKey.from_private_bytes(b"x" * 32)
    key = AnchorServiceKey(service_id=SERVICE, key_id="receipt-key-2026",
        public_key_b64=base64.b64encode(private.public_key().public_bytes_raw()).decode())
    store = ExternalAuditReceiptStore(tmp_path / "receipts.sqlite3",
        ExternalAuditReceiptVerifier((key,)))
    return authority, private, key, store, AuditCheckpointReceiptBridge(
        authority=authority, receipt_store=store)


def checkpoint(authority, sequence=1, previous=None, head=HEAD_1):
    return authority.issue(checkpoint_id=CHECKPOINT_1 if sequence == 1 else CHECKPOINT_2,
        sequence=sequence, audit_chain_commitment=head,
        previous_checkpoint_digest=previous, issued_at=NOW,
        expires_at=NOW + timedelta(hours=1))


def receipt(private, key, local_checkpoint, *, sequence=None, tenant=TENANT,
            digest=None, previous=None, when=NOW):
    provisional = ExternalAuditReceipt(tenant_ref=tenant,
        checkpoint_digest=digest or local_checkpoint.digest,
        sequence=local_checkpoint.sequence if sequence is None else sequence,
        anchored_at=when, service_id=key.service_id, key_id=key.key_id,
        public_key_fingerprint=key.public_key_fingerprint,
        receipt_id="auditreceipt:v1:" + ("G" if local_checkpoint.sequence == 1 else "H") * 43,
        previous_receipt_digest=previous,
        signature="external-audit-receipt-sig:v1:" + "A" * 86)
    signature = private.sign(b"external-audit-receipt-v1:" + json.dumps(
        provisional.canonical(), sort_keys=True, separators=(",", ":")).encode())
    return replace(provisional, signature="external-audit-receipt-sig:v1:" +
        base64.urlsafe_b64encode(signature).decode().rstrip("="))


def test_accepts_only_the_exact_authenticated_checkpoint_and_persists_receipt(tmp_path):
    authority, private, key, store, bridge = setup(tmp_path)
    local = checkpoint(authority)
    external = receipt(private, key, local)
    assert bridge.accept(local, external, tenant_ref=TENANT, at=NOW) == external
    assert store.head(TENANT, at=NOW) == external
    store.close()


@pytest.mark.parametrize("change", ["missing", "digest", "tenant", "sequence", "before-issued"])
def test_missing_or_mismatched_signed_receipts_fail_closed(tmp_path, change):
    authority, private, key, store, bridge = setup(tmp_path)
    local = checkpoint(authority)
    external = receipt(private, key, local)
    candidate = {
        "missing": None,
        "digest": receipt(private, key, local, digest="sha256:" + "0" * 64),
        "tenant": receipt(private, key, local, tenant=OTHER_TENANT),
        "sequence": receipt(private, key, local, sequence=2),
        "before-issued": receipt(private, key, local, when=NOW - timedelta(seconds=1)),
    }[change]
    with pytest.raises(AuditReceiptBridgeError):
        bridge.accept(local, candidate, tenant_ref=TENANT, at=NOW)
    assert store.head(TENANT, at=NOW) is None
    store.close()


def test_forged_or_unauthenticated_local_evidence_cannot_be_admitted(tmp_path):
    authority, private, key, store, bridge = setup(tmp_path)
    local = checkpoint(authority)
    external = receipt(private, key, local)
    forged_checkpoint = replace(local, signature="auditsig:v1:" + "Z" * 43)
    forged_receipt = replace(external, signature="external-audit-receipt-sig:v1:" + "A" * 86)
    for bad_checkpoint, bad_receipt in ((forged_checkpoint, external), (local, forged_receipt)):
        with pytest.raises(AuditReceiptBridgeError):
            bridge.accept(bad_checkpoint, bad_receipt, tenant_ref=TENANT, at=NOW)
    assert store.head(TENANT, at=NOW) is None
    store.close()


def test_stale_receipt_and_broken_persisted_continuity_fail_closed(tmp_path):
    authority, private, key, store, bridge = setup(tmp_path)
    first_local = checkpoint(authority)
    first = receipt(private, key, first_local)
    bridge.accept(first_local, first, tenant_ref=TENANT, at=NOW)
    with pytest.raises(AuditReceiptBridgeError):
        bridge.accept(first_local, first, tenant_ref=TENANT, at=NOW)

    second_local = checkpoint(authority, 2, first_local.digest, HEAD_2)
    wrong_parent = receipt(private, key, second_local, previous=None)
    with pytest.raises(AuditReceiptBridgeError):
        bridge.accept(second_local, wrong_parent, tenant_ref=TENANT, at=NOW)
    assert store.head(TENANT, at=NOW) == first
    store.close()
