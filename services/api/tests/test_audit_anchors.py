"""Tests for source-safe, non-production audit anchor checkpoints."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from app.audit_anchors import (AuditAnchorAuthority, AuditAnchorError, CHECKPOINT_STATE,
                                LIMITATIONS)


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
TENANT_A = "tenantref:v1:" + "A" * 43
TENANT_B = "tenantref:v1:" + "B" * 43
HEAD_A = "audithead:v1:" + "C" * 43
HEAD_B = "audithead:v1:" + "D" * 43
CHECKPOINT_A = "auditcp:v1:" + "E" * 43
CHECKPOINT_B = "auditcp:v1:" + "F" * 43


def authority(tenant=TENANT_A, key=b"k" * 32):
    return AuditAnchorAuthority(tenant_ref=tenant, authority_id="audit-authority-v1:control-plane", key=key)


def issued(signer=None):
    signer = signer or authority()
    return signer.issue(checkpoint_id=CHECKPOINT_A, sequence=1, audit_chain_commitment=HEAD_A,
                        previous_checkpoint_digest=None, issued_at=NOW, expires_at=NOW + timedelta(hours=1))


def test_signed_checkpoint_is_canonical_source_safe_and_not_an_external_anchor_claim():
    signer = authority()
    checkpoint = issued(signer)
    record = checkpoint.to_record()
    assert signer.verify(checkpoint, tenant_ref=TENANT_A, at=NOW)
    assert signer.restore(record, tenant_ref=TENANT_A, at=NOW).to_record() == record
    assert record["checkpoint_state"] == CHECKPOINT_STATE
    assert record["limitations"] == list(LIMITATIONS)
    forbidden = ("payload", "object_id", "subject", "actor", "url", "receipt", "event")
    assert not any(word in str(record).lower() for word in forbidden)


def test_signature_precisely_binds_every_signed_field_and_record_digest():
    signer = authority()
    checkpoint = issued(signer)
    for field, value in {
        "tenant_ref": TENANT_B,
        "checkpoint_id": CHECKPOINT_B,
        "sequence": 2,
        "audit_chain_commitment": HEAD_B,
        "previous_checkpoint_digest": "sha256:" + "a" * 64,
        "issued_at": NOW + timedelta(seconds=1),
        "expires_at": NOW + timedelta(hours=2),
        "authority_id": "audit-authority-v1:other",
    }.items():
        assert not signer.verify(replace(checkpoint, **{field: value}), tenant_ref=TENANT_A, at=NOW)
    record = checkpoint.to_record()
    record["digest"] = "sha256:" + "0" * 64
    with pytest.raises(AuditAnchorError):
        signer.restore(record, tenant_ref=TENANT_A, at=NOW)


def test_expiry_and_tenant_isolation_fail_closed():
    signer = authority()
    checkpoint = issued(signer)
    assert not signer.verify(checkpoint, tenant_ref=TENANT_B, at=NOW)
    assert not signer.verify(checkpoint, tenant_ref=TENANT_A, at=NOW - timedelta(seconds=1))
    assert not signer.verify(checkpoint, tenant_ref=TENANT_A, at=NOW + timedelta(hours=1))
    other = authority(TENANT_B)
    assert not other.verify(checkpoint, tenant_ref=TENANT_B, at=NOW)


def test_issuance_prevents_chain_forks_and_repeated_heads_and_claim_prevents_replay():
    signer = authority()
    first = issued(signer)
    with pytest.raises(AuditAnchorError):
        signer.issue(checkpoint_id=CHECKPOINT_A, sequence=2, audit_chain_commitment=HEAD_B,
                     previous_checkpoint_digest=first.digest, issued_at=NOW, expires_at=NOW + timedelta(hours=1))
    with pytest.raises(AuditAnchorError):
        signer.issue(checkpoint_id=CHECKPOINT_B, sequence=2, audit_chain_commitment=HEAD_B,
                     previous_checkpoint_digest=None, issued_at=NOW, expires_at=NOW + timedelta(hours=1))
    with pytest.raises(AuditAnchorError):
        signer.issue(checkpoint_id=CHECKPOINT_B, sequence=2, audit_chain_commitment=HEAD_A,
                     previous_checkpoint_digest=first.digest, issued_at=NOW, expires_at=NOW + timedelta(hours=1))
    assert signer.claim(first, tenant_ref=TENANT_A, at=NOW)
    assert not signer.claim(first, tenant_ref=TENANT_A, at=NOW)
    # Repeated inspection stays possible; only a submission claim is one-shot.
    assert signer.verify(first, tenant_ref=TENANT_A, at=NOW)


def test_rejects_unverified_serialization_bad_windows_and_nonopaque_input():
    signer = authority()
    with pytest.raises(AuditAnchorError):
        signer.issue(checkpoint_id=CHECKPOINT_A, sequence=1, audit_chain_commitment=HEAD_A,
                     previous_checkpoint_digest=None, issued_at=NOW, expires_at=NOW + timedelta(hours=25))
    with pytest.raises(AuditAnchorError):
        signer.issue(checkpoint_id="raw-identifier", sequence=1, audit_chain_commitment=HEAD_A,
                     previous_checkpoint_digest=None, issued_at=NOW, expires_at=NOW + timedelta(hours=1))
    forged = replace(issued(signer), signature="auditsig:v1:" + "Z" * 43)
    with pytest.raises(AuditAnchorError):
        forged.to_record()


def test_verifier_rejects_subclass_canonicalizer_overrides_at_trust_boundary():
    class Lookalike(type(issued())):
        def _signed_fields(self):
            return super()._signed_fields()

    signer = authority()
    checkpoint = issued(signer)
    lookalike = Lookalike(checkpoint.tenant_ref, checkpoint.checkpoint_id, checkpoint.sequence,
                          checkpoint.audit_chain_commitment, checkpoint.previous_checkpoint_digest,
                          checkpoint.issued_at, checkpoint.expires_at, checkpoint.authority_id,
                          checkpoint.signature)
    assert not signer.verify(lookalike, tenant_ref=TENANT_A, at=NOW)


def test_concurrent_issuance_admits_exactly_one_head_without_a_fork():
    signer = authority()
    workers = 16
    barrier = threading.Barrier(workers)

    def issue_same_head():
        barrier.wait()
        try:
            return signer.issue(checkpoint_id=CHECKPOINT_A, sequence=1, audit_chain_commitment=HEAD_A,
                                previous_checkpoint_digest=None, issued_at=NOW,
                                expires_at=NOW + timedelta(hours=1))
        except AuditAnchorError:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda _: issue_same_head(), range(workers)))
    successful = [result for result in results if result is not None]
    assert len(successful) == 1
    assert successful[0].sequence == 1


def test_concurrent_claim_admits_exactly_one_external_submission():
    signer = authority()
    checkpoint = issued(signer)
    workers = 16
    barrier = threading.Barrier(workers)

    def claim_once():
        barrier.wait()
        return signer.claim(checkpoint, tenant_ref=TENANT_A, at=NOW)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda _: claim_once(), range(workers)))
    assert results.count(True) == 1
    assert results.count(False) == workers - 1
