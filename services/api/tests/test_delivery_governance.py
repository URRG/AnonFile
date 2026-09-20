from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.delivery_governance import (
    DeliveryAssertionKind,
    DeliveryBinding,
    DeliveryEvidenceAuthority,
    DeliveryGovernanceError,
    DeliveryReadinessReason,
    DeliveryReadinessStatus,
    assess_delivery_readiness,
)


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)


def digest(char: str) -> str:
    return "sha256:" + char * 64


def binding() -> DeliveryBinding:
    return DeliveryBinding(
        candidate_artifact_digest=digest("a"), policy_digest=digest("b"), rights_digest="c" * 64,
        recipient_reference=digest("d"), purpose_code="model-training", contract_reference=digest("e"),
        contract_digest=digest("f"), candidate_expires_at=NOW + timedelta(days=10),
    )


def authority() -> DeliveryEvidenceAuthority:
    return DeliveryEvidenceAuthority(key_id="delivery-control-v1", secret=b"s" * 32)


def assertions(current_binding: DeliveryBinding, signer: DeliveryEvidenceAuthority):
    reference_characters = "1234"
    digest_characters = "5678"
    return tuple(signer.issue_assertion(
        assertion_id=f"assertion-{kind.value.lower()}", kind=kind, binding=current_binding,
        evidence_reference=digest(reference_characters[index]), evidence_digest=digest(digest_characters[index]),
        issued_at=NOW - timedelta(hours=1), expires_at=NOW + timedelta(days=2),
    ) for index, kind in enumerate(DeliveryAssertionKind))


def test_complete_evidence_is_signed_but_never_ready_or_authorized():
    current_binding, signer = binding(), authority()
    result = assess_delivery_readiness(delivery_id="handoff-1", binding=current_binding,
                                      assertions=assertions(current_binding, signer), at=NOW, authority=signer)

    assert result.status is DeliveryReadinessStatus.INDEPENDENT_APPROVAL_REQUIRED
    assert result.reasons == (DeliveryReadinessReason.INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED,)
    assert result.posture == "NO_DELIVERY_AUTHORIZATION"
    assert signer.verifies_evidence(result)
    record = result.to_record()
    assert record["digest"] == result.digest
    assert type(record["signature"]) is str
    assert "payload" not in str(record).lower()
    assert "export" not in str(record).lower()
    assert "ready" not in {status.value.lower() for status in DeliveryReadinessStatus}


def test_missing_assertion_and_absent_authority_fail_closed():
    current_binding, signer = binding(), authority()
    result = assess_delivery_readiness(delivery_id="handoff-2", binding=current_binding,
                                      assertions=assertions(current_binding, signer)[:-1], at=NOW, authority=None)

    assert result.status is DeliveryReadinessStatus.QUARANTINED
    assert DeliveryReadinessReason.MISSING_REQUIRED_ASSERTIONS in result.reasons
    assert DeliveryReadinessReason.ASSERTION_UNVERIFIED in result.reasons
    assert result.signature is None


def test_tampering_binding_or_assertion_is_quarantined_and_record_rejects():
    current_binding, signer = binding(), authority()
    signed = assertions(current_binding, signer)
    tampered = replace(signed[0], evidence_digest=digest("9"))
    result = assess_delivery_readiness(delivery_id="handoff-3", binding=current_binding,
                                      assertions=(tampered, *signed[1:]), at=NOW, authority=signer)
    assert result.status is DeliveryReadinessStatus.QUARANTINED
    assert DeliveryReadinessReason.ASSERTION_UNVERIFIED in result.reasons

    complete = assess_delivery_readiness(delivery_id="handoff-4", binding=current_binding,
                                         assertions=signed, at=NOW, authority=signer)
    record = complete.to_record()
    record["binding"]["purpose_code"] = "other-purpose"
    with pytest.raises(DeliveryGovernanceError, match="Invalid delivery governance input"):
        type(complete).from_record(record, authority=signer)


def test_expired_future_and_mismatched_inputs_are_quarantined():
    current_binding, signer = binding(), authority()
    signed = list(assertions(current_binding, signer))
    signed[0] = signer.issue_assertion(
        assertion_id=signed[0].assertion_id, kind=signed[0].kind, binding=current_binding,
        evidence_reference=signed[0].evidence_reference, evidence_digest=signed[0].evidence_digest,
        issued_at=NOW - timedelta(days=2), expires_at=NOW - timedelta(seconds=1),
    )
    signed[1] = signer.issue_assertion(
        assertion_id=signed[1].assertion_id, kind=signed[1].kind, binding=current_binding,
        evidence_reference=signed[1].evidence_reference, evidence_digest=signed[1].evidence_digest,
        issued_at=NOW + timedelta(seconds=1), expires_at=NOW + timedelta(days=2),
    )
    other_binding = replace(current_binding, purpose_code="evaluation")
    signed[2] = signer.issue_assertion(
        assertion_id=signed[2].assertion_id, kind=signed[2].kind, binding=other_binding,
        evidence_reference=signed[2].evidence_reference, evidence_digest=signed[2].evidence_digest,
        issued_at=NOW - timedelta(hours=1), expires_at=NOW + timedelta(days=2),
    )
    result = assess_delivery_readiness(delivery_id="handoff-5", binding=current_binding,
                                      assertions=signed, at=NOW, authority=signer)

    assert result.status is DeliveryReadinessStatus.QUARANTINED
    assert DeliveryReadinessReason.ASSERTION_EXPIRED in result.reasons
    assert DeliveryReadinessReason.ASSERTION_TIME_INVALID in result.reasons
    assert DeliveryReadinessReason.ASSERTION_BINDING_MISMATCH in result.reasons


def test_records_are_deterministic_bounded_and_do_not_accept_raw_values():
    current_binding, signer = binding(), authority()
    result = assess_delivery_readiness(delivery_id="handoff-6", binding=current_binding,
                                      assertions=reversed(assertions(current_binding, signer)), at=NOW, authority=signer)
    restored = type(result).from_record(result.to_record(), authority=signer)
    assert restored.digest == result.digest
    assert [item.kind for item in restored.assertions] == sorted(DeliveryAssertionKind, key=lambda item: item.value)
    with_extra = result.to_record()
    with_extra["assertions"][0]["raw_payload"] = "must-not-be-accepted"
    with pytest.raises(DeliveryGovernanceError):
        type(result).from_record(with_extra, authority=signer)

    with pytest.raises(DeliveryGovernanceError):
        DeliveryBinding(candidate_artifact_digest=digest("a"), policy_digest=digest("b"), rights_digest="c" * 64,
                        recipient_reference="actual-person@example.com", purpose_code="model-training",
                        contract_reference=digest("e"), contract_digest=digest("f"),
                        candidate_expires_at=NOW + timedelta(days=1))
    with pytest.raises(DeliveryGovernanceError):
        assess_delivery_readiness(delivery_id="handoff-7", binding=current_binding,
                                  assertions=[*assertions(current_binding, signer)] * 9, at=NOW, authority=signer)
