"""Fail-closed policy tests for opaque, attested privacy evidence."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.privacy_evidence_policy import (
    AttestedPrivacyEvidence, EvidenceRequirement, PrivacyEvidenceAuthority,
    PrivacyEvidenceBinding, PrivacyEvidenceKind, PrivacyEvidenceOutcome,
    PrivacyEvidencePolicy, PrivacyEvidencePolicyError, PrivacyEvidenceReason,
    assess_privacy_evidence,
)


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
DIGESTS = ["sha256:" + char * 64 for char in "abcdef123456"]


def binding(method=DIGESTS[4]):
    return PrivacyEvidenceBinding(candidate_artifact_digest=DIGESTS[0], processing_policy_digest=DIGESTS[1],
                                  rights_digest="c" * 64, recipient_reference=DIGESTS[2],
                                  purpose_code="external-model-training", method_provenance_digest=method,
                                  candidate_expires_at=NOW + timedelta(days=2))


def authorities():
    return tuple(PrivacyEvidenceAuthority(key_id=f"issuer-{kind.value.lower()}", secret=bytes([index + 1]) * 32)
                 for index, kind in enumerate(PrivacyEvidenceKind))


def policy(method=DIGESTS[4]):
    thresholds = {
        PrivacyEvidenceKind.RESIDUAL_SCAN: 10,
        PrivacyEvidenceKind.DISCLOSURE_RISK: 5,
        PrivacyEvidenceKind.UTILITY: 900_000,
        PrivacyEvidenceKind.LINKAGE: 10_000,
        PrivacyEvidenceKind.BENCHMARK: 900_000,
    }
    signer_by_kind = dict(zip(PrivacyEvidenceKind, authorities(), strict=True))
    requirements = tuple(sorted((EvidenceRequirement(kind, signer_by_kind[kind].key_id, thresholds[kind])
                                 for kind in PrivacyEvidenceKind), key=lambda item: item.kind.value))
    return PrivacyEvidencePolicy(policy_id="privacy-evidence-v1", method_provenance_digest=method,
                                 max_evidence_age_seconds=3600, requirements=requirements), signer_by_kind


def evidence_set(current_binding=None, current_policy=None, signer_by_kind=None, values=None, measured_at=NOW):
    current_binding = current_binding or binding()
    if current_policy is None:
        current_policy, default_signers = policy(current_binding.method_provenance_digest)
        signer_by_kind = signer_by_kind or default_signers
    values = values or {
        PrivacyEvidenceKind.RESIDUAL_SCAN: 0, PrivacyEvidenceKind.DISCLOSURE_RISK: 10,
        PrivacyEvidenceKind.UTILITY: 950_000, PrivacyEvidenceKind.LINKAGE: 0,
        PrivacyEvidenceKind.BENCHMARK: 950_000,
    }
    return tuple(signer_by_kind[kind].issue(kind=kind, evidence_reference="evidence:v1:" + chr(65 + index) * 43,
                                              evidence_digest="sha256:" + chr(97 + index) * 64,
                                              binding=current_binding, policy=current_policy,
                                              observed_value=values[kind], measured_at=measured_at,
                                              expires_at=measured_at + timedelta(hours=2))
                 for index, kind in enumerate(PrivacyEvidenceKind))


def assess(evidence=None, current_binding=None, current_policy=None, signer_by_kind=None, at=NOW):
    current_binding = current_binding or binding()
    current_policy, default_signers = (current_policy, signer_by_kind) if current_policy else policy(current_binding.method_provenance_digest)
    signer_by_kind = signer_by_kind or default_signers
    evidence = evidence if evidence is not None else evidence_set(current_binding, current_policy, signer_by_kind)
    return assess_privacy_evidence(decision_id="evidence-decision", binding=current_binding, policy=current_policy,
                                   evidence=evidence, authorities=tuple(signer_by_kind.values()), at=at)


def test_complete_within_threshold_evidence_still_never_authorizes_release():
    decision = assess()
    assert decision.outcome is PrivacyEvidenceOutcome.INSUFFICIENT_EVIDENCE
    assert decision.reasons == (PrivacyEvidenceReason.INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED,)
    record = decision.to_record()
    assert record["posture"] == "NO_RELEASE_AUTHORIZATION"
    assert "ready" not in str(record).lower()
    assert "b'" not in repr(authorities()[0])


def test_tampered_unverified_and_mismatched_evidence_quarantine():
    current_binding = binding()
    current_policy, signer_by_kind = policy(current_binding.method_provenance_digest)
    evidence = list(evidence_set(current_binding, current_policy, signer_by_kind))
    evidence[0] = replace(evidence[0], observed_value=1)
    result = assess(tuple(evidence), current_binding, current_policy, signer_by_kind)
    assert result.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.EVIDENCE_UNVERIFIED in result.reasons
    foreign_binding = binding(DIGESTS[5])
    result = assess(evidence_set(foreign_binding, current_policy, signer_by_kind), current_binding, current_policy, signer_by_kind)
    assert result.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.BINDING_MISMATCH in result.reasons


@pytest.mark.parametrize(("field", "value"), [
    ("candidate_artifact_digest", DIGESTS[5]), ("processing_policy_digest", DIGESTS[3]),
    ("rights_digest", "d" * 64), ("recipient_reference", DIGESTS[5]),
    ("purpose_code", "another-purpose"), ("method_provenance_digest", DIGESTS[5]),
])
def test_every_candidate_policy_rights_recipient_purpose_and_method_binding_is_exact(field, value):
    current_binding = binding()
    current_policy, signer_by_kind = policy(current_binding.method_provenance_digest)
    result = assess(evidence_set(current_binding, current_policy, signer_by_kind),
                    replace(current_binding, **{field: value}), current_policy, signer_by_kind)
    assert result.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.BINDING_MISMATCH in result.reasons


def test_missing_stale_and_expired_evidence_are_insufficient_not_approved():
    current_binding = binding()
    current_policy, signer_by_kind = policy(current_binding.method_provenance_digest)
    all_evidence = evidence_set(current_binding, current_policy, signer_by_kind)
    missing = assess(all_evidence[:-1], current_binding, current_policy, signer_by_kind)
    assert missing.outcome is PrivacyEvidenceOutcome.INSUFFICIENT_EVIDENCE
    assert PrivacyEvidenceReason.MISSING_EVIDENCE in missing.reasons
    stale = assess(evidence_set(current_binding, current_policy, signer_by_kind, measured_at=NOW - timedelta(seconds=3_700)),
                   current_binding, current_policy, signer_by_kind)
    assert stale.outcome is PrivacyEvidenceOutcome.INSUFFICIENT_EVIDENCE
    assert PrivacyEvidenceReason.EVIDENCE_STALE in stale.reasons
    expired = assess(evidence_set(current_binding, current_policy, signer_by_kind, measured_at=NOW - timedelta(hours=3)),
                     current_binding, current_policy, signer_by_kind, at=NOW)
    assert expired.outcome is PrivacyEvidenceOutcome.INSUFFICIENT_EVIDENCE
    assert PrivacyEvidenceReason.EVIDENCE_EXPIRED in expired.reasons


@pytest.mark.parametrize(("kind", "value"), [
    (PrivacyEvidenceKind.RESIDUAL_SCAN, 11), (PrivacyEvidenceKind.DISCLOSURE_RISK, 4),
    (PrivacyEvidenceKind.UTILITY, 899_999), (PrivacyEvidenceKind.LINKAGE, 10_001),
    (PrivacyEvidenceKind.BENCHMARK, 899_999),
])
def test_each_threshold_violation_quarantines(kind, value):
    current_binding = binding()
    current_policy, signer_by_kind = policy(current_binding.method_provenance_digest)
    values = {PrivacyEvidenceKind.RESIDUAL_SCAN: 0, PrivacyEvidenceKind.DISCLOSURE_RISK: 10,
              PrivacyEvidenceKind.UTILITY: 950_000, PrivacyEvidenceKind.LINKAGE: 0,
              PrivacyEvidenceKind.BENCHMARK: 950_000}
    values[kind] = value
    result = assess(evidence_set(current_binding, current_policy, signer_by_kind, values),
                    current_binding, current_policy, signer_by_kind)
    assert result.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.THRESHOLD_EXCEEDED in result.reasons


def test_candidate_expiry_duplicate_and_missing_authority_fail_closed():
    current_binding = binding()
    current_policy, signer_by_kind = policy(current_binding.method_provenance_digest)
    evidence = evidence_set(current_binding, current_policy, signer_by_kind)
    candidate_expired = replace(current_binding, candidate_expires_at=NOW)
    result = assess(evidence, candidate_expired, current_policy, signer_by_kind)
    assert result.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.CANDIDATE_EXPIRED in result.reasons
    duplicate = assess((*evidence, evidence[0]), current_binding, current_policy, signer_by_kind)
    assert duplicate.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.DUPLICATE_EVIDENCE_KIND in duplicate.reasons
    result = assess_privacy_evidence(decision_id="no-authority", binding=current_binding, policy=current_policy,
                                     evidence=evidence, authorities=(), at=NOW)
    assert result.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.EVIDENCE_UNVERIFIED in result.reasons


def test_policy_requires_complete_unique_requirements_and_source_safe_inputs():
    signer = PrivacyEvidenceAuthority(key_id="issuer", secret=b"x" * 32)
    with pytest.raises(PrivacyEvidencePolicyError):
        PrivacyEvidencePolicy(policy_id="policy", method_provenance_digest=DIGESTS[0], max_evidence_age_seconds=1,
                              requirements=(EvidenceRequirement(PrivacyEvidenceKind.UTILITY, signer.key_id, 1),))
    with pytest.raises(PrivacyEvidencePolicyError):
        PrivacyEvidenceBinding(candidate_artifact_digest=DIGESTS[0], processing_policy_digest=DIGESTS[1],
                               rights_digest="c" * 64, recipient_reference="recipient-name",
                               purpose_code="training", method_provenance_digest=DIGESTS[2],
                               candidate_expires_at=NOW)
