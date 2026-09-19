from __future__ import annotations

import pytest

from app.residual_eval import (
    CandidateMetadata,
    DetectorIdentity,
    DetectorResult,
    EvaluationError,
    EvaluationProfile,
    EvidenceStatus,
    candidate_digest,
    candidate_schema_digest,
    evaluate_candidate,
)


RECORDS = [{"account": "alias-1", "status": "active"}, {"account": "alias-2", "status": "inactive"}]
CONFIG = "sha256:" + "c" * 64


def profile(**overrides):
    value = {"profile_id": "external-release", "version": "v1", "required_categories": ["PII", "PAYMENT"]}
    value.update(overrides)
    return EvaluationProfile.create(**value)


def metadata(candidate=RECORDS, **overrides):
    value = {
        "artifact_digest": candidate_digest(candidate), "media_type": "application/json",
        "expected_record_count": len(candidate), "expected_schema_digest": candidate_schema_digest(candidate),
    }
    value.update(overrides)
    return CandidateMetadata(**value)


def detector(result):
    def evaluate(_candidate):
        return result
    return evaluate


def test_zero_findings_never_claims_pass_and_binds_exact_candidate_and_config():
    report = evaluate_candidate(
        RECORDS, metadata=metadata(), detector=detector(DetectorResult({}, scanned_units=2)),
        detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile(),
    )
    assert report.evidence_status is EvidenceStatus.INSUFFICIENT_EVIDENCE
    assert report.candidate_digest == candidate_digest(RECORDS)
    assert report.detector_config_digest == CONFIG
    assert report.to_record()["residual_counts"] == {"PAYMENT": 0, "PII": 0}
    assert "alias-1" not in str(report.to_record())
    assert report.digest.startswith("sha256:")


def test_residuals_abstentions_coverage_and_utility_failure_fail_profile():
    residual = evaluate_candidate(
        RECORDS, metadata=metadata(), detector=detector(DetectorResult({"PII": 1}, scanned_units=2)),
        detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile(),
    )
    assert residual.evidence_status is EvidenceStatus.FAILS_PROFILE
    low_coverage = evaluate_candidate(
        RECORDS, metadata=metadata(), detector=detector(DetectorResult({}, scanned_units=2, abstained_units=1)),
        detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile(),
    )
    assert low_coverage.coverage_percent == 50
    assert low_coverage.evidence_status is EvidenceStatus.FAILS_PROFILE
    structural = evaluate_candidate(
        RECORDS, metadata=metadata(expected_record_count=1), detector=detector(DetectorResult({}, scanned_units=2)),
        detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile(),
    )
    assert structural.evidence_status is EvidenceStatus.FAILS_PROFILE
    assert any(not check.passed for check in structural.utility_checks)


@pytest.mark.parametrize("change", [
    {"media_type": "application/json", "expected_schema_digest": None},
    {"media_type": "text/plain", "expected_schema_digest": "sha256:" + "a" * 64},
    {"expected_record_count": True},
])
def test_metadata_rejects_invalid_or_ambiguous_candidate_contract(change):
    with pytest.raises(EvaluationError):
        metadata(**change)


def test_exact_candidate_digest_mismatch_is_rejected_before_detector_execution():
    calls = 0
    def never(candidate):
        nonlocal calls
        calls += 1
        return DetectorResult({}, scanned_units=2)
    with pytest.raises(EvaluationError, match="integrity"):
        evaluate_candidate(RECORDS, metadata=metadata(artifact_digest="sha256:" + "0" * 64), detector=never,
                           detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile())
    assert calls == 0


def test_detector_errors_and_nonaggregate_outputs_never_leak_candidate_values():
    def broken(_candidate):
        raise RuntimeError("candidate says alias-1")
    with pytest.raises(EvaluationError) as error:
        evaluate_candidate(RECORDS, metadata=metadata(), detector=broken,
                           detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile())
    assert "alias-1" not in str(error.value)
    with pytest.raises(EvaluationError):
        evaluate_candidate(RECORDS, metadata=metadata(), detector=lambda _: {"snippet": "alias-1"},
                           detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile())


@pytest.mark.parametrize("result", [
    DetectorResult({}, scanned_units=3),
    DetectorResult({}, scanned_units=1, abstained_units=2),
])
def test_detector_cannot_claim_impossible_coverage(result):
    with pytest.raises(EvaluationError, match="Invalid detector result"):
        evaluate_candidate(RECORDS, metadata=metadata(), detector=detector(result),
                           detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile())


def test_detector_result_and_profile_reject_bad_categories_duplicates_and_boolean_counts():
    with pytest.raises(EvaluationError):
        DetectorResult({"PII": True}, scanned_units=1)
    with pytest.raises(EvaluationError):
        DetectorResult({"PII*": 1}, scanned_units=1)
    with pytest.raises(EvaluationError):
        EvaluationProfile.create(profile_id="p", version="v1", required_categories=["PII", "PII"])
    with pytest.raises(EvaluationError):
        EvaluationProfile.create(profile_id="p", version="v1", required_categories="PII")
    with pytest.raises(EvaluationError):
        EvaluationProfile(profile_id="p", version="v1", required_categories="PII")
    with pytest.raises(EvaluationError):
        EvaluationProfile(profile_id="p", version="v1", required_categories=("PII", "PII"))


def test_report_digest_changes_on_detector_config_but_contains_no_values():
    first = evaluate_candidate(RECORDS, metadata=metadata(), detector=detector(DetectorResult({}, scanned_units=2)),
                               detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile())
    second = evaluate_candidate(RECORDS, metadata=metadata(), detector=detector(DetectorResult({}, scanned_units=2)),
                                detector_identity=DetectorIdentity("rules-evaluator", "sha256:" + "d" * 64), profile=profile())
    assert first.digest != second.digest
    serialized = str(second.to_record())
    assert "alias-1" not in serialized and "active" not in serialized


def test_text_candidate_is_evaluable_without_a_source_or_schema():
    candidate = "synthetic transformed text"
    item = CandidateMetadata(artifact_digest=candidate_digest(candidate), media_type="text/plain", expected_record_count=1)
    result = evaluate_candidate(candidate, metadata=item, detector=detector(DetectorResult({}, scanned_units=1)),
                                detector_identity=DetectorIdentity("rules-evaluator", CONFIG), profile=profile())
    assert result.evidence_status is EvidenceStatus.INSUFFICIENT_EVIDENCE
