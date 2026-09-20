from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from app.policies import TAXONOMY_CATEGORIES
from app.qualification import (CandidateBinding, CategoryMeasurement, CategoryThreshold,
                               EvaluationReport, QualificationCriteria, QualificationError,
                               QualificationOutcome, QualificationReason, qualify)


def digest(letter):
    return "sha256:" + letter * 64


RIGHTS = "f" * 64
NOW = datetime(2030, 1, 1, tzinfo=UTC)


def criteria(**changes):
    result = QualificationCriteria(tuple(CategoryThreshold(category, 0) for category in TAXONOMY_CATEGORIES), 3600)
    return replace(result, **changes)


def candidate(**changes):
    result = CandidateBinding(digest("a"), digest("c"), RIGHTS, "buyer-a", "model-training", NOW + timedelta(days=1))
    return replace(result, **changes)


def report(**changes):
    current = candidate()
    result = EvaluationReport(digest("e"), current.artifact_digest, current.policy_digest, current.rights_digest,
                              current.buyer, current.purpose, NOW,
                              tuple(CategoryMeasurement(category, 0, 100) for category in TAXONOMY_CATEGORIES))
    return replace(result, **changes)


def decision(**changes):
    arguments = {"qualification_id": "qualification-1", "candidate": candidate(), "report": report(), "criteria": criteria(), "at": NOW}
    arguments.update(changes)
    return qualify(**arguments)


def test_within_threshold_evidence_never_becomes_approved_or_exportable():
    result = decision()
    assert result.outcome is QualificationOutcome.INSUFFICIENT_EVIDENCE
    assert result.reasons == (QualificationReason.INDEPENDENT_APPROVAL_REQUIRED,)
    snapshot = result.snapshot()
    assert snapshot["candidate_artifact_digest"] == digest("a")
    assert "APPROVED" not in repr(result) and "export" not in repr(result).lower()


@pytest.mark.parametrize("field", ["candidate_artifact_digest", "policy_digest", "rights_digest", "buyer", "purpose"])
def test_mismatched_report_binding_quarantines(field):
    changed = {field: "e" * 64 if field == "rights_digest" else "buyer-b" if field == "buyer" else "evaluation" if field == "purpose" else digest("b")}
    result = decision(report=replace(report(), **changed))
    assert result.outcome is QualificationOutcome.QUARANTINED
    assert result.reasons == (QualificationReason.BINDING_MISMATCH,)


def test_missing_or_empty_category_evidence_is_insufficient_not_success():
    incomplete = report(measurements=tuple(CategoryMeasurement(category, 0, 1) for category in sorted(TAXONOMY_CATEGORIES)[:-1]))
    missing = decision(report=incomplete)
    assert missing.outcome is QualificationOutcome.INSUFFICIENT_EVIDENCE
    assert missing.reasons == (QualificationReason.MISSING_CATEGORY_MEASUREMENT,)
    empty = decision(report=report(measurements=tuple(CategoryMeasurement(category, 0, 0) for category in TAXONOMY_CATEGORIES)))
    assert empty.outcome is QualificationOutcome.INSUFFICIENT_EVIDENCE
    assert empty.reasons == (QualificationReason.EMPTY_CATEGORY_SAMPLE,)


def test_over_threshold_residual_quarantines():
    measurements = tuple(CategoryMeasurement(category, 1 if category == "PII" else 0, 100) for category in TAXONOMY_CATEGORIES)
    result = decision(report=report(measurements=measurements))
    assert result.outcome is QualificationOutcome.QUARANTINED
    assert result.reasons == (QualificationReason.THRESHOLD_EXCEEDED,)


def test_known_threshold_violation_quarantines_even_when_other_categories_are_missing():
    measurements = (CategoryMeasurement("PII", 1, 100),)
    result = decision(report=report(measurements=measurements))
    assert result.outcome is QualificationOutcome.QUARANTINED
    assert result.reasons == (QualificationReason.MISSING_CATEGORY_MEASUREMENT,
                              QualificationReason.THRESHOLD_EXCEEDED)


def test_stale_future_and_expired_inputs_fail_closed():
    stale = decision(report=report(evaluated_at=NOW - timedelta(seconds=3601)))
    assert stale.outcome is QualificationOutcome.INSUFFICIENT_EVIDENCE
    assert stale.reasons == (QualificationReason.EVALUATION_STALE,)
    future = decision(report=report(evaluated_at=NOW + timedelta(seconds=1)))
    assert future.reasons == (QualificationReason.EVALUATION_TIME_INVALID,)
    expired = decision(candidate=candidate(expires_at=NOW))
    assert expired.outcome is QualificationOutcome.QUARANTINED
    assert expired.reasons == (QualificationReason.CANDIDATE_EXPIRED,)


def test_canonical_immutable_snapshot_detects_tampering_by_digest_change():
    original = decision()
    modified = decision(report=report(measurements=tuple(CategoryMeasurement(category, 0, 101) for category in TAXONOMY_CATEGORIES)))
    assert original.digest != modified.digest
    with pytest.raises((AttributeError, TypeError)):
        original.digest = digest("b")
    with pytest.raises(TypeError):
        original.snapshot()["outcome"] = "APPROVED"


def test_audit_event_is_metadata_only():
    event = decision().audit_event(sequence=1)
    assert set(event) == {"action", "object_id", "outcome", "qualification_digest", "sequence"}
    assert "buyer-a" not in str(event) and "model-training" not in str(event)


@pytest.mark.parametrize("bad", [
    lambda: CategoryThreshold("UNKNOWN", 0),
    lambda: CategoryThreshold("PII", True),
    lambda: QualificationCriteria((CategoryThreshold("PII", 0),), 1),
    lambda: CandidateBinding("not-a-digest", digest("c"), RIGHTS, "buyer-a", "model-training", NOW),
    lambda: EvaluationReport(digest("e"), digest("a"), digest("c"), RIGHTS, "Buyer-A", "model-training", NOW, ()),
    lambda: decision(qualification_id="bad space"),
])
def test_invalid_or_unsafe_input_has_fixed_error(bad):
    with pytest.raises(QualificationError) as error:
        bad()
    assert str(error.value) == "Invalid qualification input"
