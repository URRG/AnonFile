from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from app.benchmark_evidence import (
    BenchmarkBinding,
    BenchmarkEvidence,
    BenchmarkEvidenceError,
    CategoryMetrics,
    Coverage,
    EvidencePosture,
)


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


def binding(**changes):
    values = {
        "benchmark_dataset_id": "support-export-gold", "benchmark_dataset_version": "2026.01",
        "benchmark_dataset_digest": digest("a"), "annotation_protocol_digest": digest("b"),
        "model_id": "rules-engine", "model_version": "v2", "model_digest": digest("c"),
        "detector_id": "residual-detector", "detector_version": "v4", "detector_config_digest": digest("d"),
        "taxonomy_mapping_digest": digest("e"),
    }
    values.update(changes)
    return BenchmarkBinding(**values)


def evidence(**changes):
    values = {
        "evidence_id": "benchmark-run-01", "binding": binding(),
        "metrics": (CategoryMetrics("PAYMENT", 9, 1, 1), CategoryMetrics("PII", 18, 2, 0)),
        "coverage": Coverage(eligible_units=100, evaluated_units=100, abstained_units=0),
        "limitations": ("NO_RELEASE_AUTHORIZATION", "SYNTHETIC_BENCHMARK_ONLY"),
        "evaluated_at": datetime(2030, 1, 1, tzinfo=UTC),
    }
    values.update(changes)
    return BenchmarkEvidence.create(**values)


def test_record_binds_dataset_model_detector_versions_and_is_canonical():
    first = evidence()
    reordered = evidence(metrics=(CategoryMetrics("PII", 18, 2, 0), CategoryMetrics("PAYMENT", 9, 1, 1)),
                         limitations=("SYNTHETIC_BENCHMARK_ONLY", "NO_RELEASE_AUTHORIZATION"))
    assert first.digest == reordered.digest
    record = first.to_record()
    assert record["binding"]["benchmark_dataset_version"] == "2026.01"
    assert record["binding"]["detector_config_digest"] == digest("d")
    assert record["binding"]["taxonomy_mapping_digest"] == digest("e")
    assert record["coverage_ppm"] == 1_000_000
    assert record["metrics"][0]["precision_ppm"] is not None
    assert BenchmarkEvidence.from_record(record) == first


def test_high_scores_are_observational_only_never_release_authorization():
    item = evidence(metrics=(CategoryMetrics("PII", 100, 0, 0),))
    assert item.posture is EvidencePosture.OBSERVATIONAL_ONLY
    record = item.to_record()
    assert record["posture"] == "OBSERVATIONAL_ONLY"
    assert "APPROVED" not in str(record) and "RELEASE_READY" not in str(record)


def test_coverage_excludes_abstentions_and_is_bounded():
    covered = Coverage(eligible_units=10, evaluated_units=9, abstained_units=2)
    assert covered.assessed_units == 7
    assert covered.coverage_ppm == 700_000
    for args in ((10, 11, 0), (10, 5, 6), (True, 1, 0)):
        with pytest.raises(BenchmarkEvidenceError):
            Coverage(*args)


@pytest.mark.parametrize("mutate", [
    lambda r: r["binding"].__setitem__("model_version", "v9"),
    lambda r: r["metrics"][0].__setitem__("precision_ppm", 0),
    lambda r: r.__setitem__("coverage_ppm", 1),
    lambda r: r.__setitem__("digest", digest("f")),
])
def test_persisted_tampering_is_detected(mutate):
    record = evidence().to_record()
    mutate(record)
    with pytest.raises(BenchmarkEvidenceError):
        BenchmarkEvidence.from_record(record)


@pytest.mark.parametrize("changes", [
    {"limitations": ("SYNTHETIC_BENCHMARK_ONLY",)},
    {"limitations": ("NO_RELEASE_AUTHORIZATION", "NO_RELEASE_AUTHORIZATION")},
    {"metrics": (CategoryMetrics("PII", 1, 0, 0), CategoryMetrics("PII", 0, 0, 1))},
])
def test_evidence_rejects_ambiguous_or_unsafe_metadata(changes):
    with pytest.raises(BenchmarkEvidenceError):
        evidence(**changes)

    with pytest.raises(BenchmarkEvidenceError):
        binding(detector_id="Detector Contains Source Text")


def test_errors_and_repr_do_not_echo_untrusted_input():
    secret = "customer-secret@example.test"
    with pytest.raises(BenchmarkEvidenceError) as error:
        binding(benchmark_dataset_id=secret)
    assert secret not in str(error.value)
    assert secret not in repr(evidence())


def test_version_or_detector_change_changes_immutable_evidence_digest():
    base = evidence()
    updated_model = evidence(binding=binding(model_version="v3"))
    updated_detector = evidence(binding=binding(detector_config_digest=digest("e")))
    updated_mapping = evidence(binding=binding(taxonomy_mapping_digest=digest("f")))
    assert len({base.digest, updated_model.digest, updated_detector.digest, updated_mapping.digest}) == 4


def test_timezone_normalizes_to_the_same_canonical_evaluation_time():
    utc = evidence(evaluated_at=datetime(2030, 1, 1, 0, 0, tzinfo=UTC))
    offset = evidence(evaluated_at=datetime(2030, 1, 1, 5, 30, tzinfo=timezone(timedelta(hours=5, minutes=30))))
    assert utc.digest == offset.digest
    with pytest.raises(BenchmarkEvidenceError):
        evidence(evaluated_at=datetime(2030, 1, 1))


def test_non_taxonomy_metrics_and_boolean_derived_scores_are_rejected():
    with pytest.raises(BenchmarkEvidenceError):
        evidence(metrics=(CategoryMetrics("UNMAPPED_LABEL", 1, 0, 0),))
    item = evidence(metrics=(CategoryMetrics("PII", 1, 999_999, 0),),
                    coverage=Coverage(eligible_units=1_000_000, evaluated_units=1, abstained_units=0))
    record = item.to_record()
    assert record["metrics"][0]["precision_ppm"] == 1 and record["coverage_ppm"] == 1
    record["metrics"][0]["precision_ppm"] = True
    with pytest.raises(BenchmarkEvidenceError):
        BenchmarkEvidence.from_record(record)
    record = item.to_record()
    record["coverage_ppm"] = True
    with pytest.raises(BenchmarkEvidenceError):
        BenchmarkEvidence.from_record(record)
