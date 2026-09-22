"""M17 fixed-profile benchmark adapter regressions."""
from datetime import UTC, datetime

import pytest

from app.benchmark_evidence import CategoryMetrics
from app.benchmark_evidence_profile import (BenchmarkEvidenceAssessment, BenchmarkEvidenceProfile,
                                             BenchmarkEvidenceProfileError)
from app.evaluation_harness import ScoredEvaluation, ScoringBinding
from app.evaluator_authority import EvaluatorAuthority
from app.policies import TAXONOMY_CATEGORIES


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


def authority() -> EvaluatorAuthority:
    return EvaluatorAuthority("evaluator", "tenant-a", "benchmark-worker", "v1", digest("a"),
                              frozenset({digest("b")}), b"k" * 32)


def profile(**changes) -> BenchmarkEvidenceProfile:
    values = {"tenant": "tenant-a", "evaluator_subject": "evaluator", "evaluator_id": "benchmark-worker",
              "evaluator_version": "v1", "evaluator_config_digest": digest("a"), "corpus_digest": digest("b"),
              "detector_id": "rules-v1", "detector_version": "v1", "detector_config_digest": digest("c"),
              "taxonomy_mapping_digest": digest("d"), "required_categories": tuple(sorted(TAXONOMY_CATEGORIES)),
              "minimum_category_reference_count": 2}
    values.update(changes)
    return BenchmarkEvidenceProfile(**values)


def report(**changes) -> ScoredEvaluation:
    values = {"binding": ScoringBinding("benchmark-worker", "v1", digest("a"), "rules-v1", "v1", digest("c"),
                                         digest("d"), digest("b"), digest("e")),
              "metrics": tuple(CategoryMetrics(category, 8 if category != "PAYMENT" else 3, 0,
                                                 2 if category == "PAYMENT" else 0)
                               for category in sorted(TAXONOMY_CATEGORIES)),
              "evaluated_at": datetime(2030, 1, 1, tzinfo=UTC)}
    values.update(changes)
    return ScoredEvaluation(**values)


def test_fixed_full_taxonomy_uses_minimum_recall_not_the_best_category():
    item = report()
    result = BenchmarkEvidenceAssessment.from_profile(profile=profile(), report=item, authority=authority(),
        evaluator_subject="evaluator", evaluator_authority_id=authority().authority_id)
    assert result.conservative_recall_ppm == 600_000
    assert result.source_report_digest == item.digest and result.profile_digest == profile().digest
    assert BenchmarkEvidenceAssessment.from_record(result.to_record()) == result


def test_partial_category_profile_partial_report_and_low_coverage_fail_closed():
    with pytest.raises(BenchmarkEvidenceProfileError):
        profile(required_categories=("PII",))
    with pytest.raises(BenchmarkEvidenceProfileError):
        profile().observe(report=report(metrics=(CategoryMetrics("PII", 8, 0, 0),)), authority=authority(),
                          evaluator_subject="evaluator", evaluator_authority_id=authority().authority_id)
    metrics = list(report().metrics); metrics[0] = CategoryMetrics(metrics[0].category, 1, 0, 0)
    with pytest.raises(BenchmarkEvidenceProfileError):
        profile().observe(report=report(metrics=tuple(metrics)), authority=authority(), evaluator_subject="evaluator",
                          evaluator_authority_id=authority().authority_id)
