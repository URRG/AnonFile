from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.evaluation_harness import (
    AnnotatedCase,
    AnnotatedCorpus,
    AnnotatedFinding,
    EvaluationHarnessError,
    PredictionCase,
    PredictionSet,
    ScoringBinding,
    score,
)


NOW = datetime(2030, 1, 1, tzinfo=UTC)


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


def finding(category: str, letter: str) -> AnnotatedFinding:
    return AnnotatedFinding(digest(letter), category)


def corpus() -> AnnotatedCorpus:
    return AnnotatedCorpus.create(
        corpus_id="synthetic-corpus", corpus_version="v1", source_manifest_digest=digest("a"),
        annotation_protocol_digest=digest("b"), provenance_digest=digest("c"),
        assessed_categories=("PII", "PAYMENT"),
        cases=(AnnotatedCase("case-a", (finding("PAYMENT", "e"), finding("PII", "d"))),
               AnnotatedCase("case-b", (finding("PII", "f"),))),
    )


def prediction_set(value: AnnotatedCorpus, **changes) -> PredictionSet:
    values = {
        "corpus_digest": value.digest, "output_digest": digest("1"),
        "cases": (PredictionCase("case-a", (finding("PAYMENT", "0"), finding("PII", "d"),
                                             finding("PII", "d"))),
                  PredictionCase("case-b", ())),
    }
    values.update(changes)
    return PredictionSet.create(**values)


def binding(value: AnnotatedCorpus, predictions: PredictionSet, **changes) -> ScoringBinding:
    values = {
        "evaluator_id": "protected-reference-evaluator", "evaluator_version": "v1",
        "evaluator_config_digest": digest("2"), "detector_id": "rules-v1", "detector_version": "v1",
        "detector_config_digest": digest("3"), "taxonomy_mapping_digest": digest("4"),
        "corpus_digest": value.digest, "prediction_set_digest": predictions.digest,
    }
    values.update(changes)
    return ScoringBinding(**values)


def test_scores_exact_matches_per_assessed_family_and_preserves_duplicate_predictions():
    gold = corpus()
    predictions = prediction_set(gold)
    result = score(corpus=gold, predictions=predictions, binding=binding(gold, predictions), evaluated_at=NOW)
    metrics = {item.category: item for item in result.metrics}
    assert (metrics["PII"].true_positives, metrics["PII"].false_positives, metrics["PII"].false_negatives) == (1, 1, 1)
    assert metrics["PII"].precision_ppm == 500_000
    assert metrics["PII"].recall_ppm == 500_000
    assert metrics["PII"].f1_ppm == 500_000
    assert (metrics["PAYMENT"].true_positives, metrics["PAYMENT"].false_positives, metrics["PAYMENT"].false_negatives) == (0, 1, 1)
    assert metrics["PAYMENT"].f1_ppm == 0
    assert result.to_record()["posture"] == "OBSERVATIONAL_ONLY"
    assert "NO_RELEASE_AUTHORIZATION" in result.limitations


@pytest.mark.parametrize("builder", [
    lambda: AnnotatedCase("case-a", (finding("PII", "d"), finding("PII", "d"))),
    lambda: AnnotatedCorpus.create(corpus_id="synthetic-corpus", corpus_version="v1", source_manifest_digest=digest("a"),
                                    annotation_protocol_digest=digest("b"), provenance_digest=digest("c"),
                                    assessed_categories=("PII",),
                                    cases=(AnnotatedCase("case-a", (finding("PII", "d"),)),
                                           AnnotatedCase("case-a", (finding("PII", "e"),)))),
    lambda: PredictionSet.create(corpus_digest=digest("a"), output_digest=digest("b"),
                                 cases=(PredictionCase("case-a", ()), PredictionCase("case-a", ()))),
])
def test_rejects_duplicate_annotation_case_or_prediction_case(builder):
    with pytest.raises(EvaluationHarnessError):
        builder()


def test_rejects_malformed_or_out_of_scope_inputs_without_echoing_them():
    secret = "alice@example.test"
    with pytest.raises(EvaluationHarnessError) as error:
        AnnotatedFinding(secret, "PII")
    assert secret not in str(error.value)
    gold = corpus()
    invalid = PredictionSet.create(corpus_digest=gold.digest, output_digest=digest("1"),
                                   cases=(PredictionCase("case-a", (finding("CREDENTIAL", "d"),)),
                                          PredictionCase("case-b", ())))
    with pytest.raises(EvaluationHarnessError):
        score(corpus=gold, predictions=invalid, binding=binding(gold, invalid), evaluated_at=NOW)


def test_provenance_and_digest_mismatches_are_fail_closed():
    gold = corpus()
    predictions = prediction_set(gold)
    with pytest.raises(EvaluationHarnessError):
        score(corpus=gold, predictions=predictions,
              binding=binding(gold, predictions, detector_config_digest=digest("9"),
                              prediction_set_digest=digest("8")), evaluated_at=NOW)
    incomplete = prediction_set(gold, cases=(PredictionCase("case-a", ()),))
    with pytest.raises(EvaluationHarnessError):
        score(corpus=gold, predictions=incomplete, binding=binding(gold, incomplete), evaluated_at=NOW)


def test_score_digest_binds_detector_configuration_and_corpus_provenance():
    gold = corpus()
    predictions = prediction_set(gold)
    baseline = score(corpus=gold, predictions=predictions, binding=binding(gold, predictions), evaluated_at=NOW)
    revised = score(corpus=gold, predictions=predictions,
                    binding=binding(gold, predictions, detector_config_digest=digest("8")), evaluated_at=NOW)
    assert baseline.digest != revised.digest
    assert digest("a") not in repr(gold)


def test_persisted_score_recomputes_derived_metrics_and_evidence_digest():
    gold = corpus()
    predictions = prediction_set(gold)
    result = score(corpus=gold, predictions=predictions, binding=binding(gold, predictions), evaluated_at=NOW)
    assert type(result).from_record(result.to_record()) == result
    forged = result.to_record()
    forged["metrics"][0]["f1_ppm"] = 1_000_000
    with pytest.raises(EvaluationHarnessError):
        type(result).from_record(forged)
