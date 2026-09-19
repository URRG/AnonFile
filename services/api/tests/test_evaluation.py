import json
from pathlib import Path

import pytest

from app.evaluate import main
from app.evaluation import (Annotation, EvaluationError, GoldDocument,
                            baseline_predictions, evaluate, parse_gold,
                            parse_predictions, read_jsonl)

FIXTURES = Path(__file__).parent / "fixtures" / "evaluation"


def fixture_inputs():
    gold = parse_gold(read_jsonl(FIXTURES / "synthetic-gold.jsonl")[0])
    predictions = parse_predictions(read_jsonl(FIXTURES / "synthetic-predictions.jsonl")[0], gold)
    return gold, predictions


def test_independent_synthetic_expected_metrics():
    report = evaluate(*fixture_inputs())
    assert report["documents_evaluated"] == 4
    assert report["documents_with_gold_annotations"] == 3
    assert report["exact"]["corpus"] == {
        "true_positives": 1, "false_positives": 2, "false_negatives": 2,
        "gold_annotations": 3, "predicted_annotations": 3,
        "precision": 1 / 3, "recall": 1 / 3, "f1": 1 / 3,
    }
    assert report["same_type_overlap"]["corpus"]["recall"] == 2 / 3
    assert report["exact"]["missed_document_rate"] == 2 / 3
    assert report["same_type_overlap"]["missed_document_rate"] == 1 / 3
    assert report["exact"]["per_entity"]["PERSON_NAME"]["false_negatives"] == 1
    assert report["exact"]["per_entity"]["EMAIL"]["false_negatives"] == 1
    assert report["qualification"] == "NOT_QUALIFIED"
    assert report["output_residual_disclosure"] == "NOT_EVALUATED"


@pytest.mark.parametrize("gold", [(), (GoldDocument("secret-id", "benign", ()),)])
def test_no_gold_does_not_fabricate_perfect_scores(gold):
    report = evaluate(gold, {doc.id: () for doc in gold})
    assert report["evidence_status"] == "INSUFFICIENT_EVIDENCE"
    for matching in ("exact", "same_type_overlap"):
        assert report[matching]["corpus"]["recall"] is None
        assert report[matching]["corpus"]["precision"] is None
        assert report[matching]["corpus"]["f1"] is None
        assert report[matching]["missed_document_rate"] is None


def test_zero_predictions_has_zero_recall_but_undefined_precision():
    gold = (GoldDocument("a", "Ada", (Annotation(0, 3, "PERSON_NAME"),)),)
    report = evaluate(gold, {"a": ()})["exact"]["corpus"]
    assert report["recall"] == 0
    assert report["precision"] is None
    assert report["f1"] is None


def test_duplicate_predictions_do_not_inflate_recall():
    annotation = Annotation(0, 3, "PERSON_NAME")
    report = evaluate((GoldDocument("a", "Ada", (annotation,)),), {"a": (annotation, annotation)})
    for matching in ("exact", "same_type_overlap"):
        assert report[matching]["corpus"]["true_positives"] == 1
        assert report[matching]["corpus"]["false_positives"] == 1
        assert report[matching]["corpus"]["recall"] == 1


def test_overlap_requires_positive_intersection_and_same_label():
    gold = (GoldDocument("a", "abcdef", (Annotation(0, 3, "PERSON_NAME"),)),)
    report = evaluate(gold, {"a": (Annotation(3, 6, "PERSON_NAME"), Annotation(0, 3, "EMAIL"))})
    assert report["same_type_overlap"]["corpus"]["true_positives"] == 0


def test_overlap_uses_maximum_matching_not_greedy():
    gold = (GoldDocument("a", "0123456789", (Annotation(0, 5, "PERSON_NAME"), Annotation(5, 10, "PERSON_NAME"))),)
    predictions = {"a": (Annotation(0, 10, "PERSON_NAME"), Annotation(1, 2, "PERSON_NAME"))}
    report = evaluate(gold, predictions)
    assert report["same_type_overlap"]["corpus"]["true_positives"] == 2
    assert report["exact"]["corpus"]["true_positives"] == 0


@pytest.mark.parametrize("rows", [[], [{"id": "extra", "annotations": []}],
    [{"id": "a", "annotations": []}, {"id": "a", "annotations": []}],
    [{"id": "a", "annotations": [], "text": "private"}]])
def test_missing_extra_duplicate_prediction_documents_fail(rows):
    with pytest.raises(EvaluationError):
        parse_predictions(rows, (GoldDocument("a", "abc", ()),))


@pytest.mark.parametrize("annotation", [
    {"start": -1, "end": 1, "entity_type": "EMAIL"},
    {"start": 0, "end": 4, "entity_type": "EMAIL"},
    {"start": 1, "end": 1, "entity_type": "EMAIL"},
    {"start": True, "end": 2, "entity_type": "EMAIL"},
    {"start": 0, "end": 2.0, "entity_type": "EMAIL"},
    {"start": 0, "end": 2, "entity_type": "SECRET_SOURCE_VALUE"},
    {"start": 0, "end": 2, "entity_type": ["EMAIL"]},
    {"start": 0, "end": 2, "entity_type": "EMAIL", "raw": "secret"},
])
def test_bad_annotations_fail_without_echo(annotation):
    with pytest.raises(EvaluationError) as error:
        parse_gold([{"id": "private-id", "text": "abc", "annotations": [annotation]}])
    assert str(error.value) == "Invalid evaluation input; no report was produced."


def test_duplicate_gold_document_and_annotation_rejected():
    row = {"id": "a", "text": "Ada", "annotations": [{"start": 0, "end": 3, "entity_type": "PERSON_NAME"}]}
    with pytest.raises(EvaluationError):
        parse_gold([row, row])
    row["annotations"] *= 2
    with pytest.raises(EvaluationError):
        parse_gold([row])


def test_group_spanning_splits_is_rejected():
    rows = [{"id": str(i), "text": "abc", "annotations": [], "group_id": "same-person", "split": split}
            for i, split in enumerate(["train", "test"])]
    with pytest.raises(EvaluationError):
        parse_gold(rows)


@pytest.mark.parametrize("source", ['{"secret":', '{"id":"secret","id":"other"}', '{"x":NaN}', '[]', '\ud800'])
def test_bad_files_have_safe_errors(tmp_path, source):
    path = tmp_path / "sensitive-file-name.jsonl"
    path.write_bytes(source.encode("utf-8", errors="surrogatepass"))
    with pytest.raises(EvaluationError) as error:
        read_jsonl(path)
    assert str(error.value) == "Invalid evaluation input; no report was produced."


def test_missing_file_has_safe_error(tmp_path):
    with pytest.raises(EvaluationError) as error:
        read_jsonl(tmp_path / "sensitive-id")
    assert "sensitive-id" not in str(error.value)


def test_jsonl_preserves_unicode_line_separator_inside_text(tmp_path):
    path = tmp_path / "unicode.jsonl"
    row = {"id": "a", "text": "one\u2028two\u0085three", "annotations": []}
    path.write_text(json.dumps(row, ensure_ascii=False) + "\n", encoding="utf-8")
    assert parse_gold(read_jsonl(path)[0])[0].text == row["text"]


def test_overlap_matching_agrees_with_exhaustive_small_cases():
    import random
    from app.evaluation import _matched_count

    rng = random.Random(7)

    def exhaustive(expected, actual, index=0, used=frozenset()):
        if index == len(expected):
            return 0
        best = exhaustive(expected, actual, index + 1, used)
        target = expected[index]
        for position, candidate in enumerate(actual):
            if (position not in used and target.start < candidate.end
                    and candidate.start < target.end):
                best = max(best, 1 + exhaustive(expected, actual, index + 1, used | {position}))
        return best

    for _ in range(60):
        def spans():
            return tuple(Annotation(start, rng.randrange(start + 1, 11), "PERSON_NAME")
                         for start in (rng.randrange(10) for _ in range(rng.randrange(5))))
        expected, actual = spans(), spans()
        assert _matched_count(expected, actual, overlap=True) == exhaustive(expected, actual)


def test_direct_evaluator_revalidates_predictions():
    with pytest.raises(EvaluationError):
        evaluate((GoldDocument("a", "abc", ()),), {})
    with pytest.raises(EvaluationError):
        evaluate((GoldDocument("a", "abc", ()),), {"a": (Annotation(0, 99, "EMAIL"),)})


def test_unicode_codepoint_offsets():
    annotation = Annotation(2, 17, "EMAIL")
    report = evaluate((GoldDocument("a", "🙂 ada@example.com", (annotation,)),), {"a": (annotation,)})
    assert report["exact"]["corpus"]["true_positives"] == 1
    assert report["characters_evaluated"] == 17


def test_baseline_failure_does_not_echo_source():
    def broken(_):
        raise ValueError("private source")
    with pytest.raises(EvaluationError) as error:
        baseline_predictions((GoldDocument("private-id", "private source", ()),), broken)
    assert str(error.value) == "Baseline evaluation failed; no report was produced."


def test_cli_deterministic_internal_aggregate_only(tmp_path, capsys):
    args = ["--gold", str(FIXTURES / "synthetic-gold.jsonl"), "--predictions", str(FIXTURES / "synthetic-predictions.jsonl")]
    assert main(args) == 0
    first = capsys.readouterr().out
    assert main(args) == 0
    assert capsys.readouterr().out == first
    report = json.loads(first)
    assert len(report["manifest"]["gold_sha256"]) == 64
    for value in ["ada@example.com", "synthetic-email", "Ada Example", str(FIXTURES)]:
        assert value not in first
    output = tmp_path / "report.json"
    assert main(args + ["--output", str(output)]) == 0
    assert output.read_text(encoding="utf-8") == first
    assert not list(tmp_path.glob(".evaluation-*"))


def test_cli_failure_retains_old_output_and_never_partial_report(tmp_path, capsys):
    gold = tmp_path / "gold.jsonl"
    gold.write_text('{"id":"PRIVATE-ID","text":"SECRET","annotations":[]}\n', encoding="utf-8")
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text("", encoding="utf-8")
    output = tmp_path / "report.json"
    output.write_text("previous report", encoding="utf-8")
    assert main(["--gold", str(gold), "--predictions", str(predictions), "--output", str(output)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "Evaluation failed; no report was produced.\n"
    assert output.read_text(encoding="utf-8") == "previous report"


def test_cli_cannot_overwrite_inputs(tmp_path, capsys):
    path = tmp_path / "gold.jsonl"
    original = '{"id":"a","text":"","annotations":[]}\n'
    path.write_text(original, encoding="utf-8")
    assert main(["--gold", str(path), "--baseline", "rules-v1", "--output", str(path)]) == 2
    assert path.read_text(encoding="utf-8") == original
    assert capsys.readouterr().err == "Evaluation failed; no report was produced.\n"


def test_cli_baseline_independent_fixture_smoke(capsys):
    assert main(["--gold", str(FIXTURES / "synthetic-gold.jsonl"), "--baseline", "rules-v1"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["manifest"]["configuration"]["prediction_source"] == "rules-v1"
    assert report["exact"]["per_entity"]["PERSON_NAME"]["false_negatives"] == 1
    assert report["qualification"] == "NOT_QUALIFIED"
