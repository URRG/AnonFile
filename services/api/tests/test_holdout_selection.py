"""Pinned split selection is a regression safeguard, not independent evidence."""
import hashlib
import json

import pytest

from app.evaluate import main


def corpus(tmp_path):
    records = [
        {"id": "train-one", "group_id": "person-a", "split": "train",
         "text": "Riya is fictional.", "annotations": [{"start": 0, "end": 4, "entity_type": "PERSON_NAME"}]},
        {"id": "holdout-one", "group_id": "person-b", "split": "holdout",
         "text": "Mail sita@example.test", "annotations": [{"start": 5, "end": 22, "entity_type": "EMAIL"}]},
        {"id": "holdout-two", "group_id": "person-c", "split": "holdout",
         "text": "No identifiers here.", "annotations": []},
    ]
    gold = tmp_path / "gold.jsonl"
    gold.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
    lock = tmp_path / "holdout-lock.json"
    lock.write_text(json.dumps({
        "schema_version": "holdout-lock-v1",
        "gold_sha256": hashlib.sha256(gold.read_bytes()).hexdigest(),
        "annotation_protocol_sha256": "a" * 64,
        "holdout_split": "holdout",
        "minimum_documents": 2,
        "minimum_positive_documents": 1,
    }), encoding="utf-8")
    return gold, lock, records


def test_holdout_lock_scores_only_pinned_holdout_without_independence_claim(tmp_path, capsys):
    gold, lock, _ = corpus(tmp_path)
    assert main(["--gold", str(gold), "--baseline", "rules-v1", "--holdout-lock", str(lock)]) == 0
    output = capsys.readouterr().out
    report = json.loads(output)
    assert report["documents_evaluated"] == 2
    assert report["manifest"]["configuration"]["split_selection"] == "holdout"
    assert report["manifest"]["holdout"]["non_holdout_documents"] == 1
    assert report["manifest"]["holdout"]["independence_attestation"] == "NOT_VERIFIED_BY_SOFTWARE"
    assert report["qualification"] == "NOT_QUALIFIED"
    assert "sita@example.test" not in output and "train-one" not in output


@pytest.mark.parametrize("change", ["gold_changed", "duplicate_text", "missing_split", "lock_mismatch"])
def test_holdout_refuses_unpinned_or_leaking_corpus(tmp_path, capsys, change):
    gold, lock, records = corpus(tmp_path)
    if change == "gold_changed":
        gold.write_bytes(gold.read_bytes() + b"\n")
    elif change in {"duplicate_text", "missing_split"}:
        if change == "duplicate_text":
            records[0]["text"] = records[1]["text"]
        else:
            del records[0]["split"]
        gold.write_text("".join(json.dumps(record) + "\n" for record in records), encoding="utf-8")
        manifest = json.loads(lock.read_text(encoding="utf-8"))
        manifest["gold_sha256"] = hashlib.sha256(gold.read_bytes()).hexdigest()
        lock.write_text(json.dumps(manifest), encoding="utf-8")
    else:
        manifest = json.loads(lock.read_text(encoding="utf-8"))
        manifest["annotation_protocol_sha256"] = "not-a-hash"
        lock.write_text(json.dumps(manifest), encoding="utf-8")
    assert main(["--gold", str(gold), "--baseline", "rules-v1", "--holdout-lock", str(lock)]) == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err == "Evaluation failed; no report was produced.\n"


def test_holdout_predictions_must_cover_exactly_selected_rows(tmp_path, capsys):
    gold, lock, records = corpus(tmp_path)
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text("".join(json.dumps({"id": item["id"], "annotations": []}) + "\n"
                                   for item in records), encoding="utf-8")
    assert main(["--gold", str(gold), "--predictions", str(predictions),
                 "--holdout-lock", str(lock)]) == 2
    assert capsys.readouterr().out == ""
    predictions.write_text("".join(json.dumps({"id": item["id"], "annotations": []}) + "\n"
                                   for item in records if item["split"] == "holdout"), encoding="utf-8")
    assert main(["--gold", str(gold), "--predictions", str(predictions),
                 "--holdout-lock", str(lock)]) == 0
    assert json.loads(capsys.readouterr().out)["exact"]["corpus"]["false_negatives"] == 1


def test_holdout_lock_cannot_be_overwritten_by_report(tmp_path, capsys):
    gold, lock, _ = corpus(tmp_path)
    original = lock.read_bytes()
    assert main(["--gold", str(gold), "--baseline", "rules-v1", "--holdout-lock", str(lock),
                 "--output", str(lock)]) == 2
    assert lock.read_bytes() == original
    assert capsys.readouterr().out == ""
