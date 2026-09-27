"""The D07 text holdout is a locked regression fixture, never a release gate."""
import json
from pathlib import Path

import pytest

from app.d07_text_holdout import D07TextHoldoutError, main, run_fixture


FIXTURE = Path(__file__).parent / "fixtures" / "d07_text_holdout"


def test_frozen_text_holdout_reports_only_exact_aggregate_text_metrics():
    report = run_fixture(FIXTURE)
    assert report["classification"] == "SYNTHETIC_TEXT_ONLY_HOLDOUT_FIXTURE"
    assert report["qualification"] == "NOT_QUALIFIED"
    assert report["annotation_provenance"] == "INDEPENDENTLY_AUTHORED_SYNTHETIC_REFERENCE"
    assert report["demo_label_reuse"] == "NOT_USED"
    exact = report["exact_span"]
    assert exact["all_text"] == exact["by_format"]["text"]
    assert exact["all_text"]["corpus"] == {
        "true_positives": 1, "false_positives": 2, "false_negatives": 2,
        "gold_annotations": 3, "predicted_annotations": 3,
        "precision": 1 / 3, "recall": 1 / 3, "f1": 1 / 3,
    }
    assert exact["all_text"]["per_entity"]["EMAIL"]["true_positives"] == 1
    assert exact["all_text"]["per_entity"]["PHONE"]["false_negatives"] == 1
    assert report["measurement_status"] == {
        "text": "MEASURED_EXACT_SPANS", "pdf": "NOT_MEASURED", "image": "NOT_MEASURED",
        "ocr": "NOT_MEASURED", "graph": "NOT_MEASURED", "release": "NOT_MEASURED",
    }
    encoded = json.dumps(report, sort_keys=True)
    assert "jules@example.test" not in encoded and "text-001" not in encoded


@pytest.mark.parametrize("filename", ["gold.jsonl", "automatic-predictions.jsonl", "annotation-protocol.md"])
def test_fixture_or_hash_drift_fails_closed(tmp_path, filename):
    copied = tmp_path / "fixture"
    copied.mkdir()
    for source in FIXTURE.iterdir():
        (copied / source.name).write_bytes(source.read_bytes())
    with (copied / filename).open("ab") as stream:
        stream.write(b"\nfixture-drift")
    with pytest.raises(D07TextHoldoutError, match="^D07 frozen text holdout verification failed; no report was produced\\.$"):
        run_fixture(copied)


def test_lock_drift_and_cli_failure_do_not_emit_fixture_content(tmp_path, capsys):
    copied = tmp_path / "fixture"
    copied.mkdir()
    for source in FIXTURE.iterdir():
        (copied / source.name).write_bytes(source.read_bytes())
    lock = copied / "fixture-lock.json"
    lock.write_text(lock.read_text(encoding="utf-8").replace("9ec2", "0ec2", 1), encoding="utf-8")
    with pytest.raises(D07TextHoldoutError):
        run_fixture(copied)
    assert main(["--not-supported"]) == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert output.err == "D07 frozen text holdout verification failed; no report was produced.\n"
