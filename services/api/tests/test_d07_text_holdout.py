"""The D07 text holdout is a locked regression fixture, never a release gate."""
import json
import re
from pathlib import Path

import pytest

from app import processing
from app.d07_text_holdout import (D07TextHoldoutError, main, run_fixture,
                                  _code_identity, run_live_detector_fixture)


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


def test_existing_crlf_worktree_fixture_has_same_locked_content(tmp_path):
    copied = tmp_path / "crlf-fixture"
    copied.mkdir()
    for source in FIXTURE.iterdir():
        raw = source.read_bytes()
        assert b"\r" not in raw.replace(b"\r\n", b"")
        canonical = raw.replace(b"\r\n", b"\n")
        (copied / source.name).write_bytes(canonical.replace(b"\n", b"\r\n"))
    assert run_fixture(copied) == run_fixture(FIXTURE)
    assert run_live_detector_fixture(copied) == run_live_detector_fixture(FIXTURE)


def test_lone_carriage_return_is_not_a_fallback_canonicalization(tmp_path):
    copied = tmp_path / "lone-cr-fixture"
    copied.mkdir()
    for source in FIXTURE.iterdir():
        (copied / source.name).write_bytes(source.read_bytes())
    lock = copied / "fixture-lock.json"
    lock.write_bytes(lock.read_bytes().replace(b"\n", b"\r", 1))
    with pytest.raises(D07TextHoldoutError):
        run_fixture(copied)


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


def test_live_detector_holdout_uses_current_detector_and_reports_aggregate_only(monkeypatch):
    live = run_live_detector_fixture(FIXTURE)
    assert live["classification"] == "SYNTHETIC_TEXT_ONLY_LIVE_DETECTOR_HOLDOUT_FIXTURE"
    assert live["qualification"] == "NOT_QUALIFIED"
    assert live["annotation_provenance"] == "INDEPENDENTLY_AUTHORED_SYNTHETIC_REFERENCE"
    assert live["method"]["method_id"] == processing.RULES_METHOD_ID
    assert live["method"]["method_version"] == processing.RULES_METHOD_VERSION
    assert live["method"]["config_digest"] == processing.rules_method_config_digest()
    assert set(live["method"]["implementation"]) == {"source_file_sha256", "callable_code_sha256"}
    assert all(value.startswith("sha256:") for value in live["method"]["implementation"].values())
    assert live["exact_span"]["all_text"] == live["exact_span"]["by_format"]["text"]
    assert live["measurement_status"] == {
        "text": "MEASURED_EXACT_SPANS", "media": "NOT_MEASURED", "pdf": "NOT_MEASURED",
        "image": "NOT_MEASURED", "ocr": "NOT_MEASURED", "graph": "NOT_MEASURED",
        "release": "NOT_MEASURED",
    }
    monkeypatch.setattr(processing, "detect_text", lambda _: ())
    changed = run_live_detector_fixture(FIXTURE)
    assert changed["exact_span"]["all_text"]["corpus"] != live["exact_span"]["all_text"]["corpus"]
    assert changed["exact_span"]["all_text"]["corpus"]["true_positives"] == 0
    assert changed["method"]["implementation"] != live["method"]["implementation"]
    monkeypatch.setattr(processing, "detect_text", object())
    with pytest.raises(D07TextHoldoutError, match="^D07 frozen text holdout verification failed; no report was produced\\.$"):
        run_live_detector_fixture(FIXTURE)
    encoded = json.dumps(live, sort_keys=True)
    assert "jules@example.test" not in encoded and "text-001" not in encoded


@pytest.mark.parametrize("filename", ["gold.jsonl", "annotation-protocol.md", "live-detector-lock.json"])
def test_live_detector_fixture_drift_fails_closed(tmp_path, filename):
    copied = tmp_path / "fixture"
    copied.mkdir()
    for source in FIXTURE.iterdir():
        (copied / source.name).write_bytes(source.read_bytes())
    with (copied / filename).open("ab") as stream:
        stream.write(b"\nlive-fixture-drift")
    with pytest.raises(D07TextHoldoutError, match="^D07 frozen text holdout verification failed; no report was produced\\.$"):
        run_live_detector_fixture(copied)


def test_live_detector_cli(monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["d07_text_holdout", "--live-detector"])
    assert main() == 0
    report = json.loads(capsys.readouterr().out)
    assert report["schema_version"] == "d07-live-current-detector-text-holdout-v1"


def test_live_detector_reports_call_time_config_digest(monkeypatch):
    before = run_live_detector_fixture(FIXTURE)
    monkeypatch.setattr(processing, "_EMAIL", re.compile(r"never-a-live-email-match"))
    after = run_live_detector_fixture(FIXTURE)
    assert after["method"]["config_digest"] == processing.rules_method_config_digest()
    assert after["method"]["config_digest"] != before["method"]["config_digest"]
    assert after["exact_span"]["all_text"]["corpus"] != before["exact_span"]["all_text"]["corpus"]


def test_live_detector_rejects_configuration_drift_during_scoring(monkeypatch):
    def changing_detector(_: str):
        monkeypatch.setattr(processing, "_EMAIL", re.compile(r"drifted"))
        return ()

    monkeypatch.setattr(processing, "detect_text", changing_detector)
    with pytest.raises(D07TextHoldoutError, match="^D07 frozen text holdout verification failed; no report was produced\\.$"):
        run_live_detector_fixture(FIXTURE)


def test_code_identity_canonicalizes_nonempty_frozenset_constants():
    def uses_frozenset(value):
        return value in {"alpha", "beta"}

    assert frozenset({"alpha", "beta"}) in uses_frozenset.__code__.co_consts
    identity = _code_identity(uses_frozenset.__code__)
    assert json.dumps(identity, sort_keys=True, ensure_ascii=True, allow_nan=False)
