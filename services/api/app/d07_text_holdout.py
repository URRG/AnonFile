"""Run the frozen D07 synthetic text-only holdout fixture.

This is a regression fixture, not a benchmark runner.  Its reference spans
were authored separately from the checked-in detector/demo labels, and every
input byte is pinned by the checked-in lock before scoring.  It intentionally
does not inspect PDFs, images, OCR output, graph claims, or release artifacts.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from app.evaluation import EvaluationError, evaluate, parse_gold, parse_predictions, read_jsonl

VERSION = "d07-frozen-text-holdout-v1"
_FIXTURE_DIRECTORY = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "d07_text_holdout"
_LOCK_KEYS = frozenset({"schema_version", "fixture_id", "gold_sha256", "automatic_predictions_sha256",
                        "annotation_protocol_sha256"})
_DIGEST_LENGTH = 64
# The lock itself is source-pinned so changing both a fixture input and its
# JSON lock cannot silently redefine this fixed regression case.
_LOCK_SHA256 = "4ec94657070e3430d5e9fc8d7a999e3a13ad3f4e85a2742dbd1ca8401b713494"


class D07TextHoldoutError(ValueError):
    """Fixed error that never reflects fixture content or paths."""


def _reject() -> None:
    raise D07TextHoldoutError("D07 frozen text holdout verification failed; no report was produced.")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _digest(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == _DIGEST_LENGTH
            and all(character in "0123456789abcdef" for character in value))


def _read_lock(path: Path) -> dict[str, str]:
    try:
        raw = path.read_bytes()
        if len(raw) > 4096:
            _reject()
        if hashlib.sha256(raw).hexdigest() != _LOCK_SHA256:
            _reject()
        lock = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
        if (not isinstance(lock, dict) or set(lock) != _LOCK_KEYS
                or lock.get("schema_version") != VERSION
                or lock.get("fixture_id") != "synthetic-text-only-independent-annotations-v1"
                or any(not _digest(lock[key]) for key in _LOCK_KEYS - {"schema_version", "fixture_id"})):
            _reject()
        return lock
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError):
        _reject()


def _load_bound_fixture(directory: Path) -> tuple[tuple[Any, ...], dict[str, tuple[Any, ...]], dict[str, str]]:
    try:
        gold_path = directory / "gold.jsonl"
        predictions_path = directory / "automatic-predictions.jsonl"
        protocol_path = directory / "annotation-protocol.md"
        lock = _read_lock(directory / "fixture-lock.json")
        gold_rows, gold_sha256 = read_jsonl(gold_path)
        prediction_rows, predictions_sha256 = read_jsonl(predictions_path)
        protocol_sha256 = hashlib.sha256(protocol_path.read_bytes()).hexdigest()
        if (gold_sha256 != lock["gold_sha256"]
                or predictions_sha256 != lock["automatic_predictions_sha256"]
                or protocol_sha256 != lock["annotation_protocol_sha256"]):
            _reject()
        gold = parse_gold(gold_rows)
        if (not gold or any(document.group_id is None or document.split != "holdout" for document in gold)):
            _reject()
        return gold, parse_predictions(prediction_rows, gold), {
            "gold_sha256": gold_sha256,
            "automatic_predictions_sha256": predictions_sha256,
            "annotation_protocol_sha256": protocol_sha256,
        }
    except (D07TextHoldoutError, EvaluationError, OSError, TypeError, ValueError, RecursionError):
        _reject()


def run_fixture(directory: Path = _FIXTURE_DIRECTORY) -> dict[str, Any]:
    """Verify the immutable fixture then return source-free exact-span aggregates."""
    gold, predictions, hashes = _load_bound_fixture(directory)
    exact = evaluate(gold, predictions)["exact"]
    aggregates = {"corpus": exact["corpus"], "per_entity": exact["per_entity"]}
    report = {
        "schema_version": VERSION,
        "classification": "SYNTHETIC_TEXT_ONLY_HOLDOUT_FIXTURE",
        "qualification": "NOT_QUALIFIED",
        "annotation_provenance": "INDEPENDENTLY_AUTHORED_SYNTHETIC_REFERENCE",
        "demo_label_reuse": "NOT_USED",
        "inputs": hashes,
        "exact_span": {"all_text": aggregates, "by_format": {"text": aggregates}},
        "measurement_status": {
            "text": "MEASURED_EXACT_SPANS",
            "pdf": "NOT_MEASURED",
            "image": "NOT_MEASURED",
            "ocr": "NOT_MEASURED",
            "graph": "NOT_MEASURED",
            "release": "NOT_MEASURED",
        },
        "limitations": [
            "A frozen synthetic text fixture is a regression check, not evidence of generalization.",
            "Exact text-span agreement does not measure final-artifact disclosure or release safety.",
            "PDF, image, OCR, graph, and release evaluation are not measured by this fixture.",
        ],
    }
    return report


def main(argv: list[str] | None = None) -> int:
    if argv:
        sys.stderr.write("D07 frozen text holdout verification failed; no report was produced.\n")
        return 2
    try:
        sys.stdout.write(json.dumps(run_fixture(), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
        return 0
    except Exception:
        sys.stderr.write("D07 frozen text holdout verification failed; no report was produced.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
