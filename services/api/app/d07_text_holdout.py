"""Run the frozen D07 synthetic text-only holdout fixture.

This is a regression fixture, not a benchmark runner.  Its reference spans
were authored separately from the checked-in detector/demo labels, and every
input byte is pinned by the checked-in lock before scoring.  It intentionally
does not inspect PDFs, images, OCR output, graph claims, or release artifacts.
"""
from __future__ import annotations

import hashlib
import inspect
import json
import sys
from types import CodeType
from pathlib import Path
from typing import Any

from app import processing
from app.evaluation import (EvaluationError, baseline_predictions, evaluate, parse_gold,
                            parse_predictions, read_jsonl)

VERSION = "d07-frozen-text-holdout-v1"
_FIXTURE_DIRECTORY = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "d07_text_holdout"
_LOCK_KEYS = frozenset({"schema_version", "fixture_id", "gold_sha256", "automatic_predictions_sha256",
                        "annotation_protocol_sha256"})
_DIGEST_LENGTH = 64
# The lock itself is source-pinned so changing both a fixture input and its
# JSON lock cannot silently redefine this fixed regression case.
_LOCK_SHA256 = "4ec94657070e3430d5e9fc8d7a999e3a13ad3f4e85a2742dbd1ca8401b713494"
LIVE_VERSION = "d07-live-current-detector-text-holdout-v1"
_LIVE_LOCK_KEYS = frozenset({"schema_version", "fixture_id", "gold_sha256", "annotation_protocol_sha256"})
# As with the static-prediction fixture, source-pin the live-mode lock.  This
# prevents a local gold-and-lock edit from silently changing this regression case.
_LIVE_LOCK_SHA256 = "8839f99b2375c604363a8794de923de0fa07ba66087c4200e3e1566bedc52897"


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


def _code_constant(value: Any) -> Any:
    """Make code constants canonical without retaining a callable's source text."""
    if value is None or isinstance(value, (bool, int, str)):
        return {"type": type(value).__name__, "value": value}
    if isinstance(value, float):
        return {"type": "float", "value": value.hex()}
    if isinstance(value, bytes):
        return {"type": "bytes", "value": value.hex()}
    if isinstance(value, tuple):
        return {"type": "tuple", "value": [_code_constant(item) for item in value]}
    if isinstance(value, frozenset):
        items = [_code_constant(item) for item in value]
        return {"type": "frozenset", "value": sorted(
            items, key=lambda item: json.dumps(item, sort_keys=True, ensure_ascii=True,
                                                separators=(",", ":"), allow_nan=False))}
    if isinstance(value, CodeType):
        return {"type": "code", "value": _code_identity(value)}
    raise TypeError("Unsupported callable code constant.")


def _code_identity(code: CodeType) -> dict[str, Any]:
    """Canonical implementation fields independent of local source-file paths."""
    return {
        "argcount": code.co_argcount,
        "posonlyargcount": code.co_posonlyargcount,
        "kwonlyargcount": code.co_kwonlyargcount,
        "nlocals": code.co_nlocals,
        "stacksize": code.co_stacksize,
        "flags": code.co_flags,
        "bytecode": code.co_code.hex(),
        "constants": [_code_constant(value) for value in code.co_consts],
        "names": list(code.co_names),
        "varnames": list(code.co_varnames),
        "freevars": list(code.co_freevars),
        "cellvars": list(code.co_cellvars),
    }


def _detector_implementation_identity(detector: Any) -> dict[str, str]:
    """Bind a live report to both callable behavior and its source file.

    The rules configuration digest identifies declarative configuration only.
    This separate, source-free identity detects implementation changes and is
    deliberately rejected when a callable cannot be reproducibly bound.
    """
    try:
        code = getattr(detector, "__code__", None)
        source = inspect.getsourcefile(detector)
        if not isinstance(code, CodeType) or not source:
            _reject()
        source_bytes = Path(source).read_bytes()
        if not source_bytes or len(source_bytes) > 2_000_000:
            _reject()
        canonical_code = json.dumps(_code_identity(code), sort_keys=True, ensure_ascii=True,
                                    separators=(",", ":"), allow_nan=False).encode("utf-8")
        return {
            "source_file_sha256": "sha256:" + hashlib.sha256(source_bytes).hexdigest(),
            "callable_code_sha256": "sha256:" + hashlib.sha256(canonical_code).hexdigest(),
        }
    except (OSError, TypeError, ValueError, RecursionError):
        _reject()


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


def _read_live_lock(path: Path) -> dict[str, str]:
    try:
        raw = path.read_bytes()
        if len(raw) > 4096 or hashlib.sha256(raw).hexdigest() != _LIVE_LOCK_SHA256:
            _reject()
        lock = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
        if (not isinstance(lock, dict) or set(lock) != _LIVE_LOCK_KEYS
                or lock.get("schema_version") != LIVE_VERSION
                or lock.get("fixture_id") != "synthetic-text-only-independent-annotations-v1"
                or any(not _digest(lock[key]) for key in _LIVE_LOCK_KEYS - {"schema_version", "fixture_id"})):
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


def _load_live_bound_fixture(directory: Path) -> tuple[tuple[Any, ...], dict[str, str]]:
    """Load only gold text and annotation protocol for the live detector path."""
    try:
        gold_path = directory / "gold.jsonl"
        protocol_path = directory / "annotation-protocol.md"
        lock = _read_live_lock(directory / "live-detector-lock.json")
        gold_rows, gold_sha256 = read_jsonl(gold_path)
        protocol_sha256 = hashlib.sha256(protocol_path.read_bytes()).hexdigest()
        if gold_sha256 != lock["gold_sha256"] or protocol_sha256 != lock["annotation_protocol_sha256"]:
            _reject()
        gold = parse_gold(gold_rows)
        if not gold or any(document.group_id is None or document.split != "holdout" for document in gold):
            _reject()
        return gold, {"gold_sha256": gold_sha256, "annotation_protocol_sha256": protocol_sha256}
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


def run_live_detector_fixture(directory: Path = _FIXTURE_DIRECTORY) -> dict[str, Any]:
    """Score current ``processing.detect_text`` over immutable synthetic gold text.

    The detector is intentionally resolved from ``app.processing`` at call time:
    this is a live regression check, not a replay of checked-in predictions.
    """
    gold, hashes = _load_live_bound_fixture(directory)
    try:
        detector = processing.detect_text
        config_digest = processing.rules_method_config_digest()
        implementation = _detector_implementation_identity(detector)
        predictions = baseline_predictions(gold, detector)
        exact = evaluate(gold, predictions)["exact"]
        # Do not attach a stale configuration identity if a mutable rules
        # declaration changes while live scoring is in progress.
        if processing.rules_method_config_digest() != config_digest:
            _reject()
    except EvaluationError:
        _reject()
    aggregates = {"corpus": exact["corpus"], "per_entity": exact["per_entity"]}
    return {
        "schema_version": LIVE_VERSION,
        "classification": "SYNTHETIC_TEXT_ONLY_LIVE_DETECTOR_HOLDOUT_FIXTURE",
        "qualification": "NOT_QUALIFIED",
        "annotation_provenance": "INDEPENDENTLY_AUTHORED_SYNTHETIC_REFERENCE",
        "demo_label_reuse": "NOT_USED",
        "inputs": hashes,
        "method": {
            "method_id": processing.RULES_METHOD_ID,
            "method_version": processing.RULES_METHOD_VERSION,
            "config_digest": config_digest,
            "implementation": implementation,
        },
        "exact_span": {"all_text": aggregates, "by_format": {"text": aggregates}},
        "measurement_status": {
            "text": "MEASURED_EXACT_SPANS",
            "media": "NOT_MEASURED",
            "pdf": "NOT_MEASURED",
            "image": "NOT_MEASURED",
            "ocr": "NOT_MEASURED",
            "graph": "NOT_MEASURED",
            "release": "NOT_MEASURED",
        },
        "limitations": [
            "A frozen synthetic text fixture is a regression check, not evidence of generalization.",
            "Live detector metrics are limited to exact text spans in this synthetic fixture.",
            "Media, graph, and release evaluation are not measured by this fixture.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments not in ([], ["--live-detector"]):
        sys.stderr.write("D07 frozen text holdout verification failed; no report was produced.\n")
        return 2
    try:
        runner = run_live_detector_fixture if arguments == ["--live-detector"] else run_fixture
        sys.stdout.write(json.dumps(runner(), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n")
        return 0
    except Exception:
        sys.stderr.write("D07 frozen text holdout verification failed; no report was produced.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
