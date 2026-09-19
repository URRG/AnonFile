"""CLI: python -m app.evaluate --gold FILE (--predictions FILE | --baseline rules-v1).

Gold JSONL rows: id, text, annotations [{start,end,entity_type}]; optional
group_id and split. Predictions JSONL rows: id, annotations (no source text).
Every gold document needs an explicit prediction row, including empty lists.
Reports are deterministic internal-only measurements, not export certificates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from pathlib import Path

from app.evaluation import (ENTITY_TYPES, VERSION, EvaluationError, baseline_predictions,
                            canonical_hash, evaluate, parse_gold, parse_predictions, read_jsonl)


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, "Invalid command arguments; use --help for usage.\n")


def run(args: argparse.Namespace) -> dict:
    if args.output:
        target = Path(args.output).resolve()
        sources = [Path(args.gold).resolve()]
        if args.predictions:
            sources.append(Path(args.predictions).resolve())
        if target in sources:
            raise EvaluationError("Output must not replace an input file.")
    gold_rows, gold_hash = read_jsonl(args.gold)
    gold = parse_gold(gold_rows)
    source = "supplied-predictions"
    detector_hash = None
    if args.baseline:
        from app import processing
        predictions = baseline_predictions(gold, processing.detect_text)
        source = "rules-v1"
        detector_hash = hashlib.sha256(Path(processing.__file__).read_bytes()).hexdigest()
        prediction_hash = canonical_hash([
            {"id": doc.id, "annotations": [vars(a) for a in predictions[doc.id]]} for doc in gold
        ])
    else:
        prediction_rows, prediction_hash = read_jsonl(args.predictions)
        predictions = parse_predictions(prediction_rows, gold)
    report = evaluate(gold, predictions)
    configuration = {"evaluator": VERSION, "prediction_source": source,
                     "detector_source_sha256": detector_hash,
                     "entity_types": sorted(ENTITY_TYPES), "split_selection": "ALL_RECORDS",
                     "matching": "maximum-cardinality-one-to-one-same-type",
                     "evaluator_source_sha256": hashlib.sha256(Path(__file__).with_name("evaluation.py").read_bytes()).hexdigest(),
                     "cli_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    report["manifest"] = {"gold_sha256": gold_hash, "predictions_sha256": prediction_hash,
                          "configuration": configuration,
                          "configuration_sha256": canonical_hash(configuration)}
    return report


def _write_report(path: str, result: str) -> None:
    destination = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         dir=destination.parent, prefix=".evaluation-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(result)
        os.replace(temporary, destination)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def main(argv: list[str] | None = None) -> int:
    parser = _Parser(description=__doc__)
    parser.add_argument("--gold", required=True)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--predictions")
    source.add_argument("--baseline", choices=["rules-v1"])
    parser.add_argument("--output", help="Write internal aggregate JSON atomically; defaults to stdout.")
    args = parser.parse_args(argv)
    try:
        result = json.dumps(run(args), sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n"
        if args.output:
            _write_report(args.output, result)
        else:
            sys.stdout.write(result)
        return 0
    except Exception:
        # Source values, IDs, paths and exception representations are never logged.
        sys.stderr.write("Evaluation failed; no report was produced.\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
