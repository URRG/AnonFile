"""Independent, annotation-based span evaluation; never release authorization.

All offsets are half-open Python Unicode code-point offsets. Exact matches and
same-label positive-length overlaps are reported separately. Neither measures
residual disclosure in transformed output or contextual re-identification.
"""
from __future__ import annotations

import hashlib
import json
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

VERSION = "span-evaluator-v1"
ENTITY_TYPES = frozenset({
    "CREDENTIAL", "EMAIL", "PHONE", "AADHAAR", "PAN", "CARD", "IP",
    "PERSON", "ADDRESS", "DATE", "LOCATION", "ORGANIZATION", "PASSPORT",
    "GOVERNMENT_ID", "HEALTH", "PAYMENT", "BUSINESS_SECRET", "USER_ID",
    "OTHER_SENSITIVE", "IP_ADDRESS", "SENSITIVE_NUMBER", "PAYMENT_SECRET",
    "PERSON_NAME", "DATE_OF_BIRTH",
    "HEALTH_SENSITIVE", "BUSINESS_CONFIDENTIAL", "QUASI_IDENTIFIER",
})
MAX_FILE_BYTES = 20_000_000
MAX_DOCUMENTS = 10_000
MAX_TEXT_CHARS = 2_000_000
MAX_ANNOTATIONS = 1_000


class EvaluationError(ValueError):
    """Fixed-message validation error that never incorporates source values."""


@dataclass(frozen=True)
class Annotation:
    start: int
    end: int
    entity_type: str


@dataclass(frozen=True)
class GoldDocument:
    id: str
    text: str
    annotations: tuple[Annotation, ...]
    group_id: str | None = None
    split: str | None = None


def _reject() -> None:
    raise EvaluationError("Invalid evaluation input; no report was produced.")


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _constant(_: str) -> None:
    _reject()


def read_jsonl(path: str | Path) -> tuple[list[dict[str, Any]], str]:
    """Read bounded UTF-8 JSONL without exposing paths or content in errors."""
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(MAX_FILE_BYTES + 1)
        if len(raw) > MAX_FILE_BYTES:
            _reject()
        rows = []
        # JSONL separates records with LF, not Unicode line separators that may
        # legitimately occur inside an unescaped JSON string.
        for line in raw.decode("utf-8").split("\n"):
            if not line.strip():
                continue
            row = json.loads(line, object_pairs_hook=_object, parse_constant=_constant)
            if not isinstance(row, dict) or len(rows) >= MAX_DOCUMENTS:
                _reject()
            rows.append(row)
        return rows, hashlib.sha256(raw).hexdigest()
    except (OSError, UnicodeError, ValueError, RecursionError):
        raise EvaluationError("Invalid evaluation input; no report was produced.") from None


def _identifier(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 256:
        _reject()
    return value


def _annotations(value: Any, text_length: int, *, gold: bool) -> tuple[Annotation, ...]:
    if not isinstance(value, list) or len(value) > MAX_ANNOTATIONS:
        _reject()
    result = []
    for item in value:
        if not isinstance(item, dict) or set(item) != {"start", "end", "entity_type"}:
            _reject()
        start, end, label = item["start"], item["end"], item["entity_type"]
        if (type(start) is not int or type(end) is not int
                or not 0 <= start < end <= text_length
                or not isinstance(label, str) or label not in ENTITY_TYPES):
            _reject()
        result.append(Annotation(start, end, label))
    if gold and len(set(result)) != len(result):
        _reject()
    return tuple(sorted(result, key=lambda a: (a.entity_type, a.start, a.end)))


def parse_gold(rows: list[dict[str, Any]]) -> tuple[GoldDocument, ...]:
    if len(rows) > MAX_DOCUMENTS:
        _reject()
    documents = []
    seen = set()
    group_splits: dict[str, set[str | None]] = {}
    for row in rows:
        if (not isinstance(row, dict) or not {"id", "text", "annotations"} <= set(row)
                or not set(row) <= {"id", "text", "annotations", "group_id", "split"}):
            _reject()
        doc_id = _identifier(row["id"])
        text = row["text"]
        if doc_id in seen or not isinstance(text, str) or len(text) > MAX_TEXT_CHARS:
            _reject()
        group = _identifier(row["group_id"]) if "group_id" in row else None
        split = _identifier(row["split"]) if "split" in row else None
        if group is not None:
            group_splits.setdefault(group, set()).add(split)
            if len(group_splits[group]) > 1:
                _reject()
        documents.append(GoldDocument(doc_id, text, _annotations(row["annotations"], len(text), gold=True), group, split))
        seen.add(doc_id)
    return tuple(documents)


def parse_predictions(rows: list[dict[str, Any]], gold: tuple[GoldDocument, ...]) -> dict[str, tuple[Annotation, ...]]:
    lengths = {doc.id: len(doc.text) for doc in gold}
    predictions = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"id", "annotations"}:
            _reject()
        doc_id = _identifier(row["id"])
        if doc_id not in lengths or doc_id in predictions:
            _reject()
        predictions[doc_id] = _annotations(row["annotations"], lengths[doc_id], gold=False)
    if set(predictions) != set(lengths):
        _reject()
    return predictions


def _matched_count(gold: tuple[Annotation, ...], predicted: tuple[Annotation, ...], *, overlap: bool) -> int:
    """Maximum-cardinality one-to-one matching, including nested annotations.

    Breadth-first augmenting paths avoid recursion limits and greedy order bias.
    Duplicate predictions remain separate candidates and count as false positives.
    """
    edges = []
    for target in gold:
        edges.append([index for index, candidate in enumerate(predicted)
                      if target.entity_type == candidate.entity_type and
                      ((target.start < candidate.end and candidate.start < target.end)
                       if overlap else (target.start == candidate.start and target.end == candidate.end))])
    matched_gold: dict[int, int] = {}
    matched_prediction: dict[int, int] = {}
    for start in range(len(gold)):
        queue = deque([start])
        visited_gold = {start}
        parent: dict[int, int] = {}
        end: int | None = None
        while queue and end is None:
            current = queue.popleft()
            for candidate in edges[current]:
                if candidate in parent:
                    continue
                parent[candidate] = current
                if candidate not in matched_prediction:
                    end = candidate
                    break
                next_gold = matched_prediction[candidate]
                if next_gold not in visited_gold:
                    visited_gold.add(next_gold)
                    queue.append(next_gold)
        while end is not None:
            current = parent[end]
            previous = matched_gold.get(current)
            matched_gold[current] = end
            matched_prediction[end] = current
            end = previous
    return len(matched_gold)


def _metrics(tp: int, fp: int, fn: int) -> dict[str, Any]:
    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None
    f1 = (2 * tp / (2 * tp + fp + fn)) if precision is not None and recall is not None else None
    return {"true_positives": tp, "false_positives": fp, "false_negatives": fn,
            "gold_annotations": tp + fn, "predicted_annotations": tp + fp,
            "precision": precision, "recall": recall, "f1": f1}


def evaluate(gold: tuple[GoldDocument, ...], predictions: dict[str, tuple[Annotation, ...]]) -> dict[str, Any]:
    """Evaluate parsed inputs. Revalidate even direct Python callers fail closed."""
    try:
        validated_gold = parse_gold([{
            "id": doc.id, "text": doc.text,
            "annotations": [vars(a) for a in doc.annotations],
            **({"group_id": doc.group_id} if doc.group_id is not None else {}),
            **({"split": doc.split} if doc.split is not None else {}),
        } for doc in gold])
        validated_predictions = parse_predictions([
            {"id": doc_id, "annotations": [vars(a) for a in annotations]}
            for doc_id, annotations in predictions.items()
        ], validated_gold)
    except (AttributeError, TypeError):
        _reject()
    gold, predictions = validated_gold, validated_predictions
    labels = sorted({a.entity_type for doc in gold for a in doc.annotations}
                    | {a.entity_type for spans in predictions.values() for a in spans})
    gold_count = sum(len(doc.annotations) for doc in gold)
    gold_documents = sum(bool(doc.annotations) for doc in gold)
    report: dict[str, Any] = {
        "schema_version": VERSION,
        "report_classification": "INTERNAL_EVALUATION_ONLY",
        "qualification": "NOT_QUALIFIED",
        "evidence_status": "SPAN_MEASUREMENT_ONLY" if gold_count else "INSUFFICIENT_EVIDENCE",
        "documents_evaluated": len(gold),
        "documents_with_gold_annotations": gold_documents,
        "characters_evaluated": sum(len(doc.text) for doc in gold),
        "offset_unit": "UNICODE_CODE_POINTS_HALF_OPEN",
        "output_residual_disclosure": "NOT_EVALUATED",
        "dataset_representativeness": "NOT_ESTABLISHED",
        "limitations": [
            "Measures annotation agreement, not anonymity, output leakage, or buyer acceptance.",
            "Unannotated sensitive entities are invisible to these measurements.",
            "All supplied records are evaluated; split labels do not imply a held-out study.",
            "No confidence intervals or generalization claims are made.",
            "Overlap measurements are lenient and cannot substitute for exact detection coverage.",
            "Counts and content fingerprints are internal evidence, not approved public disclosures.",
            "Empty denominators are null, not perfect scores. Reports cannot authorize releases.",
        ],
    }
    for name, overlap in (("exact", False), ("same_type_overlap", True)):
        counts = {label: [0, 0, 0] for label in labels}
        missed_documents = 0
        false_positive_documents = 0
        for doc in gold:
            doc_fn = doc_fp = 0
            for label in labels:
                expected = tuple(a for a in doc.annotations if a.entity_type == label)
                actual = tuple(a for a in predictions[doc.id] if a.entity_type == label)
                tp = _matched_count(expected, actual, overlap=overlap)
                fp, fn = len(actual) - tp, len(expected) - tp
                counts[label] = [old + new for old, new in zip(counts[label], (tp, fp, fn))]
                doc_fn += fn
                doc_fp += fp
            missed_documents += doc_fn > 0
            false_positive_documents += doc_fp > 0
        totals = [sum(count[index] for count in counts.values()) for index in range(3)]
        report[name] = {
            "corpus": _metrics(*totals),
            "per_entity": {label: _metrics(*count) for label, count in counts.items()},
            "documents_with_unmatched_gold": missed_documents,
            "missed_document_rate": missed_documents / gold_documents if gold_documents else None,
            "missed_document_rate_denominator": gold_documents,
            "documents_with_false_positive_predictions": false_positive_documents,
        }
    return report


def baseline_predictions(gold: tuple[GoldDocument, ...], detector: Callable) -> dict[str, tuple[Annotation, ...]]:
    try:
        rows = [{"id": doc.id, "annotations": [{"start": span.start, "end": span.end,
                 "entity_type": span.entity_type} for span in detector(doc.text)]} for doc in gold]
        return parse_predictions(rows, gold)
    except Exception:
        raise EvaluationError("Baseline evaluation failed; no report was produced.") from None


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
