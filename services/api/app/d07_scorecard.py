"""D07 synthetic evaluation scorecard.

This module produces aggregate-only, reproducible measurements.  It is not a
release gate, does not run OCR, and never calls a validation pass independent
merely because it was executed a second time.  Callers supply already parsed
synthetic annotations and graph claims; raw text and document identifiers stay
inside the evaluator and are absent from its result.
"""
from __future__ import annotations

from collections import Counter
import re
from typing import Any

from app.evaluation import GoldDocument, canonical_hash, evaluate, parse_gold, parse_predictions

VERSION = "d07-scorecard-v1"
_FORMATS = frozenset({"text", "csv", "json", "jsonl", "pdf", "image"})
_ABSTENTIONS = frozenset({"UNSUPPORTED_FORMAT", "LOW_CONFIDENCE", "NO_DEFENSIBLE_LOCATOR",
                          "INDEPENDENT_ENGINE_UNAVAILABLE", "UNTOUCHED_ARTIFACT_UNAVAILABLE"})
_RELATION_TYPES = frozenset({"assistant_to", "assistant_for", "works_at", "client_of", "works_on", "assigned_to", "sent_to"})
_PERSON_ID = re.compile(r"^E[1-9][0-9]{0,5}$")
_ORGANIZATION_ID = re.compile(r"^organization_[1-9][0-9]{0,5}$")
_PROJECT_ID = re.compile(r"^project_[1-9][0-9]{0,5}$")
_RELATION_ENDPOINTS = {
    "assistant_to": (_PERSON_ID, _PERSON_ID), "sent_to": (_PERSON_ID, _PERSON_ID),
    "assistant_for": (_PERSON_ID, _ORGANIZATION_ID), "works_at": (_PERSON_ID, _ORGANIZATION_ID),
    "client_of": (_PERSON_ID, _ORGANIZATION_ID), "works_on": (_PERSON_ID, _PROJECT_ID),
    "assigned_to": (_PROJECT_ID, _PERSON_ID),
}
_MAX_GRAPH_CLAIMS = 10_000


class ScorecardError(ValueError):
    """Fixed error: source values and IDs are never reflected."""


def _reject() -> None:
    raise ScorecardError("Invalid D07 scorecard input.")


def _format_map(documents: tuple[GoldDocument, ...], formats: dict[str, str]) -> dict[str, str]:
    if not isinstance(formats, dict) or set(formats) != {document.id for document in documents}:
        _reject()
    if any(not isinstance(identifier, str) or not isinstance(value, str) or value not in _FORMATS
           for identifier, value in formats.items()):
        _reject()
    return formats


def _slice(documents: tuple[GoldDocument, ...], predictions: dict[str, tuple[Any, ...]], format_name: str,
           formats: dict[str, str]) -> dict[str, Any]:
    selected = tuple(document for document in documents if formats[document.id] == format_name)
    if not selected:
        return {"documents": 0, "status": "NO_DOCUMENTS", "exact": None}
    return {"documents": len(selected), "status": "SCORED",
            "exact": evaluate(selected, {document.id: predictions[document.id] for document in selected})["exact"]}


def _abstentions(documents: tuple[GoldDocument, ...], value: dict[str, str]) -> dict[str, Any]:
    document_ids = {document.id for document in documents}
    if not isinstance(value, dict) or any(not isinstance(key, str) or key not in document_ids
                                          or not isinstance(reason, str) or reason not in _ABSTENTIONS
                                          for key, reason in value.items()):
        _reject()
    counts = Counter(value.values())
    return {"abstained_documents": len(value), "assessed_documents": len(documents) - len(value),
            "by_reason": {reason: counts[reason] for reason in sorted(counts)}}


def _span_metrics(documents: tuple[GoldDocument, ...], predictions: dict[str, tuple[Any, ...]]) -> dict[str, Any]:
    """Score only assessed documents; an empty assessed set is an abstention."""
    if not documents:
        return {"status": "ABSTAINED", "reason": "NO_ASSESSED_DOCUMENTS", "exact": None}
    selected_predictions = {document.id: predictions[document.id] for document in documents}
    return {"status": "SCORED", **evaluate(documents, selected_predictions)}


def _graph_metrics(gold: set[tuple[str, str, str]] | None,
                   predicted: set[tuple[str, str, str]] | None) -> dict[str, Any]:
    # Validate both containers before any set operation.  Direct callers must
    # get the same fixed error rather than a type-dependent exception.
    if gold is None and predicted is None:
        return {"status": "ABSTAINED", "reason": "NO_GRAPH_GOLD_OR_REVIEW_STATE"}
    if gold is None or predicted is None:
        _reject()
    if (type(gold) is not set or type(predicted) is not set or len(gold) > _MAX_GRAPH_CLAIMS
            or len(predicted) > _MAX_GRAPH_CLAIMS
            or any(not isinstance(edge, tuple) or len(edge) != 3
                   or not isinstance(edge[0], str) or edge[0] not in _RELATION_TYPES
                   or not isinstance(edge[1], str) or not isinstance(edge[2], str)
                   or not _RELATION_ENDPOINTS[edge[0]][0].fullmatch(edge[1])
                   or not _RELATION_ENDPOINTS[edge[0]][1].fullmatch(edge[2])
                   for edge in gold)
            or any(not isinstance(edge, tuple) or len(edge) != 3
                   or not isinstance(edge[0], str) or edge[0] not in _RELATION_TYPES
                   or not isinstance(edge[1], str) or not isinstance(edge[2], str)
                   or not _RELATION_ENDPOINTS[edge[0]][0].fullmatch(edge[1])
                   or not _RELATION_ENDPOINTS[edge[0]][1].fullmatch(edge[2])
                   for edge in predicted)):
        _reject()
    labels = sorted({edge[0] for edge in gold | predicted})
    def counts(expected: set[tuple[str, str, str]], actual: set[tuple[str, str, str]]) -> dict[str, int]:
        return {"true_positives": len(expected & actual), "false_positives": len(actual - expected),
                "false_negatives": len(expected - actual)}
    return {"status": "SCORED", "exact": counts(gold, predicted),
            "per_type": {label: counts({edge for edge in gold if edge[0] == label},
                                         {edge for edge in predicted if edge[0] == label}) for label in labels},
            "limitations": ["Exact graph claims measure supplied identity keys, not real-world identity resolution.",
                            "Evidence-location agreement and contradictory-claim adjudication are not scored by this schema."]}


def _final_validation(value: dict[str, Any] | None, primary_engine: str) -> dict[str, Any]:
    """Do not accept caller assertions as independent validation evidence.

    D07 has no executable second engine, artifact-byte binding, ground-truth
    binding, or reproducible validator result.  A caller-provided engine name
    and counts therefore cannot cross the independence boundary.
    """
    if value is None:
        return {"status": "ABSTAINED", "reason": "INDEPENDENT_ENGINE_UNAVAILABLE"}
    return {"status": "ABSTAINED", "reason": "NO_EXECUTABLE_BOUND_INDEPENDENT_VALIDATOR"}


def _validated_documents(value: Any) -> tuple[GoldDocument, ...]:
    """Apply the evaluator's direct-input validation before scorecard parsing."""
    try:
        if type(value) is not tuple:
            _reject()
        return parse_gold([{
            "id": document.id, "text": document.text,
            "annotations": [vars(annotation) for annotation in document.annotations],
            **({"group_id": document.group_id} if document.group_id is not None else {}),
            **({"split": document.split} if document.split is not None else {}),
        } for document in value])
    except (AttributeError, TypeError, ValueError, RecursionError):
        _reject()


def scorecard(*, documents: tuple[GoldDocument, ...], formats: dict[str, str], automatic: list[dict[str, Any]],
              reviewer_corrected: list[dict[str, Any]], abstentions: dict[str, str],
              graph_gold: set[tuple[str, str, str]] | None, graph_automatic: set[tuple[str, str, str]] | None,
              graph_reviewer_corrected: set[tuple[str, str, str]] | None, primary_engine: str,
              final_validation: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a deterministic, aggregate-only synthetic D07 report."""
    if not isinstance(primary_engine, str) or not primary_engine:
        _reject()
    documents = _validated_documents(documents)
    # Parsing here makes direct callers meet the same all-document contract.
    automatic_predictions = parse_predictions(automatic, documents)
    reviewer_predictions = parse_predictions(reviewer_corrected, documents)
    formats = _format_map(documents, formats)
    abstention_summary = _abstentions(documents, abstentions)
    assessed_documents = tuple(document for document in documents if document.id not in abstentions)
    by_format = {name: {"automatic": _slice(assessed_documents, automatic_predictions, name, formats),
                        "reviewer_corrected": _slice(assessed_documents, reviewer_predictions, name, formats)}
                 for name in sorted(set(formats.values()))}
    result = {"schema_version": VERSION, "classification": "SYNTHETIC_INTERNAL_EVALUATION_ONLY",
              "qualification": "NOT_QUALIFIED", "automatic": _span_metrics(assessed_documents, automatic_predictions),
              "reviewer_corrected": _span_metrics(assessed_documents, reviewer_predictions), "by_format": by_format,
              "abstentions": abstention_summary,
              "graph": {"automatic": _graph_metrics(graph_gold, graph_automatic),
                        "reviewer_corrected": _graph_metrics(graph_gold, graph_reviewer_corrected)},
              "final_artifact_validation": _final_validation(final_validation, primary_engine),
              "limitations": ["Synthetic scorecard results are not representative holdout evidence.",
                              "Reviewer-corrected scores are not automatic detector performance.",
                              "No same-engine OCR recheck is labelled independent.",
                              "This report does not authorize a release."]}
    result["report_sha256"] = canonical_hash(result)
    return result
