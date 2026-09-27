"""D07 synthetic evaluation scorecard.

This module produces aggregate-only, reproducible measurements.  It is not a
release gate, does not run OCR, and never calls a validation pass independent
merely because it was executed a second time.  Callers supply already parsed
synthetic annotations and graph claims; raw text and document identifiers stay
inside the evaluator and are absent from its result.
"""
from __future__ import annotations

from collections import Counter
from typing import Any

from app.evaluation import GoldDocument, canonical_hash, evaluate, parse_predictions

VERSION = "d07-scorecard-v1"
_FORMATS = frozenset({"text", "csv", "json", "jsonl", "pdf", "image"})
_ABSTENTIONS = frozenset({"UNSUPPORTED_FORMAT", "LOW_CONFIDENCE", "NO_DEFENSIBLE_LOCATOR",
                          "INDEPENDENT_ENGINE_UNAVAILABLE", "UNTOUCHED_ARTIFACT_UNAVAILABLE"})


class ScorecardError(ValueError):
    """Fixed error: source values and IDs are never reflected."""


def _reject() -> None:
    raise ScorecardError("Invalid D07 scorecard input.")


def _format_map(documents: tuple[GoldDocument, ...], formats: dict[str, str]) -> dict[str, str]:
    if not isinstance(formats, dict) or set(formats) != {document.id for document in documents}:
        _reject()
    if any(not isinstance(identifier, str) or value not in _FORMATS for identifier, value in formats.items()):
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
    if not isinstance(value, dict) or any(key not in {doc.id for doc in documents} or reason not in _ABSTENTIONS
                                          for key, reason in value.items()):
        _reject()
    counts = Counter(value.values())
    return {"abstained_documents": len(value), "assessed_documents": len(documents) - len(value),
            "by_reason": {reason: counts[reason] for reason in sorted(counts)}}


def _graph_metrics(gold: set[tuple[str, str, str]], predicted: set[tuple[str, str, str]]) -> dict[str, Any]:
    if any(not isinstance(edge, tuple) or len(edge) != 3 or any(not isinstance(value, str) or not value for value in edge)
           for edge in gold | predicted):
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
    """Only accept an already independently attested aggregate comparison."""
    if value is None:
        return {"status": "ABSTAINED", "reason": "INDEPENDENT_ENGINE_UNAVAILABLE"}
    if (not isinstance(value, dict) or set(value) != {"engine_id", "artifact_kind", "assessed_units", "residual_units"}
            or not isinstance(value["engine_id"], str) or not value["engine_id"]
            or value["engine_id"] == primary_engine or value["artifact_kind"] not in {"text", "pixels"}
            or any(type(value[key]) is not int or value[key] < 0 for key in ("assessed_units", "residual_units"))
            or value["residual_units"] > value["assessed_units"]):
        return {"status": "ABSTAINED", "reason": "NO_DEFENSIBLE_INDEPENDENT_VALIDATION"}
    return {"status": "ASSESSED", "engine_id": value["engine_id"], "artifact_kind": value["artifact_kind"],
            "assessed_units": value["assessed_units"], "residual_units": value["residual_units"],
            "limitation": "Aggregate comparison only; it does not establish absence of unrecognized content or release safety."}


def scorecard(*, documents: tuple[GoldDocument, ...], formats: dict[str, str], automatic: list[dict[str, Any]],
              reviewer_corrected: list[dict[str, Any]], abstentions: dict[str, str],
              graph_gold: set[tuple[str, str, str]], graph_automatic: set[tuple[str, str, str]],
              graph_reviewer_corrected: set[tuple[str, str, str]], primary_engine: str,
              final_validation: dict[str, Any] | None = None) -> dict[str, Any]:
    """Create a deterministic, aggregate-only synthetic D07 report."""
    if not isinstance(primary_engine, str) or not primary_engine:
        _reject()
    # Parsing here makes direct callers meet the same all-document contract.
    automatic_predictions = parse_predictions(automatic, documents)
    reviewer_predictions = parse_predictions(reviewer_corrected, documents)
    formats = _format_map(documents, formats)
    by_format = {name: {"automatic": _slice(documents, automatic_predictions, name, formats),
                        "reviewer_corrected": _slice(documents, reviewer_predictions, name, formats)}
                 for name in sorted(set(formats.values()))}
    result = {"schema_version": VERSION, "classification": "SYNTHETIC_INTERNAL_EVALUATION_ONLY",
              "qualification": "NOT_QUALIFIED", "automatic": evaluate(documents, automatic_predictions),
              "reviewer_corrected": evaluate(documents, reviewer_predictions), "by_format": by_format,
              "abstentions": _abstentions(documents, abstentions),
              "graph": {"automatic": _graph_metrics(graph_gold, graph_automatic),
                        "reviewer_corrected": _graph_metrics(graph_gold, graph_reviewer_corrected)},
              "final_artifact_validation": _final_validation(final_validation, primary_engine),
              "limitations": ["Synthetic scorecard results are not representative holdout evidence.",
                              "Reviewer-corrected scores are not automatic detector performance.",
                              "No same-engine OCR recheck is labelled independent.",
                              "This report does not authorize a release."]}
    result["report_sha256"] = canonical_hash(result)
    return result
