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

VERSION = "d07-scorecard-v2"
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
_LOCATOR_ID = re.compile(r"^L[1-9][0-9]{0,5}$")
_IDENTITY_DISPOSITIONS = frozenset({"MERGE", "SPLIT"})


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


def _recall_bounds(*, eligible: tuple[GoldDocument, ...], assessed: tuple[GoldDocument, ...],
                   predictions: dict[str, tuple[Any, ...]]) -> dict[str, Any]:
    """Report assessed-only recall beside conservative bounds over all gold.

    A detector may abstain on difficult documents.  Its ordinary score is
    therefore conditional on the documents it assessed, whereas the lower and
    upper bounds retain positives in abstained documents.  This intentionally
    prevents an all-abstained positive slice from appearing perfect.
    """
    eligible_ids = {document.id for document in eligible}
    assessed_ids = {document.id for document in assessed}
    if not assessed_ids <= eligible_ids:
        _reject()
    labels = sorted({annotation.entity_type for document in eligible for annotation in document.annotations})
    scored = (evaluate(assessed, {document.id: predictions[document.id] for document in assessed})["exact"]
              if assessed else None)

    def metrics(label: str | None) -> dict[str, Any]:
        eligible_gold = sum(1 for document in eligible for annotation in document.annotations
                            if label is None or annotation.entity_type == label)
        assessed_gold = sum(1 for document in assessed for annotation in document.annotations
                            if label is None or annotation.entity_type == label)
        abstained_gold = eligible_gold - assessed_gold
        assessed_exact = (scored["corpus"] if label is None else scored["per_entity"].get(label)) if scored else None
        true_positives = assessed_exact["true_positives"] if assessed_exact else 0
        false_negatives = assessed_exact["false_negatives"] if assessed_exact else 0
        conditional_recall = assessed_exact["recall"] if assessed_exact else None
        if eligible_gold == 0:
            lower = upper = None
        else:
            lower = true_positives / eligible_gold
            upper = (true_positives + abstained_gold) / eligible_gold
        return {
            "eligible_documents": len(eligible), "assessed_documents": len(assessed),
            "abstained_documents": len(eligible) - len(assessed),
            "eligible_gold_positives": eligible_gold,
            "assessed_gold_positives": assessed_gold,
            "abstained_gold_positives": abstained_gold,
            "assessed_true_positives": true_positives,
            "assessed_false_negatives": false_negatives,
            "conditional_recall": conditional_recall,
            "operational_recall_lower_bound": lower,
            "operational_recall_upper_bound": upper,
        }

    return {
        "status": "SCORED" if assessed else "ABSTAINED",
        "reason": None if assessed else "NO_ASSESSED_DOCUMENTS",
        "corpus": metrics(None),
        "per_entity": {label: metrics(label) for label in labels},
    }


def _recall_bounds_by_format(documents: tuple[GoldDocument, ...], assessed: tuple[GoldDocument, ...],
                             predictions: dict[str, tuple[Any, ...]], formats: dict[str, str]) -> dict[str, Any]:
    return {
        name: _recall_bounds(
            eligible=tuple(document for document in documents if formats[document.id] == name),
            assessed=tuple(document for document in assessed if formats[document.id] == name),
            predictions=predictions,
        )
        for name in sorted(set(formats.values()))
    }


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
    return {"status": "SCORED", "exact": _counts(gold, predicted),
            "precision_recall": {"corpus": _pr_counts(gold, predicted),
                                  "per_type": {label: _pr_counts({edge for edge in gold if edge[0] == label},
                                                                   {edge for edge in predicted if edge[0] == label})
                                               for label in labels}},
            "per_type": {label: _counts({edge for edge in gold if edge[0] == label},
                                         {edge for edge in predicted if edge[0] == label}) for label in labels},
            "limitations": ["Exact graph claims measure supplied identity keys, not real-world identity resolution.",
                            "Contradictory-claim adjudication is not scored by this schema."]}


def _counts(expected: set[Any], actual: set[Any]) -> dict[str, int]:
    return {"true_positives": len(expected & actual), "false_positives": len(actual - expected),
            "false_negatives": len(expected - actual)}


def _pr_counts(expected: set[Any], actual: set[Any]) -> dict[str, int | float | None]:
    counts = _counts(expected, actual)
    predicted_count = counts["true_positives"] + counts["false_positives"]
    gold_count = counts["true_positives"] + counts["false_negatives"]
    return {**counts, "precision": counts["true_positives"] / predicted_count if predicted_count else None,
            "recall": counts["true_positives"] / gold_count if gold_count else None}


def _evidence_locator_metrics(gold: set[tuple[str, str, str, str]] | None,
                              predicted: set[tuple[str, str, str, str]] | None) -> dict[str, Any]:
    """Score opaque fictional locator bindings, never source locations or IDs."""
    if gold is None and predicted is None:
        return {"status": "ABSTAINED", "reason": "NO_COMPLETE_EVIDENCE_LOCATOR_LABELS"}
    if gold is None or predicted is None or type(gold) is not set or type(predicted) is not set:
        _reject()
    def valid(binding: Any) -> bool:
        return (isinstance(binding, tuple) and len(binding) == 4 and isinstance(binding[3], str)
                and _LOCATOR_ID.fullmatch(binding[3]) is not None
                and _valid_edge(binding[:3]))
    if len(gold) > _MAX_GRAPH_CLAIMS or len(predicted) > _MAX_GRAPH_CLAIMS or not all(valid(item) for item in gold | predicted):
        _reject()
    types = sorted({item[0] for item in gold | predicted})
    return {"status": "SCORED", "precision_recall": {
        "corpus": _pr_counts(gold, predicted),
        "per_type": {kind: _pr_counts({item for item in gold if item[0] == kind},
                                        {item for item in predicted if item[0] == kind}) for kind in types},
    }}


def _locator_gold_matches_graph(locator_gold: set[tuple[str, str, str, str]] | None,
                                graph_gold: set[tuple[str, str, str]] | None) -> None:
    """Keep locator gold distinct from, and complete for, relation gold."""
    if locator_gold is None:
        return
    if type(locator_gold) is not set or type(graph_gold) is not set:
        _reject()
    try:
        bases = {binding[:3] for binding in locator_gold}
    except (TypeError, AttributeError):
        _reject()
    if bases != graph_gold:
        _reject()


def _locator_predictions_match_graph(locator_predictions: set[tuple[str, str, str, str]] | None,
                                     graph_predictions: set[tuple[str, str, str]] | None) -> None:
    """A predicted locator may only bind a relation the same output predicted."""
    if locator_predictions is None:
        return
    if type(locator_predictions) is not set or type(graph_predictions) is not set:
        _reject()
    try:
        bases = {binding[:3] for binding in locator_predictions}
    except (TypeError, AttributeError):
        _reject()
    if not bases <= graph_predictions:
        _reject()


def _valid_edge(edge: Any) -> bool:
    return (isinstance(edge, tuple) and len(edge) == 3 and isinstance(edge[0], str) and edge[0] in _RELATION_TYPES
            and isinstance(edge[1], str) and isinstance(edge[2], str)
            and _RELATION_ENDPOINTS[edge[0]][0].fullmatch(edge[1]) is not None
            and _RELATION_ENDPOINTS[edge[0]][1].fullmatch(edge[2]) is not None)


def _identity_metrics(gold: set[tuple[str, str, str]] | None,
                      predicted: set[tuple[str, str, str]] | None) -> dict[str, Any]:
    """Score complete fictional pair dispositions and their merge clusters.

    A label set contains one MERGE or SPLIT disposition for every unordered
    pair in its identity universe.  This prevents an omitted hard pair from
    turning into an apparent correct merge score.
    """
    if gold is None and predicted is None:
        return {"status": "ABSTAINED", "reason": "NO_COMPLETE_IDENTITY_LABELS"}
    if gold is None or predicted is None or type(gold) is not set or type(predicted) is not set:
        _reject()
    def canonical(item: Any) -> tuple[str, str, str] | None:
        if (not isinstance(item, tuple) or len(item) != 3 or not isinstance(item[0], str)
                or item[0] not in _IDENTITY_DISPOSITIONS
                or not isinstance(item[1], str) or not isinstance(item[2], str)
                or _PERSON_ID.fullmatch(item[1]) is None or _PERSON_ID.fullmatch(item[2]) is None or item[1] == item[2]):
            return None
        return (item[0], *sorted(item[1:]))
    if len(gold) > _MAX_GRAPH_CLAIMS or len(predicted) > _MAX_GRAPH_CLAIMS:
        _reject()
    normalized_gold = [canonical(item) for item in gold]
    normalized_predicted = [canonical(item) for item in predicted]
    if any(item is None for item in normalized_gold + normalized_predicted):
        _reject()
    gold_set, predicted_set = set(normalized_gold), set(normalized_predicted)
    gold_pairs = {(item[1], item[2]) for item in gold_set}
    predicted_pairs = {(item[1], item[2]) for item in predicted_set}
    universe = {identifier for _, left, right in gold_set for identifier in (left, right)}
    complete = {(left, right) for left in universe for right in universe if left < right}
    if (len(universe) < 2 or gold_pairs != complete or predicted_pairs != complete
            or len(gold_pairs) != len(gold_set) or len(predicted_pairs) != len(predicted_set)
            or len(gold_set) != len(gold) or len(predicted_set) != len(predicted)):
        _reject()
    if (not _merge_dispositions_are_transitive(gold_set, universe)
            or not _merge_dispositions_are_transitive(predicted_set, universe)):
        _reject()
    by_disposition = {kind: _pr_counts({item for item in gold_set if item[0] == kind},
                                        {item for item in predicted_set if item[0] == kind})
                      for kind in sorted(_IDENTITY_DISPOSITIONS)}
    return {"status": "SCORED", "pair_dispositions": by_disposition,
            "merge_clusters": _pr_counts(_merge_clusters(gold_set, universe), _merge_clusters(predicted_set, universe))}


def _merge_clusters(dispositions: set[tuple[str, str, str]], universe: set[str]) -> set[frozenset[str]]:
    parents = {identifier: identifier for identifier in universe}
    def root(identifier: str) -> str:
        while parents[identifier] != identifier:
            parents[identifier] = parents[parents[identifier]]
            identifier = parents[identifier]
        return identifier
    for _, left, right in (item for item in dispositions if item[0] == "MERGE"):
        left_root, right_root = root(left), root(right)
        if left_root != right_root:
            parents[right_root] = left_root
    groups: dict[str, set[str]] = {}
    for identifier in universe:
        groups.setdefault(root(identifier), set()).add(identifier)
    return {frozenset(group) for group in groups.values()}


def _merge_dispositions_are_transitive(dispositions: set[tuple[str, str, str]], universe: set[str]) -> bool:
    """All pairs within a merge component must be labelled MERGE, not SPLIT."""
    closed_merges = {
        (left, right)
        for cluster in _merge_clusters(dispositions, universe)
        for left in cluster for right in cluster if left < right
    }
    labelled_merges = {(left, right) for kind, left, right in dispositions if kind == "MERGE"}
    return labelled_merges == closed_merges


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
              final_validation: dict[str, Any] | None = None,
              graph_evidence_gold: set[tuple[str, str, str, str]] | None = None,
              graph_evidence_automatic: set[tuple[str, str, str, str]] | None = None,
              graph_evidence_reviewer_corrected: set[tuple[str, str, str, str]] | None = None,
              identity_gold: set[tuple[str, str, str]] | None = None,
              identity_automatic: set[tuple[str, str, str]] | None = None,
              identity_reviewer_corrected: set[tuple[str, str, str]] | None = None) -> dict[str, Any]:
    """Create a deterministic, aggregate-only synthetic D07 report."""
    if not isinstance(primary_engine, str) or not primary_engine:
        _reject()
    documents = _validated_documents(documents)
    # Parsing here makes direct callers meet the same all-document contract.
    automatic_predictions = parse_predictions(automatic, documents)
    reviewer_predictions = parse_predictions(reviewer_corrected, documents)
    formats = _format_map(documents, formats)
    abstention_summary = _abstentions(documents, abstentions)
    _locator_gold_matches_graph(graph_evidence_gold, graph_gold)
    _locator_predictions_match_graph(graph_evidence_automatic, graph_automatic)
    _locator_predictions_match_graph(graph_evidence_reviewer_corrected, graph_reviewer_corrected)
    assessed_documents = tuple(document for document in documents if document.id not in abstentions)
    by_format = {name: {"automatic": _slice(assessed_documents, automatic_predictions, name, formats),
                        "reviewer_corrected": _slice(assessed_documents, reviewer_predictions, name, formats)}
                 for name in sorted(set(formats.values()))}
    result = {"schema_version": VERSION, "classification": "SYNTHETIC_INTERNAL_EVALUATION_ONLY",
              "qualification": "NOT_QUALIFIED", "automatic": _span_metrics(assessed_documents, automatic_predictions),
              "reviewer_corrected": _span_metrics(assessed_documents, reviewer_predictions), "by_format": by_format,
              "coverage_aware_recall": {
                  "automatic": {"all_formats": _recall_bounds(eligible=documents, assessed=assessed_documents,
                                                                  predictions=automatic_predictions),
                                "by_format": _recall_bounds_by_format(documents, assessed_documents, automatic_predictions, formats)},
                  "reviewer_corrected": {"all_formats": _recall_bounds(eligible=documents, assessed=assessed_documents,
                                                                           predictions=reviewer_predictions),
                                         "by_format": _recall_bounds_by_format(documents, assessed_documents, reviewer_predictions, formats)},
              },
              "abstentions": abstention_summary,
              "graph": {"automatic": _graph_metrics(graph_gold, graph_automatic),
                        "reviewer_corrected": _graph_metrics(graph_gold, graph_reviewer_corrected)},
              "evidence_locator_agreement": {
                  "automatic": _evidence_locator_metrics(graph_evidence_gold, graph_evidence_automatic),
                  "reviewer_corrected": _evidence_locator_metrics(graph_evidence_gold, graph_evidence_reviewer_corrected),
              },
              "identity": {
                  "automatic": _identity_metrics(identity_gold, identity_automatic),
                  "reviewer_corrected": _identity_metrics(identity_gold, identity_reviewer_corrected),
              },
              "final_artifact_validation": _final_validation(final_validation, primary_engine),
              "limitations": ["Synthetic scorecard results are not representative holdout evidence.",
                              "Reviewer-corrected scores are not automatic detector performance.",
                              "Conditional recall excludes abstained documents; operational recall bounds retain their gold positives.",
                              "No same-engine OCR recheck is labelled independent.",
                              "This report does not authorize a release."]}
    result["report_sha256"] = canonical_hash(result)
    return result
