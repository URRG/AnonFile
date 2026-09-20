"""Bounded, source-free annotation scoring for detector evaluation.

This contract deliberately accepts no source payloads, snippets, field paths,
or offsets.  An annotation boundary supplies opaque, high-entropy reference
digests for entity occurrences; this scorer compares those references with a
detector's similarly protected observations.  Callers must not derive a
reference digest directly from low-entropy personal data.

Scores are deterministic internal measurement evidence only.  They do not
measure transformed-output disclosure, linkage risk, utility, or authorize a
candidate, release, export, or delivery.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
import hashlib
import json
import re
from typing import Iterable

from app.benchmark_evidence import CategoryMetrics
from app.policies import TAXONOMY_CATEGORIES


MAX_CASES = 10_000
MAX_FINDINGS_PER_CASE = 10_000
MAX_TOTAL_FINDINGS = 100_000
MAX_LIMITATIONS = 16
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class EvaluationHarnessError(ValueError):
    """A fixed failure that never reflects annotations or source metadata."""

    def __init__(self) -> None:
        super().__init__("Invalid evaluation harness input")


class EvaluationPosture(StrEnum):
    """A scored corpus is evidence, never a release decision."""

    OBSERVATIONAL_ONLY = "OBSERVATIONAL_ONLY"


def _fail() -> None:
    raise EvaluationHarnessError()


def _identifier(value: object) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _time(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        _fail()
    return value.astimezone(UTC).replace(microsecond=0)


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()


def _hash(value: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class AnnotatedFinding:
    """One protected entity occurrence, represented only by an opaque digest."""

    reference_digest: str = field(repr=False)
    category: str

    def __post_init__(self) -> None:
        _digest(self.reference_digest)
        if type(self.category) is not str or self.category not in TAXONOMY_CATEGORIES:
            _fail()

    def canonical(self) -> dict[str, str]:
        return {"category": self.category, "reference_digest": self.reference_digest}


@dataclass(frozen=True, slots=True)
class AnnotatedCase:
    """An annotation case without its text, payload, offsets, or field paths."""

    case_id: str
    findings: tuple[AnnotatedFinding, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _identifier(self.case_id)
        # A clean, annotated negative case is essential for measuring detector
        # false positives.  The corpus itself remains nonempty and bounded.
        if (type(self.findings) is not tuple or len(self.findings) > MAX_FINDINGS_PER_CASE
                or any(not isinstance(item, AnnotatedFinding) for item in self.findings)):
            _fail()
        ordered = tuple(sorted(self.findings, key=lambda item: (item.category, item.reference_digest)))
        if ordered != self.findings or len({item.reference_digest for item in self.findings}) != len(self.findings):
            _fail()

    def canonical(self) -> dict[str, object]:
        return {"case_id": self.case_id, "findings": [item.canonical() for item in self.findings]}


@dataclass(frozen=True, slots=True)
class AnnotatedCorpus:
    """Immutable annotation corpus identity and its source-free case manifest."""

    corpus_id: str
    corpus_version: str
    source_manifest_digest: str = field(repr=False)
    annotation_protocol_digest: str = field(repr=False)
    provenance_digest: str = field(repr=False)
    assessed_categories: frozenset[str]
    cases: tuple[AnnotatedCase, ...] = field(repr=False)
    digest: str = field(init=False)

    @classmethod
    def create(cls, *, corpus_id: str, corpus_version: str, source_manifest_digest: str,
               annotation_protocol_digest: str, provenance_digest: str,
               assessed_categories: Iterable[str], cases: Iterable[AnnotatedCase]) -> "AnnotatedCorpus":
        if isinstance(assessed_categories, (str, bytes)) or isinstance(cases, (str, bytes)):
            _fail()
        try:
            categories = frozenset(assessed_categories)
            case_values = tuple(cases)
        except TypeError:
            _fail()
        return cls(corpus_id, corpus_version, source_manifest_digest, annotation_protocol_digest,
                   provenance_digest, categories, tuple(sorted(case_values, key=lambda item: item.case_id)))

    def __post_init__(self) -> None:
        _identifier(self.corpus_id)
        _identifier(self.corpus_version)
        for value in (self.source_manifest_digest, self.annotation_protocol_digest, self.provenance_digest):
            _digest(value)
        if (type(self.assessed_categories) is not frozenset or not self.assessed_categories
                or any(type(category) is not str or category not in TAXONOMY_CATEGORIES
                       for category in self.assessed_categories)
                or type(self.cases) is not tuple or not self.cases or len(self.cases) > MAX_CASES
                or any(not isinstance(item, AnnotatedCase) for item in self.cases)
                or tuple(sorted(self.cases, key=lambda item: item.case_id)) != self.cases
                or len({item.case_id for item in self.cases}) != len(self.cases)
                or sum(len(item.findings) for item in self.cases) > MAX_TOTAL_FINDINGS):
            _fail()
        if any(finding.category not in self.assessed_categories
               for case in self.cases for finding in case.findings):
            _fail()
        object.__setattr__(self, "digest", _hash(self.canonical()))

    def canonical(self) -> dict[str, object]:
        return {
            "annotation_protocol_digest": self.annotation_protocol_digest,
            "assessed_categories": sorted(self.assessed_categories),
            "cases": [item.canonical() for item in self.cases],
            "corpus_id": self.corpus_id,
            "corpus_version": self.corpus_version,
            "provenance_digest": self.provenance_digest,
            "source_manifest_digest": self.source_manifest_digest,
        }


@dataclass(frozen=True, slots=True)
class PredictionCase:
    """Detector observations for one corpus case; duplicate observations stay visible."""

    case_id: str
    findings: tuple[AnnotatedFinding, ...] = field(repr=False)

    def __post_init__(self) -> None:
        _identifier(self.case_id)
        if (type(self.findings) is not tuple or len(self.findings) > MAX_FINDINGS_PER_CASE
                or any(not isinstance(item, AnnotatedFinding) for item in self.findings)
                or tuple(sorted(self.findings, key=lambda item: (item.category, item.reference_digest))) != self.findings):
            _fail()

    def canonical(self) -> dict[str, object]:
        return {"case_id": self.case_id, "findings": [item.canonical() for item in self.findings]}


@dataclass(frozen=True, slots=True)
class PredictionSet:
    """A complete detector output declaration bound to one immutable corpus."""

    corpus_digest: str = field(repr=False)
    output_digest: str = field(repr=False)
    cases: tuple[PredictionCase, ...] = field(repr=False)
    digest: str = field(init=False)

    @classmethod
    def create(cls, *, corpus_digest: str, output_digest: str,
               cases: Iterable[PredictionCase]) -> "PredictionSet":
        if isinstance(cases, (str, bytes)):
            _fail()
        try:
            values = tuple(cases)
        except TypeError:
            _fail()
        return cls(corpus_digest, output_digest, tuple(sorted(values, key=lambda item: item.case_id)))

    def __post_init__(self) -> None:
        _digest(self.corpus_digest)
        _digest(self.output_digest)
        if (type(self.cases) is not tuple or len(self.cases) > MAX_CASES
                or any(not isinstance(item, PredictionCase) for item in self.cases)
                or tuple(sorted(self.cases, key=lambda item: item.case_id)) != self.cases
                or len({item.case_id for item in self.cases}) != len(self.cases)
                or sum(len(item.findings) for item in self.cases) > MAX_TOTAL_FINDINGS):
            _fail()
        object.__setattr__(self, "digest", _hash(self.canonical()))

    def canonical(self) -> dict[str, object]:
        return {"cases": [item.canonical() for item in self.cases], "corpus_digest": self.corpus_digest,
                "output_digest": self.output_digest}


@dataclass(frozen=True, slots=True)
class ScoringBinding:
    """Versions and digests needed to reproduce or reject scored evidence."""

    evaluator_id: str
    evaluator_version: str
    evaluator_config_digest: str = field(repr=False)
    detector_id: str
    detector_version: str
    detector_config_digest: str = field(repr=False)
    taxonomy_mapping_digest: str = field(repr=False)
    corpus_digest: str = field(repr=False)
    prediction_set_digest: str = field(repr=False)

    def __post_init__(self) -> None:
        for value in (self.evaluator_id, self.evaluator_version, self.detector_id, self.detector_version):
            _identifier(value)
        for value in (self.evaluator_config_digest, self.detector_config_digest,
                      self.taxonomy_mapping_digest, self.corpus_digest, self.prediction_set_digest):
            _digest(value)

    def canonical(self) -> dict[str, str]:
        return {
            "corpus_digest": self.corpus_digest,
            "detector_config_digest": self.detector_config_digest,
            "detector_id": self.detector_id,
            "detector_version": self.detector_version,
            "evaluator_config_digest": self.evaluator_config_digest,
            "evaluator_id": self.evaluator_id,
            "evaluator_version": self.evaluator_version,
            "prediction_set_digest": self.prediction_set_digest,
            "taxonomy_mapping_digest": self.taxonomy_mapping_digest,
        }


@dataclass(frozen=True, slots=True)
class ScoredEvaluation:
    """Source-free aggregate detector score with an immutable evidence digest."""

    binding: ScoringBinding = field(repr=False)
    metrics: tuple[CategoryMetrics, ...]
    evaluated_at: datetime = field(repr=False)
    posture: EvaluationPosture = EvaluationPosture.OBSERVATIONAL_ONLY
    limitations: tuple[str, ...] = ("ANNOTATION_AGREEMENT_ONLY", "NO_RELEASE_AUTHORIZATION",
                                    "OUTPUT_DISCLOSURE_NOT_EVALUATED")
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.binding, ScoringBinding):
            _fail()
        if (type(self.metrics) is not tuple or not self.metrics
                or any(not isinstance(item, CategoryMetrics) for item in self.metrics)
                or tuple(sorted(self.metrics, key=lambda item: item.category)) != self.metrics
                or len({item.category for item in self.metrics}) != len(self.metrics)):
            _fail()
        object.__setattr__(self, "evaluated_at", _time(self.evaluated_at))
        if self.posture is not EvaluationPosture.OBSERVATIONAL_ONLY:
            _fail()
        if (type(self.limitations) is not tuple or not 1 <= len(self.limitations) <= MAX_LIMITATIONS
                or any(type(item) is not str or not _IDENTIFIER.fullmatch(item.lower()) for item in self.limitations)
                or len(set(self.limitations)) != len(self.limitations)
                or "NO_RELEASE_AUTHORIZATION" not in self.limitations):
            _fail()
        object.__setattr__(self, "digest", _hash(self.canonical()))

    def canonical(self) -> dict[str, object]:
        return {"binding": self.binding.canonical(), "evaluated_at": self.evaluated_at.isoformat().replace("+00:00", "Z"),
                "limitations": list(self.limitations), "metrics": [item.canonical() for item in self.metrics],
                "posture": self.posture.value}

    def to_record(self) -> dict[str, object]:
        return {**self.canonical(), "digest": self.digest,
                "metrics": [{**item.canonical(), "precision_ppm": item.precision_ppm,
                             "recall_ppm": item.recall_ppm, "f1_ppm": item.f1_ppm}
                            for item in self.metrics]}

    @classmethod
    def from_record(cls, value: object) -> "ScoredEvaluation":
        """Verify a persisted aggregate record before it can be used as evidence."""
        expected = {"binding", "digest", "evaluated_at", "limitations", "metrics", "posture"}
        if not isinstance(value, dict) or set(value) != expected:
            _fail()
        try:
            if not isinstance(value["binding"], dict) or type(value["metrics"]) is not list:
                _fail()
            binding = ScoringBinding(**value["binding"])
            metrics = []
            for item in value["metrics"]:
                if (not isinstance(item, dict) or set(item) != {"category", "true_positives", "false_positives",
                                                               "false_negatives", "precision_ppm", "recall_ppm", "f1_ppm"}):
                    _fail()
                metric = CategoryMetrics(item["category"], item["true_positives"], item["false_positives"],
                                         item["false_negatives"])
                if (item["precision_ppm"], item["recall_ppm"], item["f1_ppm"]) != (
                        metric.precision_ppm, metric.recall_ppm, metric.f1_ppm):
                    _fail()
                metrics.append(metric)
            if (type(value["evaluated_at"]) is not str or type(value["posture"]) is not str
                    or type(value["limitations"]) is not list):
                _fail()
            result = cls(binding=binding, metrics=tuple(metrics),
                         evaluated_at=datetime.fromisoformat(value["evaluated_at"].replace("Z", "+00:00")),
                         posture=EvaluationPosture(value["posture"]), limitations=tuple(value["limitations"]))
            if value["digest"] != result.digest:
                _fail()
            return result
        except (TypeError, ValueError, KeyError, OverflowError):
            _fail()


def score(*, corpus: AnnotatedCorpus, predictions: PredictionSet, binding: ScoringBinding,
          evaluated_at: datetime) -> ScoredEvaluation:
    """Score exact protected-reference matches per explicitly assessed family.

    A score refuses partial prediction sets and any provenance mismatch.  It is
    intentionally separate from candidate/residual/qualification workflows.
    """
    if not isinstance(corpus, AnnotatedCorpus) or not isinstance(predictions, PredictionSet) or not isinstance(binding, ScoringBinding):
        _fail()
    if (predictions.corpus_digest != corpus.digest or binding.corpus_digest != corpus.digest
            or binding.prediction_set_digest != predictions.digest):
        _fail()
    expected_ids = {item.case_id for item in corpus.cases}
    if {item.case_id for item in predictions.cases} != expected_ids:
        _fail()
    counts = {category: [0, 0, 0] for category in corpus.assessed_categories}
    expected_by_case = {item.case_id: item.findings for item in corpus.cases}
    for predicted_case in predictions.cases:
        if any(item.category not in corpus.assessed_categories for item in predicted_case.findings):
            _fail()
        expected = {(item.category, item.reference_digest) for item in expected_by_case[predicted_case.case_id]}
        observed = [(item.category, item.reference_digest) for item in predicted_case.findings]
        matched = set()
        for item in observed:
            if item in expected and item not in matched:
                counts[item[0]][0] += 1
                matched.add(item)
            else:
                counts[item[0]][1] += 1
        for category, _reference in expected - matched:
            counts[category][2] += 1
    metrics = tuple(CategoryMetrics(category, *counts[category]) for category in sorted(counts))
    return ScoredEvaluation(binding=binding, metrics=metrics, evaluated_at=evaluated_at)
