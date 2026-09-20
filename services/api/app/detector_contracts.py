"""Strict, aggregate-only contract for pluggable sensitive-data detectors.

Adapters receive private candidate bytes in their own execution boundary, but
this module retains only a versioned identity, taxonomy-mapped aggregate counts
and explicit coverage.  It never accepts snippets, offsets, field paths or
matched values as adapter output, and no report here authorizes a release.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Callable, Mapping

from app.policies import TAXONOMY_CATEGORIES


MAX_CONFIG_BYTES = 65_536
MAX_CONFIG_NODES = 10_000
MAX_DEPTH = 16
MAX_UNITS = 10_000
MAX_LABELS = 128
MAX_FINDINGS_PER_CATEGORY = 1_000_000
_IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._:-]{0,127}\Z")
_LABEL = re.compile(r"[A-Z][A-Z0-9_.-]{0,63}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class DetectorContractError(ValueError):
    """Fixed, source-independent detector contract failure."""

    MESSAGE = "Invalid detector contract."

    def __init__(self, message: str | None = None) -> None:
        super().__init__(self.MESSAGE if message is None else message)


class CoverageStatus(StrEnum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    ABSTAINED = "ABSTAINED"


def _fail(message: str | None = None) -> None:
    raise DetectorContractError(message)


def _identifier(value: object) -> str:
    if type(value) is not str or not _IDENTIFIER.fullmatch(value):
        _fail()
    return value


def _label(value: object) -> str:
    if type(value) is not str or not _LABEL.fullmatch(value):
        _fail()
    return value


def _digest(value: object) -> str:
    if type(value) is not str or not _DIGEST.fullmatch(value):
        _fail()
    return value


def _hash(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _validate_config(value: Any) -> None:
    nodes = 0
    active: set[int] = set()
    stack: list[tuple[Any, int, bool]] = [(value, 0, False)]
    while stack:
        current, depth, exiting = stack.pop()
        if exiting:
            active.remove(id(current))
            continue
        nodes += 1
        if nodes > MAX_CONFIG_NODES or depth > MAX_DEPTH:
            _fail()
        kind = type(current)
        if kind in (dict, list):
            if id(current) in active or len(current) > MAX_CONFIG_NODES:
                _fail()
            active.add(id(current))
            stack.append((current, depth, True))
            if kind is dict:
                for key, child in current.items():
                    if type(key) is not str:
                        _fail()
                    try:
                        key.encode("utf-8")
                    except UnicodeError:
                        _fail()
                    stack.append((child, depth + 1, False))
            else:
                stack.extend((child, depth + 1, False) for child in current)
        elif kind is str:
            try:
                current.encode("utf-8")
            except UnicodeError:
                _fail()
        elif kind is float and not math.isfinite(current):
            _fail()
        elif kind not in (int, float, bool) and current is not None:
            _fail()


def canonical_configuration(configuration: Any) -> bytes:
    """Canonicalize a bounded adapter config, returning bytes only for hashing."""
    _validate_config(configuration)
    try:
        result = json.dumps(configuration, ensure_ascii=False, allow_nan=False,
                            sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        _fail()
    if len(result) > MAX_CONFIG_BYTES:
        _fail()
    return result


@dataclass(frozen=True, slots=True)
class DetectorIdentity:
    """Stable detector code/version plus a digest of its exact configuration."""

    detector_id: str
    version: str
    config_digest: str

    @classmethod
    def from_configuration(cls, *, detector_id: str, version: str,
                           configuration: Any) -> "DetectorIdentity":
        return cls(_identifier(detector_id), _identifier(version),
                   _hash(canonical_configuration(configuration)))

    def __post_init__(self) -> None:
        _identifier(self.detector_id)
        _identifier(self.version)
        _digest(self.config_digest)


@dataclass(frozen=True, slots=True)
class TaxonomyMapper:
    """Immutable explicit mapping from adapter labels to policy categories."""

    entries: tuple[tuple[str, str], ...]
    digest: str = field(init=False)

    @classmethod
    def create(cls, mapping: Mapping[str, str]) -> "TaxonomyMapper":
        if not isinstance(mapping, Mapping) or not mapping or len(mapping) > MAX_LABELS:
            _fail()
        entries = tuple(sorted((_label(label), category) for label, category in mapping.items()))
        return cls(entries)

    def __post_init__(self) -> None:
        if type(self.entries) is not tuple or not self.entries or len(self.entries) > MAX_LABELS:
            _fail()
        labels: list[str] = []
        clean: list[tuple[str, str]] = []
        for item in self.entries:
            if type(item) is not tuple or len(item) != 2:
                _fail()
            label, category = _label(item[0]), item[1]
            if type(category) is not str or category not in TAXONOMY_CATEGORIES:
                _fail()
            labels.append(label)
            clean.append((label, category))
        if len(labels) != len(set(labels)) or tuple(sorted(clean)) != tuple(clean):
            _fail()
        encoded = canonical_configuration({"taxonomy": [[label, category] for label, category in clean]})
        object.__setattr__(self, "digest", _hash(encoded))

    def category_for(self, label: str) -> str:
        value = _label(label)
        for adapter_label, category in self.entries:
            if adapter_label == value:
                return category
        _fail()

    @property
    def categories(self) -> frozenset[str]:
        """Families this concrete adapter configuration can claim to assess."""
        return frozenset(category for _, category in self.entries)


@dataclass(frozen=True, slots=True)
class AdapterResult:
    """Only aggregate per-label counts and coverage leave an adapter boundary.

    ``attempted_units`` includes deliberately abstained units.  Assessed coverage
    is therefore ``attempted_units - abstained_units``; unattempted units also
    count as uncovered.  Counts are occurrences, not unique people/records.
    """

    label_counts: Mapping[str, int]
    total_units: int
    attempted_units: int
    assessed_categories: frozenset[str]
    abstained_units: int = 0
    abstained_categories: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        if not isinstance(self.label_counts, Mapping) or len(self.label_counts) > MAX_LABELS:
            _fail()
        values: dict[str, int] = {}
        for label, count in self.label_counts.items():
            key = _label(label)
            if (key in values or type(count) is not int or isinstance(count, bool)
                    or not 0 <= count <= MAX_FINDINGS_PER_CATEGORY):
                _fail()
            values[key] = count
        for value in (self.total_units, self.attempted_units, self.abstained_units):
            if type(value) is not int or isinstance(value, bool) or not 0 <= value <= MAX_UNITS:
                _fail()
        if self.total_units < 1 or self.abstained_units > self.attempted_units or self.attempted_units > self.total_units:
            _fail()
        if (type(self.assessed_categories) is not frozenset
                or type(self.abstained_categories) is not frozenset
                or not self.assessed_categories.isdisjoint(self.abstained_categories)
                or self.assessed_categories | self.abstained_categories != TAXONOMY_CATEGORIES):
            _fail()
        if any(type(category) is not str or category not in TAXONOMY_CATEGORIES
               for category in self.assessed_categories | self.abstained_categories):
            _fail()
        object.__setattr__(self, "label_counts", MappingProxyType(dict(sorted(values.items()))))


@dataclass(frozen=True, slots=True)
class Coverage:
    total_units: int
    attempted_units: int
    abstained_units: int
    assessed_units: int
    percent: int
    status: CoverageStatus
    assessed_categories: frozenset[str]
    abstained_categories: frozenset[str]

    def __post_init__(self) -> None:
        for value in (self.total_units, self.attempted_units, self.abstained_units,
                      self.assessed_units, self.percent):
            if type(value) is not int or isinstance(value, bool):
                _fail()
        if (not 1 <= self.total_units <= MAX_UNITS or not 0 <= self.attempted_units <= self.total_units
                or not 0 <= self.abstained_units <= self.attempted_units
                or self.assessed_units != self.attempted_units - self.abstained_units
                or self.percent != (self.assessed_units * 100) // self.total_units
                or not isinstance(self.status, CoverageStatus)
                or type(self.assessed_categories) is not frozenset
                or type(self.abstained_categories) is not frozenset
                or not self.assessed_categories.isdisjoint(self.abstained_categories)
                or self.assessed_categories | self.abstained_categories != TAXONOMY_CATEGORIES
                or any(type(category) is not str or category not in TAXONOMY_CATEGORIES
                       for category in self.assessed_categories | self.abstained_categories)):
            _fail()
        # A complete unit scan cannot be called complete if a policy family was
        # absent from detector coverage. Explicit category abstention remains
        # visible and is necessarily PARTIAL/ABSTAINED evidence.
        expected = (CoverageStatus.COMPLETE if (self.assessed_units == self.total_units
                                                and self.assessed_categories == TAXONOMY_CATEGORIES) else
                    CoverageStatus.ABSTAINED if self.assessed_units == 0 and self.abstained_units else
                    CoverageStatus.PARTIAL)
        if self.status is not expected:
            _fail()

    @classmethod
    def from_result(cls, result: AdapterResult) -> "Coverage":
        if not isinstance(result, AdapterResult):
            _fail()
        assessed = result.attempted_units - result.abstained_units
        percent = (assessed * 100) // result.total_units
        status = (CoverageStatus.COMPLETE if (assessed == result.total_units
                                              and result.assessed_categories == TAXONOMY_CATEGORIES) else
                  CoverageStatus.ABSTAINED if assessed == 0 and result.abstained_units else
                  CoverageStatus.PARTIAL)
        return cls(result.total_units, result.attempted_units, result.abstained_units,
                   assessed, percent, status, result.assessed_categories,
                   result.abstained_categories)


@dataclass(frozen=True, slots=True)
class AggregateFinding:
    category: str
    count: int

    def __post_init__(self) -> None:
        if (type(self.category) is not str or self.category not in TAXONOMY_CATEGORIES
                or type(self.count) is not int or isinstance(self.count, bool)
                or not 0 <= self.count <= MAX_FINDINGS_PER_CATEGORY):
            _fail()


@dataclass(frozen=True, slots=True)
class DetectorEvidence:
    """Persistable aggregate evidence, never a source/candidate representation."""

    identity: DetectorIdentity
    mapping_digest: str
    mapped_categories: frozenset[str]
    findings: tuple[AggregateFinding, ...]
    coverage: Coverage
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if not isinstance(self.identity, DetectorIdentity) or not isinstance(self.coverage, Coverage):
            _fail()
        _digest(self.mapping_digest)
        if (type(self.mapped_categories) is not frozenset
                or self.mapped_categories != self.coverage.assessed_categories
                or any(type(category) is not str or category not in TAXONOMY_CATEGORIES
                       for category in self.mapped_categories)):
            _fail()
        if (type(self.findings) is not tuple or len(self.findings) > len(TAXONOMY_CATEGORIES)
                or any(not isinstance(item, AggregateFinding) for item in self.findings)
                or tuple(sorted(self.findings, key=lambda item: item.category)) != self.findings
                or len({item.category for item in self.findings}) != len(self.findings)):
            _fail()
        payload = self.to_record(include_digest=False)
        object.__setattr__(self, "digest", _hash(canonical_configuration(payload)))

    def to_record(self, *, include_digest: bool = True) -> dict[str, Any]:
        result: dict[str, Any] = {
            "detector_id": self.identity.detector_id,
            "detector_version": self.identity.version,
            "config_digest": self.identity.config_digest,
            "mapping_digest": self.mapping_digest,
            "mapped_categories": sorted(self.mapped_categories),
            "findings": {item.category: item.count for item in self.findings},
            "coverage": {"total_units": self.coverage.total_units,
                         "attempted_units": self.coverage.attempted_units,
                         "abstained_units": self.coverage.abstained_units,
                         "assessed_units": self.coverage.assessed_units,
                         "percent": self.coverage.percent,
                         "status": self.coverage.status.value},
        }
        if include_digest:
            result["digest"] = self.digest
        return result


def normalize_result(*, identity: DetectorIdentity, mapper: TaxonomyMapper,
                     result: AdapterResult) -> DetectorEvidence:
    """Map aggregate adapter labels to taxonomy families, failing on any gap."""
    if not isinstance(identity, DetectorIdentity) or not isinstance(mapper, TaxonomyMapper) or not isinstance(result, AdapterResult):
        _fail()
    # A mapping is a coverage assertion, not a menu of labels a caller may
    # quietly omit. Every assessed family needs a declared mapping and no
    # mapped family may be represented as unassessed/abstained this run.
    if mapper.categories != result.assessed_categories:
        _fail()
    totals: dict[str, int] = {}
    for label, count in result.label_counts.items():
        category = mapper.category_for(label)  # unknown mappings fail; never drop findings.
        updated = totals.get(category, 0) + count
        if updated > MAX_FINDINGS_PER_CATEGORY:
            _fail()
        totals[category] = updated
    findings = tuple(AggregateFinding(category, count) for category, count in sorted(totals.items()))
    return DetectorEvidence(identity, mapper.digest, mapper.categories, findings, Coverage.from_result(result))


def execute_adapter(*, adapter: Callable[[Any], AdapterResult], candidate: Any,
                    identity: DetectorIdentity, mapper: TaxonomyMapper) -> DetectorEvidence:
    """Execute an adapter without allowing its errors or output values to escape."""
    if not callable(adapter):
        _fail()
    try:
        result = adapter(candidate)
    except BaseException:
        raise DetectorContractError("Detector execution failed.") from None
    if not isinstance(result, AdapterResult):
        _fail()
    return normalize_result(identity=identity, mapper=mapper, result=result)
