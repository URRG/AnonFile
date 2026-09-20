"""Fail-closed translation of sealed taxonomy policy into worker obligations.

The module accepts only taxonomy families and aggregate finding counts.  It does
not receive source values, paths, spans, candidate bytes, or recipient access;
it cannot approve or export an artifact.  A worker must satisfy the returned
ledger requirements before separately creating private candidate evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from hashlib import sha256
import json
import re
from types import MappingProxyType
from typing import Iterable, Mapping

from app.policies import (PolicySnapshot, SUPPORTED_RELEASE_MODES,
                          TAXONOMY_CATEGORIES)


class TransformationPolicyError(ValueError):
    """Fixed, source-independent failure for policy-to-worker translation."""

    def __init__(self) -> None:
        super().__init__("Invalid transformation policy request")


class CandidateDisposition(StrEnum):
    """Worker handling states; none is a release authorization."""

    TRANSFORM_REQUIRED = "TRANSFORM_REQUIRED"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    QUARANTINE_REQUIRED = "QUARANTINE_REQUIRED"


class TransformationAction(StrEnum):
    SUPPRESS = "SUPPRESS"
    GENERALIZE = "GENERALIZE"
    PSEUDONYMIZE = "PSEUDONYMIZE"


_MAX_FINDINGS = 64
_MAX_COUNT = 1_000_000
_SHA256_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
# Tokenization creates linkability and is therefore never a valid external
# anonymized transformation.  Review and block do not describe transformations.
_MODE_ACTIONS = {
    "external_anonymized": frozenset({"suppress", "generalize", "review", "block"}),
    "restricted_pseudonymized": frozenset({"suppress", "generalize", "tokenize", "review", "block"}),
}
_ACTION_MAP = {
    "suppress": TransformationAction.SUPPRESS,
    "generalize": TransformationAction.GENERALIZE,
    "tokenize": TransformationAction.PSEUDONYMIZE,
}
_DISPOSITION_RANK = {
    CandidateDisposition.QUARANTINE_REQUIRED: 0,
    CandidateDisposition.REVIEW_REQUIRED: 1,
    CandidateDisposition.TRANSFORM_REQUIRED: 2,
}


def _fail() -> None:
    raise TransformationPolicyError()


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=True, sort_keys=True,
                          separators=(",", ":"), allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError):
        _fail()


@dataclass(frozen=True, slots=True)
class AggregateFinding:
    """A category total only; no position, field name, or sensitive value exists."""

    category: str
    count: int

    def __post_init__(self) -> None:
        if self.category not in TAXONOMY_CATEGORIES or type(self.count) is not int or not 1 <= self.count <= _MAX_COUNT:
            _fail()


@dataclass(frozen=True, slots=True)
class AggregateLedgerEntry:
    """A source-free evidence total a private worker can provide to the plan."""

    category: str
    action: TransformationAction
    count: int

    def __post_init__(self) -> None:
        if (self.category not in TAXONOMY_CATEGORIES
                or not isinstance(self.action, TransformationAction)
                or type(self.count) is not int or not 1 <= self.count <= _MAX_COUNT):
            _fail()


@dataclass(frozen=True, slots=True)
class TransformationObligation:
    """One deterministic category obligation from one sealed policy rule."""

    category: str
    policy_action: str
    priority: int
    count: int
    disposition: CandidateDisposition
    ledger_action: TransformationAction | None

    def __post_init__(self) -> None:
        if (self.category not in TAXONOMY_CATEGORIES or type(self.policy_action) is not str
                or type(self.priority) is not int or not 0 <= self.priority <= 10_000
                or type(self.count) is not int or not 1 <= self.count <= _MAX_COUNT
                or not isinstance(self.disposition, CandidateDisposition)
                or (self.ledger_action is not None and not isinstance(self.ledger_action, TransformationAction))):
            _fail()
        if self.policy_action in _ACTION_MAP:
            if self.disposition is not CandidateDisposition.TRANSFORM_REQUIRED or self.ledger_action is not _ACTION_MAP[self.policy_action]:
                _fail()
        elif self.policy_action == "review":
            if self.disposition is not CandidateDisposition.REVIEW_REQUIRED or self.ledger_action is not None:
                _fail()
        elif self.policy_action == "block":
            if self.disposition is not CandidateDisposition.QUARANTINE_REQUIRED or self.ledger_action is not None:
                _fail()
        else:
            _fail()


@dataclass(frozen=True, slots=True)
class TransformationPlan:
    """Immutable, metadata-only worker plan with no deliverable state."""

    policy_digest: str
    release_mode: str
    obligations: tuple[TransformationObligation, ...]
    disposition: CandidateDisposition
    primary_category: str
    digest: str = field(init=False)

    def __post_init__(self) -> None:
        if (type(self.policy_digest) is not str or not _SHA256_DIGEST.fullmatch(self.policy_digest)
                or self.release_mode not in SUPPORTED_RELEASE_MODES
                or not isinstance(self.obligations, tuple) or not self.obligations
                or any(not isinstance(item, TransformationObligation) for item in self.obligations)
                or len(self.obligations) > _MAX_FINDINGS
                or len({item.category for item in self.obligations}) != len(self.obligations)
                or not isinstance(self.disposition, CandidateDisposition)
                or self.primary_category not in TAXONOMY_CATEGORIES):
            _fail()
        # Construction is public (including deserialization paths), so it must
        # preserve the same mode/action boundary as the builder.  In
        # particular, tokenization is never valid for an external-anonymized
        # plan even if a caller creates obligations directly.
        if any(item.policy_action not in _MODE_ACTIONS[self.release_mode] for item in self.obligations):
            _fail()
        ordered = tuple(sorted(self.obligations, key=lambda item: (item.priority, _DISPOSITION_RANK[item.disposition], item.category)))
        if self.obligations != ordered or self.primary_category != ordered[0].category:
            _fail()
        expected = min(ordered, key=lambda item: (_DISPOSITION_RANK[item.disposition], item.priority, item.category)).disposition
        if self.disposition is not expected:
            _fail()
        object.__setattr__(self, "digest", "sha256:" + sha256(_canonical(self._canonical())).hexdigest())

    def _canonical(self) -> dict[str, object]:
        return {
            "obligations": [
                {"category": item.category, "count": item.count, "disposition": item.disposition.value,
                 "ledger_action": item.ledger_action.value if item.ledger_action else None,
                 "policy_action": item.policy_action, "priority": item.priority}
                for item in self.obligations
            ],
            "policy_digest": self.policy_digest,
            "primary_category": self.primary_category,
            "release_mode": self.release_mode,
            "disposition": self.disposition.value,
        }

    @property
    def ledger_requirements(self) -> tuple[AggregateLedgerEntry, ...]:
        """Exact aggregate transform evidence required for transform obligations."""
        return tuple(AggregateLedgerEntry(item.category, item.ledger_action, item.count)
                     for item in self.obligations if item.ledger_action is not None)

    def explain(self) -> Mapping[str, object]:
        """Immutable source-free explanation for protected audit/evidence records."""
        return MappingProxyType({
            "digest": self.digest,
            "disposition": self.disposition.value,
            "ledger_requirements": tuple(
                {"category": item.category, "action": item.action.value, "count": item.count}
                for item in self.ledger_requirements
            ),
            "policy_digest": self.policy_digest,
            "primary_category": self.primary_category,
            "release_mode": self.release_mode,
        })


def build_transformation_plan(*, policy: PolicySnapshot, release_mode: str,
                              findings: Iterable[AggregateFinding]) -> TransformationPlan:
    """Map a sealed policy and aggregate detections to deterministic obligations."""
    if not isinstance(policy, PolicySnapshot) or release_mode not in SUPPORTED_RELEASE_MODES:
        _fail()
    if release_mode not in policy.release_modes or isinstance(findings, (str, bytes)):
        _fail()
    try:
        observed = tuple(findings)
    except TypeError:
        _fail()
    if (not observed or len(observed) > _MAX_FINDINGS or any(not isinstance(item, AggregateFinding) for item in observed)
            or len({item.category for item in observed}) != len(observed)):
        _fail()
    obligations = []
    for finding in observed:
        try:
            rule = policy.rule_for(finding.category)
        except ValueError:
            _fail()
        if rule.action not in _MODE_ACTIONS[release_mode]:
            # A policy cannot silently weaken tokenize into suppression or
            # select an unrelated mode; callers must choose an eligible policy.
            _fail()
        ledger_action = _ACTION_MAP.get(rule.action)
        disposition = (CandidateDisposition.TRANSFORM_REQUIRED if ledger_action is not None
                       else CandidateDisposition.REVIEW_REQUIRED if rule.action == "review"
                       else CandidateDisposition.QUARANTINE_REQUIRED)
        obligations.append(TransformationObligation(finding.category, rule.action, rule.priority,
                                                     finding.count, disposition, ledger_action))
    ordered = tuple(sorted(obligations, key=lambda item: (item.priority, _DISPOSITION_RANK[item.disposition], item.category)))
    disposition = min(ordered, key=lambda item: (_DISPOSITION_RANK[item.disposition], item.priority, item.category)).disposition
    return TransformationPlan(policy.digest, release_mode, ordered, disposition, ordered[0].category)


def verify_aggregate_ledger(*, plan: TransformationPlan,
                            entries: Iterable[AggregateLedgerEntry]) -> None:
    """Require exact source-free aggregate evidence; missing/extra entries fail closed."""
    if not isinstance(plan, TransformationPlan) or isinstance(entries, (str, bytes)):
        _fail()
    try:
        actual = tuple(entries)
    except TypeError:
        _fail()
    if (any(not isinstance(item, AggregateLedgerEntry) for item in actual)
            or len({item.category for item in actual}) != len(actual)):
        _fail()
    expected = plan.ledger_requirements
    if len(actual) != len(expected):
        _fail()
    wanted = {(item.category, item.action, item.count) for item in expected}
    received = {(item.category, item.action, item.count) for item in actual}
    if wanted != received:
        _fail()
