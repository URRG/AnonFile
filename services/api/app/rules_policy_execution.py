"""Fail-closed bridge between the rules processor and M4 policy obligations.

``processing`` intentionally reports detector labels and an output payload, while
``transformation_policy`` intentionally operates only on sealed taxonomy
families.  This module joins those two contracts without treating a detector
count as proof of a transformation.  The caller must supply source-free,
aggregate output-operation observations from the worker.  In particular, this
adapter never guesses that a finding was redacted simply because it was found.

The bridge creates no candidate, grants no approval, and exposes no source
values, paths, spans, or transformed bytes.  A caller may create a private
candidate only when ``can_create_private_candidate`` is true.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping

from app.candidate import LedgerAction, LedgerReason, TransformLedgerEntry
from app.contracts import Finding, ProcessingResult
from app.policies import PolicySnapshot, TAXONOMY_CATEGORIES
from app.transformation_policy import (
    AggregateFinding,
    AggregateLedgerEntry,
    CandidateDisposition,
    TransformationAction,
    TransformationPlan,
    TransformationPolicyError,
    build_transformation_plan,
)


class RulesPolicyExecutionError(ValueError):
    """Fixed, source-independent failure from the rules-to-policy bridge."""

    MESSAGE = "Invalid rules policy execution."

    def __init__(self) -> None:
        super().__init__(self.MESSAGE)


def _fail() -> None:
    raise RulesPolicyExecutionError()


# Every label below has a concrete bounded recognizer in ``processing``.  That
# makes the mapping safe for finding/operation accounting, but it does *not*
# make every family policy-qualified: the new health, business and quasi rules
# have no calibrated corpus, semantic model, or linkage evaluation.  Keep that
# distinction explicit so adding a recognizer cannot silently make rules-v1
# eligible to create an all-taxonomy candidate.
RULES_LABEL_TO_CATEGORY: Mapping[str, str] = MappingProxyType({
    "AADHAAR": "PII",
    "ADDRESS": "PII",
    "CARD": "PAYMENT",
    "CREDENTIAL": "CREDENTIAL",
    "DATE_OF_BIRTH": "PII",
    "EMAIL": "PII",
    "GOVERNMENT_ID": "PII",
    "HEALTH_SENSITIVE": "HEALTH_SENSITIVE",
    "IP_ADDRESS": "PII",
    "PAN": "PII",
    "PAYMENT_SECRET": "PAYMENT",
    "PERSON_NAME": "PII",
    "PHONE": "PII",
    "SENSITIVE_NUMBER": "PII",
    "BUSINESS_CONFIDENTIAL": "BUSINESS_CONFIDENTIAL",
    "QUASI_IDENTIFIER": "QUASI_IDENTIFIER",
})
# Categories for which this implementation has at least one bounded detector.
# This is useful metadata for an evaluator and must never be interpreted as a
# release/qualification assertion.
RULES_DETECTED_CATEGORIES = frozenset(RULES_LABEL_TO_CATEGORY.values())

# Categories with the legacy policy bridge support only.  The three new
# detector families remain deliberately unqualified until they have independent
# evaluation evidence and governed operational semantics.  M5's fail-closed
# full-taxonomy execution gate relies on this set, not detector presence.
RULES_POLICY_COVERED_CATEGORIES = frozenset({"PII", "PAYMENT", "CREDENTIAL"})
# Backwards-compatible name for callers of the policy bridge.  New code should
# use the qualified name above or RULES_DETECTED_CATEGORIES as appropriate.
RULES_COVERED_CATEGORIES = RULES_POLICY_COVERED_CATEGORIES

# A redaction marker, null scalar, or explicit suppression removes the source
# value and may implement a policy's suppress action.  Generalization and
# pseudonymization have stronger, distinct semantics and therefore require the
# corresponding actual output operation.
_IMPLEMENTATIONS: Mapping[TransformationAction, frozenset[LedgerAction]] = MappingProxyType({
    TransformationAction.SUPPRESS: frozenset({LedgerAction.REDACT, LedgerAction.SUPPRESS, LedgerAction.NULLIFY}),
    TransformationAction.GENERALIZE: frozenset({LedgerAction.GENERALIZE}),
    TransformationAction.PSEUDONYMIZE: frozenset({LedgerAction.PSEUDONYMIZE}),
})


@dataclass(frozen=True, slots=True)
class ActualOutputOperation:
    """One aggregate, source-free operation actually performed by a worker.

    ``category`` is the policy family, not a detector label.  Multiple rows for
    a family are permitted only when they use different operations (for
    example, a text redaction and a numeric nullification).
    """

    category: str
    action: LedgerAction
    count: int

    def __post_init__(self) -> None:
        if (type(self.category) is not str or self.category not in TAXONOMY_CATEGORIES
                or not isinstance(self.action, LedgerAction)
                or type(self.count) is not int or not 1 <= self.count <= 1_000_000):
            _fail()


@dataclass(frozen=True, slots=True)
class RulesPolicyExecution:
    """A sealed plan plus observed operations and its safe effective state.

    ``policy_ledger`` expresses what the policy requires; ``actual_ledger``
    expresses what the worker says it did.  They intentionally are separate so
    an implementation cannot relabel redaction as generalization or claim a
    blocked/review-required run is transform-ready.
    """

    plan: TransformationPlan
    disposition: CandidateDisposition
    policy_ledger: tuple[AggregateLedgerEntry, ...]
    actual_ledger: tuple[TransformLedgerEntry, ...]
    uncovered_categories: frozenset[str]
    obligations_satisfied: bool

    def __post_init__(self) -> None:
        if (not isinstance(self.plan, TransformationPlan)
                or not isinstance(self.disposition, CandidateDisposition)
                or type(self.policy_ledger) is not tuple
                or any(not isinstance(item, AggregateLedgerEntry) for item in self.policy_ledger)
                or type(self.actual_ledger) is not tuple
                or any(not isinstance(item, TransformLedgerEntry) for item in self.actual_ledger)
                or any(item.entity_type not in TAXONOMY_CATEGORIES or item.reason is not LedgerReason.POLICY_RULE
                       for item in self.actual_ledger)
                or type(self.uncovered_categories) is not frozenset
                or any(type(item) is not str or item not in TAXONOMY_CATEGORIES
                       for item in self.uncovered_categories)
                or type(self.obligations_satisfied) is not bool):
            _fail()
        if self.policy_ledger != self.plan.ledger_requirements:
            _fail()
        expected_order = tuple(sorted(
            self.actual_ledger,
            key=lambda item: (item.entity_type, item.action.value, item.reason.value),
        ))
        if self.actual_ledger != expected_order:
            _fail()
        expected_satisfied = (not self.uncovered_categories
                              and _transform_obligations_satisfied(
                                  plan=self.plan, actual_ledger=self.actual_ledger))
        expected_disposition = (
            CandidateDisposition.TRANSFORM_REQUIRED if expected_satisfied else
            CandidateDisposition.QUARANTINE_REQUIRED if self.uncovered_categories
            or self.plan.disposition is CandidateDisposition.TRANSFORM_REQUIRED else
            self.plan.disposition
        )
        if (self.obligations_satisfied is not expected_satisfied
                or self.disposition is not expected_disposition):
            _fail()
    @property
    def can_create_private_candidate(self) -> bool:
        """Whether policy evidence permits the next *private* artifact step."""
        return (self.obligations_satisfied
                and not self.uncovered_categories
                and self.plan.disposition is CandidateDisposition.TRANSFORM_REQUIRED
                and self.disposition is CandidateDisposition.TRANSFORM_REQUIRED)

    @property
    def verified_candidate_ledger(self) -> tuple[TransformLedgerEntry, ...]:
        """Return truthful candidate evidence only for an eligible private run."""
        if not self.can_create_private_candidate:
            _fail()
        return self.actual_ledger


def _findings_from_result(result: ProcessingResult) -> tuple[AggregateFinding, ...]:
    """Map rules labels to policy families without reading payload output."""
    if not isinstance(result, ProcessingResult) or type(result.findings) is not tuple:
        _fail()
    totals: dict[str, int] = defaultdict(int)
    for finding in result.findings:
        if (not isinstance(finding, Finding) or type(finding.entity_type) is not str
                or type(finding.severity) is not str or type(finding.count) is not int
                or not 1 <= finding.count <= 1_000_000):
            _fail()
        category = RULES_LABEL_TO_CATEGORY.get(finding.entity_type)
        if category is None:
            _fail()
        totals[category] += finding.count
        if totals[category] > 1_000_000:
            _fail()
    if not totals:
        # M4 plans require a finding.  A clean result is not evidence that this
        # limited rules processor assessed the uncovered policy families.
        _fail()
    try:
        return tuple(AggregateFinding(category, count) for category, count in sorted(totals.items()))
    except TransformationPolicyError:
        _fail()


def _actual_ledger(*, observations: Iterable[ActualOutputOperation], findings: tuple[AggregateFinding, ...]) -> tuple[TransformLedgerEntry, ...]:
    if isinstance(observations, (str, bytes)):
        _fail()
    try:
        rows = tuple(observations)
    except TypeError:
        _fail()
    if (not rows or any(not isinstance(row, ActualOutputOperation) for row in rows)
            or len({(row.category, row.action) for row in rows}) != len(rows)):
        _fail()
    expected_counts = {item.category: item.count for item in findings}
    observed_counts: dict[str, int] = defaultdict(int)
    for row in rows:
        observed_counts[row.category] += row.count
        if observed_counts[row.category] > 1_000_000:
            _fail()
    # Every rules finding must be accounted for exactly.  An extra operation
    # would be unbound to a detector finding and is therefore unsafe evidence.
    if dict(observed_counts) != expected_counts:
        _fail()
    return tuple(sorted(
        (TransformLedgerEntry(row.category, row.action, LedgerReason.POLICY_RULE, row.count)
         for row in rows),
        key=lambda item: (item.entity_type, item.action.value, item.reason.value),
    ))


def _transform_obligations_satisfied(*, plan: TransformationPlan,
                                     actual_ledger: tuple[TransformLedgerEntry, ...]) -> bool:
    if plan.disposition is not CandidateDisposition.TRANSFORM_REQUIRED:
        return False
    by_category: dict[str, list[TransformLedgerEntry]] = defaultdict(list)
    for entry in actual_ledger:
        by_category[entry.entity_type].append(entry)
    expected_categories = {item.category for item in plan.obligations}
    if set(by_category) != expected_categories:
        return False
    for obligation in plan.obligations:
        if obligation.ledger_action is None:
            return False
        rows = by_category.get(obligation.category, [])
        allowed = _IMPLEMENTATIONS[obligation.ledger_action]
        if not rows or any(row.action not in allowed for row in rows):
            return False
        if sum(row.count for row in rows) != obligation.count:
            return False
    return True


def execute_rules_policy(*, policy: PolicySnapshot, release_mode: str,
                         result: ProcessingResult,
                         actual_operations: Iterable[ActualOutputOperation],
                         required_categories: frozenset[str] = TAXONOMY_CATEGORIES) -> RulesPolicyExecution:
    """Bind rules findings and explicit output operations to a sealed policy.

    ``required_categories`` documents the families demanded for this run.  It
    defaults to the entire product taxonomy.  Because the current rules engine
    only covers PII, payment and credentials, that default returns a quarantined
    result; a caller may narrow it only when a separately governed workflow
    explicitly scopes the run to the rules engine's supported families.
    """
    if (not isinstance(policy, PolicySnapshot) or type(required_categories) is not frozenset
            or not required_categories
            or any(type(category) is not str or category not in TAXONOMY_CATEGORIES
                   for category in required_categories)):
        _fail()
    findings = _findings_from_result(result)
    try:
        plan = build_transformation_plan(policy=policy, release_mode=release_mode, findings=findings)
    except TransformationPolicyError:
        _fail()
    ledger = _actual_ledger(observations=actual_operations, findings=findings)
    uncovered = frozenset(required_categories - RULES_COVERED_CATEGORIES)
    satisfied = not uncovered and _transform_obligations_satisfied(plan=plan, actual_ledger=ledger)
    disposition = (CandidateDisposition.TRANSFORM_REQUIRED if satisfied
                   else CandidateDisposition.QUARANTINE_REQUIRED if uncovered
                   or plan.disposition is CandidateDisposition.TRANSFORM_REQUIRED
                   else plan.disposition)
    return RulesPolicyExecution(plan=plan, disposition=disposition,
                                policy_ledger=plan.ledger_requirements,
                                actual_ledger=ledger,
                                uncovered_categories=uncovered,
                                obligations_satisfied=satisfied)
