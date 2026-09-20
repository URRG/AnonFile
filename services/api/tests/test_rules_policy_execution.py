"""Focused regression tests for the rules processor to M4 policy bridge."""
import pytest

from app.candidate import LedgerAction
from app.contracts import Finding, ProcessingResult
from app.policies import PolicyProfile, PolicyRule, PolicySnapshot
from app.processing import process_payload
from app.rules_policy_execution import (
    ActualOutputOperation,
    RULES_COVERED_CATEGORIES,
    RulesPolicyExecutionError,
    execute_rules_policy,
)
from app.transformation_policy import CandidateDisposition, TransformationAction


def snapshot(*, actions=None):
    values = {
        "CREDENTIAL": ("block", 0), "PAYMENT": ("suppress", 10),
        "HEALTH_SENSITIVE": ("suppress", 20), "PII": ("suppress", 30),
        "BUSINESS_CONFIDENTIAL": ("review", 40), "QUASI_IDENTIFIER": ("generalize", 50),
    }
    values.update(actions or {})
    return PolicySnapshot.seal(PolicyProfile(
        "rules-bridge", "v1", ("external_anonymized", "restricted_pseudonymized"),
        ("text",), ("en",),
        tuple(PolicyRule(category, action, priority) for category, (action, priority) in values.items()),
    ))


def test_suppression_requires_explicit_truthful_operations_and_returns_candidate_ledger():
    result = process_payload(content="Contact ada@example.invalid or 9876543210")
    execution = execute_rules_policy(
        policy=snapshot(), release_mode="external_anonymized", result=result,
        actual_operations=(ActualOutputOperation("PII", LedgerAction.REDACT, 2),),
        required_categories=RULES_COVERED_CATEGORIES,
    )
    assert execution.disposition is CandidateDisposition.TRANSFORM_REQUIRED
    assert execution.obligations_satisfied is True
    assert execution.can_create_private_candidate is True
    assert [(item.category, item.action, item.count) for item in execution.policy_ledger] == [
        ("PII", TransformationAction.SUPPRESS, 2),
    ]
    assert [(item.entity_type, item.action, item.count) for item in execution.verified_candidate_ledger] == [
        ("PII", LedgerAction.REDACT, 2),
    ]


def test_mixed_actual_nullification_and_redaction_can_truthfully_implement_suppression():
    result = process_payload(records=[{"email": "ada@example.invalid", "identifier": 123456789012}])
    execution = execute_rules_policy(
        policy=snapshot(), release_mode="external_anonymized", result=result,
        actual_operations=(
            ActualOutputOperation("PII", LedgerAction.NULLIFY, 1),
            ActualOutputOperation("PII", LedgerAction.REDACT, 1),
        ),
        required_categories=RULES_COVERED_CATEGORIES,
    )
    assert execution.can_create_private_candidate
    assert {item.action for item in execution.verified_candidate_ledger} == {LedgerAction.NULLIFY, LedgerAction.REDACT}


@pytest.mark.parametrize("policy_action, operation", [
    ("generalize", LedgerAction.REDACT),
    ("tokenize", LedgerAction.REDACT),
])
def test_redaction_cannot_be_relabeled_as_generalization_or_pseudonymization(policy_action, operation):
    result = process_payload(content="ada@example.invalid", mode="restricted_pseudonymized")
    execution = execute_rules_policy(
        policy=snapshot(actions={"PII": (policy_action, 30)}),
        release_mode="restricted_pseudonymized", result=result,
        actual_operations=(ActualOutputOperation("PII", operation, 1),),
        required_categories=RULES_COVERED_CATEGORIES,
    )
    assert execution.disposition is CandidateDisposition.QUARANTINE_REQUIRED
    assert not execution.can_create_private_candidate
    with pytest.raises(RulesPolicyExecutionError):
        _ = execution.verified_candidate_ledger


@pytest.mark.parametrize("category, action, content, actual, expected", [
    ("CREDENTIAL", "block", "password=synthetic", ActualOutputOperation("CREDENTIAL", LedgerAction.REDACT, 1),
     CandidateDisposition.QUARANTINE_REQUIRED),
    ("PII", "review", "ada@example.invalid", ActualOutputOperation("PII", LedgerAction.REDACT, 1),
     CandidateDisposition.REVIEW_REQUIRED),
])
def test_block_and_review_never_become_transform_ready(category, action, content, actual, expected):
    result = process_payload(content=content)
    priority = 0 if category == "CREDENTIAL" else 30
    execution = execute_rules_policy(policy=snapshot(actions={category: (action, priority)}), release_mode="external_anonymized", result=result,
                                     actual_operations=(actual,), required_categories=RULES_COVERED_CATEGORIES)
    assert execution.disposition is expected
    assert not execution.can_create_private_candidate


def test_default_all_taxonomy_requirement_quarantines_limited_rules_coverage():
    result = process_payload(content="ada@example.invalid")
    execution = execute_rules_policy(
        policy=snapshot(), release_mode="external_anonymized", result=result,
        actual_operations=(ActualOutputOperation("PII", LedgerAction.REDACT, 1),),
    )
    assert execution.disposition is CandidateDisposition.QUARANTINE_REQUIRED
    assert execution.uncovered_categories == frozenset({"HEALTH_SENSITIVE", "BUSINESS_CONFIDENTIAL", "QUASI_IDENTIFIER"})
    assert not execution.can_create_private_candidate


def test_unknown_labels_missing_operations_extra_operations_and_clean_result_fail_closed():
    unknown = ProcessingResult("", (Finding("UNDECLARED", "high", 1),), (), False, 0, 0)
    clean = process_payload(content="ordinary synthetic sentence")
    known = process_payload(content="ada@example.invalid")
    cases = (
        (unknown, (ActualOutputOperation("PII", LedgerAction.REDACT, 1),)),
        (clean, (ActualOutputOperation("PII", LedgerAction.REDACT, 1),)),
        (known, ()),
        (known, (ActualOutputOperation("PII", LedgerAction.REDACT, 2),)),
    )
    for result, operations in cases:
        with pytest.raises(RulesPolicyExecutionError) as error:
            execute_rules_policy(policy=snapshot(), release_mode="external_anonymized", result=result,
                                 actual_operations=operations, required_categories=RULES_COVERED_CATEGORIES)
        assert str(error.value) == "Invalid rules policy execution."
