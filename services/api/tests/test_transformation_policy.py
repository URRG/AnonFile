import pytest

from app.policies import PolicyProfile, PolicyRule, PolicySnapshot, TAXONOMY_CATEGORIES
from app.transformation_policy import (AggregateFinding, AggregateLedgerEntry,
                                       CandidateDisposition, TransformationAction,
                                       TransformationObligation, TransformationPlan,
                                       TransformationPolicyError, build_transformation_plan,
                                       verify_aggregate_ledger)


def snapshot(*, actions=None, modes=("external_anonymized", "restricted_pseudonymized")):
    values = {
        "CREDENTIAL": ("block", 0), "PAYMENT": ("suppress", 10),
        "HEALTH_SENSITIVE": ("suppress", 20), "PII": ("suppress", 30),
        "BUSINESS_CONFIDENTIAL": ("review", 40), "QUASI_IDENTIFIER": ("generalize", 50),
    }
    values.update(actions or {})
    profile = PolicyProfile("transform", "v1", modes, ("text",), ("en",),
                            tuple(PolicyRule(category, action, priority) for category, (action, priority) in values.items()))
    return PolicySnapshot.seal(profile)


def test_policy_actions_map_to_explicit_obligations_and_allowed_modes():
    plan = build_transformation_plan(policy=snapshot(), release_mode="external_anonymized", findings=(
        AggregateFinding("PAYMENT", 2), AggregateFinding("QUASI_IDENTIFIER", 3),
    ))
    assert [(item.category, item.ledger_action, item.count) for item in plan.obligations] == [
        ("PAYMENT", TransformationAction.SUPPRESS, 2),
        ("QUASI_IDENTIFIER", TransformationAction.GENERALIZE, 3),
    ]
    assert plan.disposition is CandidateDisposition.TRANSFORM_REQUIRED
    assert plan.primary_category == "PAYMENT"


def test_tokenization_is_restricted_to_pseudonymized_mode():
    policy = snapshot(actions={"PII": ("tokenize", 5)})
    restricted = build_transformation_plan(policy=policy, release_mode="restricted_pseudonymized",
                                            findings=(AggregateFinding("PII", 1),))
    assert restricted.ledger_requirements == (AggregateLedgerEntry("PII", TransformationAction.PSEUDONYMIZE, 1),)
    with pytest.raises(TransformationPolicyError):
        build_transformation_plan(policy=policy, release_mode="external_anonymized", findings=(AggregateFinding("PII", 1),))


def test_block_and_review_are_fail_closed_candidate_dispositions_with_deterministic_precedence():
    policy = snapshot()
    plan = build_transformation_plan(policy=policy, release_mode="external_anonymized", findings=(
        AggregateFinding("BUSINESS_CONFIDENTIAL", 1), AggregateFinding("CREDENTIAL", 2), AggregateFinding("PAYMENT", 1),
    ))
    assert plan.disposition is CandidateDisposition.QUARANTINE_REQUIRED
    assert plan.primary_category == "CREDENTIAL"
    assert plan.ledger_requirements == (AggregateLedgerEntry("PAYMENT", TransformationAction.SUPPRESS, 1),)
    assert all("APPROV" not in value for value in CandidateDisposition)


def test_exact_aggregate_ledger_is_required_and_never_accepts_extra_or_weakened_actions():
    plan = build_transformation_plan(policy=snapshot(), release_mode="external_anonymized",
                                     findings=(AggregateFinding("PAYMENT", 2), AggregateFinding("PII", 1)))
    verify_aggregate_ledger(plan=plan, entries=plan.ledger_requirements)
    for entries in (
        (AggregateLedgerEntry("PAYMENT", TransformationAction.SUPPRESS, 2),),
        (AggregateLedgerEntry("PAYMENT", TransformationAction.GENERALIZE, 2), AggregateLedgerEntry("PII", TransformationAction.SUPPRESS, 1)),
        (AggregateLedgerEntry("PAYMENT", TransformationAction.SUPPRESS, 1), AggregateLedgerEntry("PII", TransformationAction.SUPPRESS, 1)),
        (*plan.ledger_requirements, AggregateLedgerEntry("HEALTH_SENSITIVE", TransformationAction.SUPPRESS, 1)),
    ):
        with pytest.raises(TransformationPolicyError):
            verify_aggregate_ledger(plan=plan, entries=entries)


def test_explanation_is_immutable_aggregate_only_and_digest_binds_obligations():
    first = build_transformation_plan(policy=snapshot(), release_mode="external_anonymized", findings=(AggregateFinding("PII", 1),))
    second = build_transformation_plan(policy=snapshot(), release_mode="external_anonymized", findings=(AggregateFinding("PII", 2),))
    explanation = first.explain()
    assert first.digest != second.digest
    assert set(explanation) == {"digest", "disposition", "ledger_requirements", "policy_digest", "primary_category", "release_mode"}
    assert "value" not in str(explanation).lower() and "field" not in str(explanation).lower()
    with pytest.raises(TypeError):
        explanation["digest"] = "sha256:" + "0" * 64


@pytest.mark.parametrize("bad", [
    lambda: AggregateFinding("UNKNOWN", 1),
    lambda: AggregateFinding("PII", True),
    lambda: build_transformation_plan(policy=snapshot(), release_mode="invalid", findings=(AggregateFinding("PII", 1),)),
    lambda: build_transformation_plan(policy=snapshot(), release_mode="external_anonymized", findings=()),
    lambda: build_transformation_plan(policy=snapshot(), release_mode="external_anonymized", findings=(AggregateFinding("PII", 1), AggregateFinding("PII", 2))),
    lambda: verify_aggregate_ledger(plan=build_transformation_plan(policy=snapshot(), release_mode="external_anonymized", findings=(AggregateFinding("PII", 1),)), entries=("raw-value",)),
])
def test_invalid_input_has_fixed_safe_error(bad):
    with pytest.raises(TransformationPolicyError) as error:
        bad()
    assert str(error.value) == "Invalid transformation policy request"


def test_partial_policy_cannot_supply_an_uncovered_category_default():
    partial = PolicySnapshot.seal(PolicyProfile(
        "partial", "v1", ("external_anonymized",), ("text",), ("en",),
        (PolicyRule("PII", "suppress"),),
    ))
    with pytest.raises(TransformationPolicyError):
        build_transformation_plan(policy=partial, release_mode="external_anonymized",
                                  findings=(AggregateFinding("HEALTH_SENSITIVE", 1),))
    assert TAXONOMY_CATEGORIES


def test_direct_plan_construction_cannot_bypass_mode_action_or_digest_validation():
    tokenized = TransformationObligation("PII", "tokenize", 1, 1,
                                         CandidateDisposition.TRANSFORM_REQUIRED,
                                         TransformationAction.PSEUDONYMIZE)
    with pytest.raises(TransformationPolicyError):
        TransformationPlan("sha256:" + "a" * 64, "external_anonymized", (tokenized,),
                           CandidateDisposition.TRANSFORM_REQUIRED, "PII")
    with pytest.raises(TransformationPolicyError):
        TransformationPlan("sha256:" + "z" * 64, "restricted_pseudonymized", (tokenized,),
                           CandidateDisposition.TRANSFORM_REQUIRED, "PII")
    restricted = TransformationPlan("sha256:" + "a" * 64, "restricted_pseudonymized", (tokenized,),
                                    CandidateDisposition.TRANSFORM_REQUIRED, "PII")
    verify_aggregate_ledger(plan=restricted, entries=restricted.ledger_requirements)
