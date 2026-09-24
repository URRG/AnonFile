from __future__ import annotations

import json

import pytest

from app.candidate import CandidateArtifact, PayloadKind, SchemaContract
from app.quasi_identifier_risk import (
    MAX_RECORDS, QuasiIdentifierRiskAbstention, QuasiIdentifierRiskAuthority,
    QuasiIdentifierRiskError, QuasiIdentifierRiskReport, QuasiIdentifierRiskStatus,
    ThresholdDistribution, assess_quasi_identifier_risk,
)


AUTHORITY = QuasiIdentifierRiskAuthority.from_secret(b"r" * 32)
INPUT, POLICY = "sha256:" + "a" * 64, "sha256:" + "b" * 64


def candidate(value, kind=PayloadKind.STRUCTURED):
    return CandidateArtifact.create(run_id="qid-risk", input_digest=INPUT, policy_digest=POLICY,
                                    transformed=value, schema=SchemaContract.from_value(value, kind=kind))


def assess(value, fields=("age", "district"), scope="tenant-a:analytics"):
    return assess_quasi_identifier_risk(candidate=candidate(value), config=AUTHORITY.create_config(fields, scope=scope), authority=AUTHORITY)


def test_observes_indirect_identifier_groups_with_only_bounded_aggregates():
    report = assess([{"age": "30-39", "district": "west", "name": "Ava"},
                     {"age": "30-39", "district": "west", "name": "Bea"},
                     {"age": "40-49", "district": "east", "name": "Cy"},
                     {"age": "50-59", "district": "north", "name": "Dee"}])
    assert report.status is QuasiIdentifierRiskStatus.ASSESSED
    assert (report.record_count, report.minimum_group_size, report.singleton_record_count) == (4, 1, 2)
    assert [(item.maximum_group_size, item.record_count) for item in report.threshold_distribution] == [(1, 2), (2, 4), (5, 4), (10, 4)]
    public = json.dumps(report.to_record(), sort_keys=True)
    for private in ("age", "district", "tenant-a", "west", "Ava", "sha256:"):
        assert private not in public


def test_missingness_and_non_scalar_values_abstain_without_metrics_or_reflection():
    for rows in ([{"age": "30-39", "district": "west"}, {"age": "30-39"}],
                 [{"age": ["30-39"], "district": "west"}]):
        report = assess(rows)
        assert report.status is QuasiIdentifierRiskStatus.ABSTAINED
        assert report.abstention_reason is QuasiIdentifierRiskAbstention.QUASI_IDENTIFIER_NOT_APPLICABLE
        assert report.record_count is None and report.threshold_distribution == ()
        assert "district" not in json.dumps(report.to_record())


@pytest.mark.parametrize("missing", [None, "", "  "])
def test_null_or_blank_qids_abstain_instead_of_forming_an_apparently_large_group(missing):
    report = assess([{"age": missing, "district": "west"}, {"age": missing, "district": "west"}])
    assert report.status is QuasiIdentifierRiskStatus.ABSTAINED
    assert report.abstention_reason is QuasiIdentifierRiskAbstention.MISSING_OR_BLANK_QUASI_IDENTIFIER
    assert report.record_count is None and report.threshold_distribution == ()


def test_canonical_numeric_and_boolean_types_do_not_collapse():
    report = assess([{"age": 1, "district": "x"}, {"age": 1.0, "district": "x"},
                     {"age": True, "district": "x"}, {"age": 1, "district": "x"}])
    assert report.minimum_group_size == 1
    assert report.singleton_record_count == 2
    assert report.threshold_distribution[1].record_count == 4


def test_scope_identity_is_hmac_bound_and_wrong_authority_abstains():
    config_a = AUTHORITY.create_config(["age"], scope="tenant-a")
    config_b = AUTHORITY.create_config(["age"], scope="tenant-b")
    assert config_a.commitment != config_b.commitment
    report = assess_quasi_identifier_risk(candidate=candidate([{"age": "30-39"}]), config=config_a,
                                          authority=QuasiIdentifierRiskAuthority.from_secret(b"s" * 32))
    assert report.status is QuasiIdentifierRiskStatus.ABSTAINED
    assert report.abstention_reason is QuasiIdentifierRiskAbstention.CONFIG_UNVERIFIED
    assert report.candidate_commitment is None


@pytest.mark.parametrize("value,kind,reason", [
    ("private JSONL text", PayloadKind.TEXT, QuasiIdentifierRiskAbstention.TEXT_PAYLOAD),
    ([], PayloadKind.STRUCTURED, QuasiIdentifierRiskAbstention.EMPTY_RECORD_SET),
    ({"age": "30-39"}, PayloadKind.STRUCTURED, QuasiIdentifierRiskAbstention.UNSUPPORTED_RECORD_SHAPE),
])
def test_unsupported_inputs_abstain(value, kind, reason):
    config = AUTHORITY.create_config(["age"], scope="tenant-a")
    report = assess_quasi_identifier_risk(candidate=candidate(value, kind), config=config, authority=AUTHORITY)
    assert report.status is QuasiIdentifierRiskStatus.ABSTAINED and report.abstention_reason is reason


def test_limits_and_unsafe_config_fail_with_a_fixed_error(monkeypatch):
    with pytest.raises(QuasiIdentifierRiskError):
        AUTHORITY.create_config(["bad.path"], scope="tenant-a")
    with pytest.raises(QuasiIdentifierRiskError):
        AUTHORITY.create_config([f"f{i}" for i in range(33)], scope="tenant-a")
    # Candidate construction is separately bounded; patching the local ceiling proves the assessment closes its own limit.
    monkeypatch.setattr("app.quasi_identifier_risk.MAX_RECORDS", 1)
    report = assess([{"age": "30", "district": "x"}, {"age": "30", "district": "x"}])
    assert report.status is QuasiIdentifierRiskStatus.ABSTAINED
    assert report.abstention_reason is QuasiIdentifierRiskAbstention.RECORD_LIMIT_EXCEEDED


def test_report_rejects_internally_inconsistent_aggregate_metrics():
    config = AUTHORITY.create_config(["age"], scope="tenant-a")
    binding = AUTHORITY.candidate_commitment(candidate([{"age": "30"}]), config)
    with pytest.raises(QuasiIdentifierRiskError):
        QuasiIdentifierRiskReport(binding, config.commitment, "m24-qid-singling-out-v1", 1,
                                  QuasiIdentifierRiskStatus.ASSESSED, None, 2, 2, 0,
                                  tuple(ThresholdDistribution(limit, 0) for limit in (1, 2, 5, 10)))
    with pytest.raises(QuasiIdentifierRiskError):
        QuasiIdentifierRiskReport(binding, config.commitment, "m24-qid-singling-out-v1", 1,
                                  QuasiIdentifierRiskStatus.ASSESSED, None, 2, 1, 1,
                                  (ThresholdDistribution(1, 1), ThresholdDistribution(2, 3),
                                   ThresholdDistribution(5, 3), ThresholdDistribution(10, 3)))
