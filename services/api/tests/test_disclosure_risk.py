from __future__ import annotations

import json

import pytest

from app.candidate import CandidateArtifact, CandidateError, PayloadKind, SchemaContract
from app.disclosure_risk import (
    DisclosureRiskAbstention,
    DisclosureRiskError,
    DisclosureRiskStatus,
    QuasiIdentifierConfig,
    assess_disclosure_risk,
)


INPUT = "sha256:" + "a" * 64
POLICY = "sha256:" + "b" * 64


def structured_candidate(records):
    return CandidateArtifact.create(
        run_id="run-risk", input_digest=INPUT, policy_digest=POLICY, transformed=records,
        schema=SchemaContract.from_value(records, kind=PayloadKind.STRUCTURED),
    )


def text_candidate():
    return CandidateArtifact.create(
        run_id="run-risk", input_digest=INPUT, policy_digest=POLICY, transformed="private text",
        schema=SchemaContract.from_value("private text", kind=PayloadKind.TEXT),
    )


def qids(*fields):
    return QuasiIdentifierConfig.from_fields(fields)


def test_assessment_reports_safe_equivalence_histogram_k_and_unique_percent():
    candidate = structured_candidate([
        {"age_band": "30-39", "region": "west", "private": "alice"},
        {"age_band": "30-39", "region": "west", "private": "bob"},
        {"age_band": "40-49", "region": "east", "private": "carol"},
        {"age_band": "50-59", "region": "north", "private": "dave"},
    ])
    report = assess_disclosure_risk(candidate=candidate, quasi_identifiers=qids("region", "age_band"))

    assert report.status is DisclosureRiskStatus.ASSESSED
    assert report.record_count == 4
    assert report.minimum_equivalence_class_size == 1
    assert report.unique_record_count == 2
    assert report.unique_record_percent == "50.00"
    assert [(item.size, item.class_count, item.record_count) for item in report.equivalence_class_sizes] == [
        (1, 2, 2), (2, 1, 2),
    ]
    public = report.to_record()
    rendered = json.dumps(public, sort_keys=True)
    assert "alice" not in rendered and "private" not in rendered
    assert "region" not in rendered and "age_band" not in rendered
    assert public["digest"].startswith("sha256:")


def test_same_candidate_and_set_have_deterministic_digest_irrespective_of_qid_order():
    candidate = structured_candidate([
        {"age": "30-39", "region": "west"}, {"age": "30-39", "region": "west"},
    ])
    first = assess_disclosure_risk(candidate=candidate, quasi_identifiers=qids("age", "region"))
    second = assess_disclosure_risk(candidate=candidate, quasi_identifiers=qids("region", "age"))

    assert first.digest == second.digest
    assert first.to_record() == second.to_record()
    changed = structured_candidate([
        {"age": "30-39", "region": "west"}, {"age": "40-49", "region": "west"},
    ])
    assert assess_disclosure_risk(candidate=changed, quasi_identifiers=qids("age", "region")).digest != first.digest


@pytest.mark.parametrize(("candidate", "reason"), [
    (text_candidate(), DisclosureRiskAbstention.TEXT_PAYLOAD),
    (structured_candidate([]), DisclosureRiskAbstention.EMPTY_RECORD_SET),
    (structured_candidate({"age": "30-39"}), DisclosureRiskAbstention.UNSUPPORTED_RECORD_SHAPE),
])
def test_text_empty_and_nonrecord_structures_abstain_without_any_source_content(candidate, reason):
    report = assess_disclosure_risk(candidate=candidate, quasi_identifiers=qids("age"))
    assert report.status is DisclosureRiskStatus.ABSTAINED
    assert report.abstention_reason is reason
    assert report.record_count is None and not report.equivalence_class_sizes
    assert "private text" not in repr(report)
    assert "age" not in json.dumps(report.to_record())


def test_missing_or_nonscalar_quasi_identifiers_abstain_fail_closed():
    missing = structured_candidate([{"age": "30-39"}, {"age": "40-49"}])
    nested = structured_candidate([{"age": ["30-39"]}, {"age": ["30-39"]}])
    for candidate in (missing, nested):
        report = assess_disclosure_risk(candidate=candidate, quasi_identifiers=qids("age", "region"))
        assert report.status is DisclosureRiskStatus.ABSTAINED
        assert report.abstention_reason is DisclosureRiskAbstention.QUASI_IDENTIFIER_NOT_APPLICABLE


def test_config_and_api_reject_unbounded_or_unsafe_inputs_with_fixed_error():
    with pytest.raises(DisclosureRiskError) as error:
        qids("one", "one")
    assert str(error.value) == "Invalid disclosure-risk assessment."
    with pytest.raises(DisclosureRiskError):
        qids("nested.path")
    with pytest.raises(DisclosureRiskError):
        qids(*(f"field_{index}" for index in range(33)))
    with pytest.raises(DisclosureRiskError):
        assess_disclosure_risk(candidate="not-artifact", quasi_identifiers=qids("age"))


def test_output_construction_cannot_introduce_raw_values_or_invalid_digest_contract():
    candidate = structured_candidate([{"age": "30-39"}])
    report = assess_disclosure_risk(candidate=candidate, quasi_identifiers=qids("age"))
    with pytest.raises(DisclosureRiskError):
        type(report)(
            candidate_artifact_digest=report.candidate_artifact_digest,
            candidate_schema_digest=report.candidate_schema_digest,
            quasi_identifier_config_digest=report.quasi_identifier_config_digest,
            quasi_identifier_count=1, status=DisclosureRiskStatus.ASSESSED,
            abstention_reason=None, record_count=1, minimum_equivalence_class_size=1,
            unique_record_count=0, unique_record_percent="0.00", equivalence_class_sizes=(),
        )
    with pytest.raises(CandidateError):
        structured_candidate([{"age": "x" * 70_000}])
