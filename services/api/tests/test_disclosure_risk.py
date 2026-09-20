from __future__ import annotations

import json

import pytest

from app.candidate import CandidateArtifact, CandidateError, PayloadKind, SchemaContract
from app.disclosure_risk import (
    DisclosureRiskAbstention,
    DisclosureRiskError,
    DisclosureRiskStatus,
    QuasiIdentifierCommitmentAuthority,
    QuasiIdentifierConfig,
    assess_disclosure_risk,
)


INPUT = "sha256:" + "a" * 64
POLICY = "sha256:" + "b" * 64
AUTHORITY = QuasiIdentifierCommitmentAuthority.from_secret(b"q" * 32)


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
    return AUTHORITY.create_config(fields)


def assess(candidate, fields):
    return assess_disclosure_risk(candidate=candidate, quasi_identifiers=qids(*fields),
                                  commitment_verifier=AUTHORITY)


def test_assessment_reports_safe_equivalence_histogram_k_and_unique_percent():
    candidate = structured_candidate([
        {"age_band": "30-39", "region": "west", "private": "alice"},
        {"age_band": "30-39", "region": "west", "private": "bob"},
        {"age_band": "40-49", "region": "east", "private": "carol"},
        {"age_band": "50-59", "region": "north", "private": "dave"},
    ])
    report = assess(candidate, ("region", "age_band"))

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
    assert public["quasi_identifier_commitment"] == qids("region", "age_band").public_commitment
    assert "config_digest" not in rendered
    assert public["digest"].startswith("sha256:")


def test_unique_percentage_is_half_up_rounded_to_exactly_two_decimal_places():
    candidate = structured_candidate([
        {"age": "20-29", "region": "north"},
        {"age": "20-29", "region": "north"},
        {"age": "30-39", "region": "south"},
    ])
    report = assess(candidate, ("age", "region"))
    assert report.unique_record_percent == "33.33"


def test_same_candidate_and_set_have_deterministic_digest_irrespective_of_qid_order():
    candidate = structured_candidate([
        {"age": "30-39", "region": "west"}, {"age": "30-39", "region": "west"},
    ])
    first = assess(candidate, ("age", "region"))
    second = assess(candidate, ("region", "age"))

    assert first.digest == second.digest
    assert first.to_record() == second.to_record()
    changed = structured_candidate([
        {"age": "30-39", "region": "west"}, {"age": "40-49", "region": "west"},
    ])
    assert assess(changed, ("age", "region")).digest != first.digest


@pytest.mark.parametrize(("candidate", "reason"), [
    (text_candidate(), DisclosureRiskAbstention.TEXT_PAYLOAD),
    (structured_candidate([]), DisclosureRiskAbstention.EMPTY_RECORD_SET),
    (structured_candidate({"age": "30-39"}), DisclosureRiskAbstention.UNSUPPORTED_RECORD_SHAPE),
])
def test_text_empty_and_nonrecord_structures_abstain_without_any_source_content(candidate, reason):
    report = assess(candidate, ("age",))
    assert report.status is DisclosureRiskStatus.ABSTAINED
    assert report.abstention_reason is reason
    assert report.record_count is None and not report.equivalence_class_sizes
    assert "private text" not in repr(report)
    assert "age" not in json.dumps(report.to_record())


def test_missing_or_nonscalar_quasi_identifiers_abstain_fail_closed():
    missing = structured_candidate([{"age": "30-39"}, {"age": "40-49"}])
    nested = structured_candidate([{"age": ["30-39"]}, {"age": ["30-39"]}])
    for candidate in (missing, nested):
        report = assess(candidate, ("age", "region"))
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
        QuasiIdentifierConfig.from_fields(["age"], public_commitment="sha256:" + "a" * 64)
    with pytest.raises(DisclosureRiskError):
        QuasiIdentifierConfig.from_fields(["age"], public_commitment="qidcfg:v1:too-short")
    with pytest.raises(DisclosureRiskError):
        assess_disclosure_risk(candidate="not-artifact", quasi_identifiers=qids("age"), commitment_verifier=AUTHORITY)


def test_output_construction_cannot_introduce_raw_values_or_invalid_digest_contract():
    candidate = structured_candidate([{"age": "30-39"}])
    report = assess(candidate, ("age",))
    with pytest.raises(DisclosureRiskError):
        type(report)(
            candidate_artifact_digest=report.candidate_artifact_digest,
            candidate_schema_digest=report.candidate_schema_digest,
            quasi_identifier_commitment=report.quasi_identifier_commitment,
            quasi_identifier_count=1, status=DisclosureRiskStatus.ASSESSED,
            abstention_reason=None, record_count=1, minimum_equivalence_class_size=1,
            unique_record_count=0, unique_record_percent="0.00", equivalence_class_sizes=(),
        )
    with pytest.raises(CandidateError):
        structured_candidate([{"age": "x" * 70_000}])


def test_public_qid_commitment_is_hmac_bound_not_a_field_name_hash():
    candidate = structured_candidate([{"age": "30-39", "region": "west"}])
    authority = QuasiIdentifierCommitmentAuthority.from_secret(b"r" * 32)
    config = authority.create_config(["age", "region"])
    report = assess_disclosure_risk(
        candidate=candidate,
        quasi_identifiers=config, commitment_verifier=authority,
    )
    public = report.to_record()
    assert public["quasi_identifier_commitment"] == config.public_commitment
    assert "age" not in json.dumps(public) and "region" not in json.dumps(public)
    assert report.status is DisclosureRiskStatus.ASSESSED


def test_missing_or_wrong_authority_abstains_and_tampered_token_is_not_assessed():
    candidate = structured_candidate([{"age": "30-39", "region": "west"}])
    config = qids("age", "region")
    missing = assess_disclosure_risk(candidate=candidate, quasi_identifiers=config)
    wrong = assess_disclosure_risk(
        candidate=candidate, quasi_identifiers=config,
        commitment_verifier=QuasiIdentifierCommitmentAuthority.from_secret(b"z" * 32),
    )
    tampered = QuasiIdentifierConfig.from_fields(
        ["age", "region"], public_commitment="qidcfg:v1:Z0FqS5wYujr9Jks0L2CIacKxDqT4CqR-lC1BuE4n3VQ",
    )
    selection_mismatch = QuasiIdentifierConfig.from_fields(
        ["age"], public_commitment=config.public_commitment,
    )
    invalid = assess_disclosure_risk(candidate=candidate, quasi_identifiers=tampered,
                                     commitment_verifier=AUTHORITY)
    mismatch = assess_disclosure_risk(candidate=candidate, quasi_identifiers=selection_mismatch,
                                      commitment_verifier=AUTHORITY)
    for report in (missing, wrong, invalid, mismatch):
        assert report.status is DisclosureRiskStatus.ABSTAINED
        assert report.abstention_reason is DisclosureRiskAbstention.QUASI_IDENTIFIER_COMMITMENT_UNVERIFIED
    assert b"q" * 32 not in repr(AUTHORITY).encode("utf-8")
