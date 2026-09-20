from __future__ import annotations

import json

import pytest

from app.candidate import CandidateArtifact, CandidateError, PayloadKind, SchemaContract
from app.utility_evidence import (
    METHODOLOGY_DIGEST,
    DataUtilityReport,
    UtilityEvidenceAbstention,
    UtilityEvidenceAuthority,
    UtilityEvidenceError,
    UtilityEvidenceStatus,
    assess_data_utility,
)


INPUT = "sha256:" + "a" * 64
POLICY = "sha256:" + "b" * 64
AUTHORITY = UtilityEvidenceAuthority.from_secret(b"u" * 32)


def artifact(value):
    kind = PayloadKind.TEXT if type(value) is str else PayloadKind.STRUCTURED
    return CandidateArtifact.create(
        run_id="run-utility", input_digest=INPUT, policy_digest=POLICY, transformed=value,
        schema=SchemaContract.from_value(value, kind=kind, allow_scalar_nulls=True),
    )


def assess(source, candidate, authority=AUTHORITY):
    return assess_data_utility(source=source, candidate=candidate, source_commitment=AUTHORITY.issue(source),
                               commitment_verifier=authority)


def test_structured_utility_is_aggregate_only_deterministic_and_candidate_bound():
    source = [
        {"customer_email": "alice@example.test", "region": "west", "orders": 2},
        {"customer_email": "bob@example.test", "region": "east", "orders": 4},
    ]
    candidate = artifact([
        {"customer_email": "<EMAIL_1>", "region": "west", "orders": 2},
        {"customer_email": "<EMAIL_2>", "region": "east", "orders": 4},
    ])
    first = assess(source, candidate)
    second = assess(source, candidate)

    assert first.status is UtilityEvidenceStatus.ASSESSED
    assert first.structure_preserved is True and first.unit_count_preserved is True
    assert first.input_unit_count == first.candidate_unit_count == 2
    assert first.input_scalar_count == first.candidate_scalar_count == 6
    assert first.methodology_digest == METHODOLOGY_DIGEST
    assert first.to_record() == second.to_record()
    assert first.digest.startswith("sha256:")
    rendered = json.dumps(first.to_record(), sort_keys=True)
    for forbidden in ("alice@example.test", "bob@example.test", "customer_email", "region", "orders", "<EMAIL_1>"):
        assert forbidden not in rendered


def test_key_renames_are_value_free_structure_but_shape_or_unit_changes_are_visible():
    source = [{"customer_email": "alice@example.test", "region": "west"}]
    renamed = artifact([{"opaque_a": "<EMAIL_1>", "opaque_b": "west"}])
    changed = artifact([{"opaque_a": {"nested": "<EMAIL_1>"}}])

    equal = assess(source, renamed)
    unequal = assess(source, changed)
    assert equal.structure_preserved is True
    assert unequal.structure_preserved is False
    assert unequal.input_unit_count == unequal.candidate_unit_count == 1


def test_text_is_supported_without_emitting_text_and_uses_byte_counts_only():
    source = "Reach Alice at alice@example.test"
    candidate = artifact("Reach <EMAIL_1>")
    report = assess(source, candidate)

    assert report.status is UtilityEvidenceStatus.ASSESSED
    assert report.input_unit_count == report.candidate_unit_count == 1
    assert report.structure_preserved is True
    rendered = json.dumps(report.to_record())
    assert "alice@example.test" not in rendered and "Reach" not in rendered and "EMAIL_1" not in rendered


def test_source_commitment_is_hmac_bound_and_is_not_a_source_digest():
    source = [{"name": "alice"}]
    candidate = artifact([{"name": "<PERSON_1>"}])
    commitment = AUTHORITY.issue(source)
    report = assess_data_utility(source=source, candidate=candidate, source_commitment=commitment,
                                 commitment_verifier=AUTHORITY)
    public = report.to_record()
    assert public["source_commitment"] == commitment
    assert "name" not in json.dumps(public) and "alice" not in json.dumps(public)
    assert INPUT not in json.dumps(public)
    assert "input_digest" not in public


def test_missing_wrong_tampered_or_invalid_source_commitment_abstains_before_metrics():
    source = [{"name": "alice"}]
    candidate = artifact([{"name": "<PERSON_1>"}])
    commitment = AUTHORITY.issue(source)
    foreign = UtilityEvidenceAuthority.from_secret(b"f" * 32)
    tampered = "utilsrc:v1:" + "A" * 43
    for verifier, used_source, token in (
        (None, source, commitment), (foreign, source, commitment), (AUTHORITY, [{"name": "eve"}], commitment),
        (AUTHORITY, source, tampered),
    ):
        report = assess_data_utility(source=used_source, candidate=candidate, source_commitment=token,
                                     commitment_verifier=verifier)
        assert report.status is UtilityEvidenceStatus.ABSTAINED
        assert report.abstention_reason is UtilityEvidenceAbstention.SOURCE_COMMITMENT_UNVERIFIED
        assert report.input_byte_count is None and report.structure_preserved is None


def test_payload_kind_mismatch_abstains_without_reported_source_or_candidate_content():
    source = [{"name": "alice"}]
    candidate = artifact("masked text")
    report = assess(source, candidate)
    assert report.status is UtilityEvidenceStatus.ABSTAINED
    assert report.abstention_reason is UtilityEvidenceAbstention.PAYLOAD_KIND_MISMATCH
    assert report.input_node_count is None
    assert "alice" not in repr(report) and "masked text" not in repr(report)


def test_bad_authority_contracts_and_oversize_malformed_sources_fail_closed_without_content():
    with pytest.raises(UtilityEvidenceError) as error:
        UtilityEvidenceAuthority.from_secret(b"short")
    assert str(error.value) == "Invalid utility-evidence assessment."
    candidate = artifact([{"name": "<PERSON_1>"}])
    # A valid-looking token is enough to request a source-safe abstention; a
    # cyclic or oversize source can never be verified or measured.
    cyclic = []
    cyclic.append(cyclic)
    report = assess_data_utility(source=cyclic, candidate=candidate,
                                 source_commitment="utilsrc:v1:" + "A" * 43,
                                 commitment_verifier=AUTHORITY)
    assert report.status is UtilityEvidenceStatus.ABSTAINED
    assert report.abstention_reason is UtilityEvidenceAbstention.SOURCE_COMMITMENT_UNVERIFIED
    with pytest.raises(CandidateError):
        artifact([{"name": "x" * 70_000}])
    with pytest.raises(UtilityEvidenceError):
        assess_data_utility(source=[{"name": "alice"}], candidate=candidate,
                            source_commitment="not-a-commitment", commitment_verifier=AUTHORITY)


def test_direct_report_construction_cannot_claim_metrics_for_an_abstention_or_bypass_digest_contract():
    candidate = artifact([{"name": "<PERSON_1>"}])
    report = assess([{"name": "alice"}], candidate)
    with pytest.raises(UtilityEvidenceError):
        DataUtilityReport(
            candidate_artifact_digest=report.candidate_artifact_digest,
            source_commitment=report.source_commitment, methodology_digest=report.methodology_digest,
            status=UtilityEvidenceStatus.ABSTAINED,
            abstention_reason=UtilityEvidenceAbstention.SOURCE_COMMITMENT_UNVERIFIED,
            input_byte_count=1, candidate_byte_count=None, input_unit_count=None, candidate_unit_count=None,
            input_node_count=None, candidate_node_count=None, input_scalar_count=None, candidate_scalar_count=None,
            input_non_null_scalar_count=None, candidate_non_null_scalar_count=None,
            structure_preserved=None, unit_count_preserved=None,
        )
