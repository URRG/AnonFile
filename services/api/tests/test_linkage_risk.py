"""Contracts for bounded, aggregate-only linkage-risk evidence."""
from __future__ import annotations

from dataclasses import replace
import json

import pytest

from app.candidate import CandidateArtifact, PayloadKind, SchemaContract
from app.linkage_risk import (
    LinkageCommitmentAuthority,
    LinkageRiskAbstention,
    LinkageRiskError,
    LinkageRiskReport,
    LinkageRiskStatus,
    assess_linkage_risk,
)


INPUT = "sha256:" + "a" * 64
POLICY = "sha256:" + "b" * 64
AUTHORITY = LinkageCommitmentAuthority.from_secret(b"l" * 32)


def candidate(value):
    return CandidateArtifact.create(
        run_id="run-linkage", input_digest=INPUT, policy_digest=POLICY, transformed=value,
        schema=SchemaContract.from_value(value, kind=PayloadKind.STRUCTURED),
    )


def text_candidate(value="private text"):
    return CandidateArtifact.create(
        run_id="run-linkage", input_digest=INPUT, policy_digest=POLICY, transformed=value,
        schema=SchemaContract.from_value(value, kind=PayloadKind.TEXT),
    )


def prepared(reference_rows, fields=("birth_band", "postal_band")):
    config = AUTHORITY.issue_key_config(fields)
    return config, AUTHORITY.create_reference(reference_rows, linkage_keys=config)


def assess(value, reference_rows, fields=("birth_band", "postal_band"), authority=AUTHORITY):
    config, reference = prepared(reference_rows, fields)
    return assess_linkage_risk(candidate=candidate(value), reference=reference, linkage_keys=config,
                               commitment_verifier=authority)


def test_hmac_reference_linkage_reports_deterministic_aggregate_coverage_unique_and_ambiguous_counts():
    candidate_rows = [
        {"birth_band": "1980s", "postal_band": "100", "private": "alice@example.test"},
        {"birth_band": "1990s", "postal_band": "200", "private": "bob@example.test"},
        {"birth_band": "1990s", "postal_band": "200", "private": "carol@example.test"},
        {"birth_band": "1970s", "postal_band": "300", "private": "dave@example.test"},
    ]
    reference_rows = [
        {"birth_band": "1980s", "postal_band": "100", "name": "reference-alice"},
        {"birth_band": "1990s", "postal_band": "200", "name": "reference-bob"},
        {"birth_band": "1990s", "postal_band": "200", "name": "reference-carol"},
        {"birth_band": "1960s", "postal_band": "400", "name": "reference-other"},
    ]
    first = assess(candidate_rows, reference_rows)
    second = assess(candidate_rows, list(reversed(reference_rows)), ("postal_band", "birth_band"))

    assert first.status is LinkageRiskStatus.ASSESSED
    assert first.candidate_record_count == first.reference_record_count == 4
    assert first.matched_record_count == 3
    assert first.unique_match_count == 1
    assert first.ambiguous_match_count == 2
    assert first.match_coverage_percent == "75.00"
    assert first.to_record() == second.to_record()
    assert first.digest.startswith("sha256:")
    rendered = json.dumps(first.to_record(), sort_keys=True)
    for forbidden in ("alice@example.test", "reference-alice", "birth_band", "postal_band", "private", "name",
                      "1980s", "100", "input_digest"):
        assert forbidden not in rendered
    assert first.linkage_key_commitment.startswith("linkcfg:v1:")
    assert first.reference_commitment.startswith("linkref:v1:")


def test_reference_representation_and_key_selection_are_hmac_attested_not_raw_or_unkeyed_hashes():
    config, reference = prepared([{"birth_band": "1980s", "postal_band": "100"}])
    report = assess_linkage_risk(candidate=candidate([{"birth_band": "1980s", "postal_band": "100"}]),
                                  reference=reference, linkage_keys=config, commitment_verifier=AUTHORITY)
    public = report.to_record()
    assert "1980s" not in repr(reference) and "postal_band" not in repr(config)
    assert "1980s" not in json.dumps(public) and "postal_band" not in json.dumps(public)
    assert INPUT not in json.dumps(public)
    assert "tokens" not in public and "fields" not in public and "reference_digest" not in public
    assert public["reference_commitment"] != "sha256:" + "0" * 64


def test_wrong_missing_or_tampered_hmac_reference_inputs_abstain_before_metrics():
    config, reference = prepared([{"birth_band": "1980s", "postal_band": "100"}])
    candidate_value = candidate([{"birth_band": "1980s", "postal_band": "100"}])
    foreign = LinkageCommitmentAuthority.from_secret(b"f" * 32)
    tampered_reference = replace(reference, _public_commitment="linkref:v1:" + "A" * 43)
    tampered_config = replace(config, _public_commitment="linkcfg:v1:" + "A" * 43)
    for used_reference, used_config, verifier in (
        (reference, config, None), (reference, config, foreign), (tampered_reference, config, AUTHORITY),
        (reference, tampered_config, AUTHORITY),
    ):
        report = assess_linkage_risk(candidate=candidate_value, reference=used_reference, linkage_keys=used_config,
                                     commitment_verifier=verifier)
        assert report.status is LinkageRiskStatus.ABSTAINED
        assert report.abstention_reason is LinkageRiskAbstention.REFERENCE_COMMITMENT_UNVERIFIED
        assert report.candidate_record_count is None and report.matched_record_count is None


def test_candidate_shape_empty_limit_and_linkage_key_failures_are_explicit_no_metric_abstentions():
    config, reference = prepared([{"birth_band": "1980s", "postal_band": "100"}])
    cases = [
        (text_candidate(), LinkageRiskAbstention.TEXT_PAYLOAD),
        (candidate([["not-an-object"]]), LinkageRiskAbstention.UNSUPPORTED_RECORD_SHAPE),
        (candidate([]), LinkageRiskAbstention.EMPTY_CANDIDATE),
        (candidate([{"birth_band": "1980s"}]), LinkageRiskAbstention.LINKAGE_KEYS_NOT_APPLICABLE),
    ]
    for item, reason in cases:
        report = assess_linkage_risk(candidate=item, reference=reference, linkage_keys=config,
                                     commitment_verifier=AUTHORITY)
        assert report.status is LinkageRiskStatus.ABSTAINED
        assert report.abstention_reason is reason
        assert report.match_coverage_percent is None
    single_key, single_reference = prepared([{"link": "x"}], ("link",))
    oversized = candidate([{"link": "x"}] * 10_001)
    report = assess_linkage_risk(candidate=oversized, reference=single_reference, linkage_keys=single_key,
                                 commitment_verifier=AUTHORITY)
    assert report.status is LinkageRiskStatus.ABSTAINED
    assert report.abstention_reason is LinkageRiskAbstention.CANDIDATE_RECORD_LIMIT_EXCEEDED


def test_empty_and_malformed_or_cyclic_external_references_never_become_measurements():
    config, empty_reference = prepared([])
    report = assess_linkage_risk(candidate=candidate([{"birth_band": "1980s", "postal_band": "100"}]),
                                  reference=empty_reference, linkage_keys=config, commitment_verifier=AUTHORITY)
    assert report.status is LinkageRiskStatus.ABSTAINED
    assert report.abstention_reason is LinkageRiskAbstention.EMPTY_REFERENCE

    cyclic = []
    cyclic.append(cyclic)
    with pytest.raises(LinkageRiskError) as error:
        AUTHORITY.create_reference(cyclic, linkage_keys=config)
    assert str(error.value) == "Invalid linkage-risk assessment."
    with pytest.raises(LinkageRiskError):
        AUTHORITY.create_reference([{"birth_band": "x", "postal_band": "y"}] * 10_001, linkage_keys=config)
    with pytest.raises(LinkageRiskError):
        AUTHORITY.create_reference([{"birth_band": ["nested"], "postal_band": "y"}], linkage_keys=config)


def test_persisted_report_is_strict_deterministic_and_rejects_metric_digest_or_extra_data_tampering():
    report = assess([{"birth_band": "1980s", "postal_band": "100"}],
                    [{"birth_band": "1980s", "postal_band": "100"}])
    persisted = report.to_record()
    assert LinkageRiskReport.from_record(persisted).to_record() == persisted
    for altered in (
        {**persisted, "matched_record_count": 0},
        {**persisted, "digest": "sha256:" + "0" * 64},
        {**persisted, "reference_path": "private/reference.csv"},
    ):
        with pytest.raises(LinkageRiskError):
            LinkageRiskReport.from_record(altered)


def test_bad_public_contracts_fail_with_fixed_errors_without_private_content():
    with pytest.raises(LinkageRiskError) as error:
        LinkageCommitmentAuthority.from_secret(b"short")
    assert str(error.value) == "Invalid linkage-risk assessment."
    config, reference = prepared([{"birth_band": "1980s", "postal_band": "100"}])
    with pytest.raises(LinkageRiskError):
        assess_linkage_risk(candidate="not-an-artifact", reference=reference, linkage_keys=config,
                            commitment_verifier=AUTHORITY)
