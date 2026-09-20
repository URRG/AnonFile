"""Tests for the tenant-bound privacy evidence attestation boundary."""
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json

import pytest

from app.privacy_evidence_authority import (
    PrivacyEvidenceAttestationAuthority,
    PrivacyEvidenceAuthorityError,
    PrivacyEvidenceReference,
)
from app.privacy_evidence_policy import (
    AttestedPrivacyEvidence,
    EvidenceRequirement,
    PrivacyEvidenceBinding,
    PrivacyEvidenceKind,
    PrivacyEvidenceOutcome,
    PrivacyEvidencePolicy,
    PrivacyEvidenceReason,
    assess_privacy_evidence,
)


NOW = datetime(2026, 9, 20, 12, 0, tzinfo=UTC)
DIGESTS = ["sha256:" + char * 64 for char in "abcdef123456789"]


def binding(method=DIGESTS[5]):
    return PrivacyEvidenceBinding(
        candidate_artifact_digest=DIGESTS[0], processing_policy_digest=DIGESTS[1], rights_digest="c" * 64,
        recipient_reference=DIGESTS[2], purpose_code="external-model-training",
        method_provenance_digest=method, candidate_expires_at=NOW + timedelta(days=2),
    )


def authority(kind=PrivacyEvidenceKind.UTILITY, *, tenant="tenant-a", secret=b"s" * 32):
    return PrivacyEvidenceAttestationAuthority(tenant=tenant, issuer_key_id="issuer-" + kind.value.lower(),
                                               expires_at=NOW + timedelta(days=90), _secret=secret)


def policy(issuer, method=DIGESTS[5]):
    requirements = []
    for index, kind in enumerate(PrivacyEvidenceKind):
        requirements.append(EvidenceRequirement(
            kind, issuer.issuer_key_id if kind is PrivacyEvidenceKind.UTILITY else "issuer-" + kind.value.lower(),
            900_000 if kind in {PrivacyEvidenceKind.UTILITY, PrivacyEvidenceKind.BENCHMARK} else 10,
        ))
    return PrivacyEvidencePolicy(policy_id="privacy-policy", method_provenance_digest=method,
                                 max_evidence_age_seconds=3600,
                                 requirements=tuple(sorted(requirements, key=lambda item: item.kind.value)))


def reference(current_authority=None, current_binding=None, current_policy=None):
    current_authority = current_authority or authority()
    current_binding = current_binding or binding()
    current_policy = current_policy or policy(current_authority, current_binding.method_provenance_digest)
    return current_authority.issue(
        kind=PrivacyEvidenceKind.UTILITY, evidence_reference="evidence:v1:" + "U" * 43,
        evidence_digest=DIGESTS[6], binding=current_binding, policy=current_policy, observed_value=950_000,
        measured_at=NOW, expires_at=NOW + timedelta(hours=2), at=NOW,
    )


def test_issues_verifies_and_adapts_a_complete_source_safe_reference_for_policy():
    issuer = authority()
    item = reference(issuer)
    assert issuer.verifies(item, at=NOW)
    assert item.authority_id.startswith("privacy-authority:v1:")
    assert item.digest.startswith("sha256:")
    policy_item = issuer.to_policy_evidence(item, at=NOW)
    assert issuer.policy_verifier.verifies(policy_item)
    assert type(issuer.policy_verifier).__name__ == "PrivacyEvidenceVerifier"
    with pytest.raises(AttributeError):
        getattr(issuer.policy_verifier, "issue")
    assert policy_item.kind is PrivacyEvidenceKind.UTILITY
    record = json.dumps(item.to_record(), sort_keys=True)
    for forbidden in ("secret", "b'", "alice@example.test", "Spirit Airlines", "recipient-name"):
        assert forbidden not in record


def test_verification_only_capability_cannot_mint_or_accept_arbitrary_five_kind_evidence():
    issuers = {kind: authority(kind, secret=bytes([index + 1]) * 32)
               for index, kind in enumerate(PrivacyEvidenceKind)}
    current_binding = binding()
    current_policy = policy(issuers[PrivacyEvidenceKind.UTILITY], current_binding.method_provenance_digest)
    forged = tuple(AttestedPrivacyEvidence(
        kind=kind, evidence_reference="evidence:v1:" + chr(65 + index) * 43,
        evidence_digest="sha256:" + chr(97 + index) * 64, binding_digest=current_binding.digest,
        evidence_policy_digest=current_policy.digest, method_provenance_digest=current_binding.method_provenance_digest,
        issuer_key_id=issuers[kind].issuer_key_id,
        observed_value=(950_000 if kind in {PrivacyEvidenceKind.UTILITY, PrivacyEvidenceKind.BENCHMARK}
                        else 10 if kind is PrivacyEvidenceKind.DISCLOSURE_RISK else 0),
        measured_at=NOW, expires_at=NOW + timedelta(hours=2),
        signature="privacy-evidence-sig:v1:" + "A" * 43,
    ) for index, kind in enumerate(PrivacyEvidenceKind))
    assert all(not issuers[item.kind].policy_verifier.verifies(item) for item in forged)
    decision = assess_privacy_evidence(
        decision_id="forged-evidence", binding=current_binding, policy=current_policy, evidence=forged,
        authorities=tuple(item.policy_verifier for item in issuers.values()), at=NOW)
    assert decision.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.EVIDENCE_UNVERIFIED in decision.reasons


def test_adapter_output_is_directly_consumable_by_existing_policy_contract():
    issuers = {kind: authority(kind, secret=bytes([index + 1]) * 32)
               for index, kind in enumerate(PrivacyEvidenceKind)}
    current_binding = binding()
    current_policy = policy(issuers[PrivacyEvidenceKind.UTILITY], current_binding.method_provenance_digest)
    records = tuple(issuers[kind].to_policy_evidence(
        issuers[kind].issue(kind=kind, evidence_reference="evidence:v1:" + chr(65 + index) * 43,
                            evidence_digest="sha256:" + chr(97 + index) * 64,
                            binding=current_binding, policy=current_policy,
                            observed_value=(950_000 if kind in {PrivacyEvidenceKind.UTILITY, PrivacyEvidenceKind.BENCHMARK}
                                            else 10 if kind is PrivacyEvidenceKind.DISCLOSURE_RISK else 0),
                            measured_at=NOW, expires_at=NOW + timedelta(hours=2), at=NOW), at=NOW)
        for index, kind in enumerate(PrivacyEvidenceKind))
    decision = assess_privacy_evidence(decision_id="m12-decision", binding=current_binding, policy=current_policy,
                                       evidence=records, authorities=tuple(item.policy_verifier for item in issuers.values()), at=NOW)
    assert decision.outcome is PrivacyEvidenceOutcome.INSUFFICIENT_EVIDENCE
    assert decision.reasons == (PrivacyEvidenceReason.INDEPENDENT_RELEASE_AUTHORIZATION_REQUIRED,)


@pytest.mark.parametrize(("field", "value"), [
    ("evidence_digest", DIGESTS[7]), ("observed_value", 950_001), ("issuer_key_id", "issuer-foreign"),
    ("tenant", "tenant-b"), ("authority_id", "privacy-authority:v1:" + "A" * 43),
])
def test_tampering_complete_scope_or_authority_identity_fails_closed(field, value):
    issuer = authority()
    item = reference(issuer)
    altered = replace(item, **{field: value})
    assert not issuer.verifies(altered, at=NOW)
    with pytest.raises(PrivacyEvidenceAuthorityError):
        issuer.to_policy_evidence(altered, at=NOW)


@pytest.mark.parametrize(("field", "value"), [
    ("candidate_artifact_digest", DIGESTS[7]), ("processing_policy_digest", DIGESTS[8]),
    ("rights_digest", "d" * 64), ("recipient_reference", DIGESTS[8]), ("purpose_code", "other-purpose"),
    ("method_provenance_digest", DIGESTS[8]), ("candidate_expires_at", NOW + timedelta(days=3)),
])
def test_every_binding_field_is_in_the_attested_scope(field, value):
    issuer = authority()
    item = reference(issuer)
    altered_binding = replace(item.binding, **{field: value})
    altered = replace(item, binding=altered_binding)
    assert not issuer.verifies(altered, at=NOW)


def test_complete_policy_canonical_including_other_issuer_thresholds_is_in_scope():
    issuer = authority()
    item = reference(issuer)
    requirements = list(item.policy.requirements)
    index = next(index for index, requirement in enumerate(requirements)
                 if requirement.kind is PrivacyEvidenceKind.BENCHMARK)
    requirements[index] = replace(requirements[index], threshold=899_999)
    changed_policy = PrivacyEvidencePolicy(policy_id=item.policy.policy_id,
                                           method_provenance_digest=item.policy.method_provenance_digest,
                                           max_evidence_age_seconds=item.policy.max_evidence_age_seconds,
                                           requirements=tuple(requirements))
    assert not issuer.verifies(replace(item, policy=changed_policy), at=NOW)


@pytest.mark.parametrize(("field", "value"), [
    ("policy_id", "privacy-policy-revised"), ("method_provenance_digest", DIGESTS[8]),
    ("max_evidence_age_seconds", 1800),
])
def test_every_top_level_policy_field_is_in_the_attested_scope(field, value):
    issuer = authority()
    item = reference(issuer)
    changed_policy = PrivacyEvidencePolicy(policy_id=value if field == "policy_id" else item.policy.policy_id,
                                           method_provenance_digest=value if field == "method_provenance_digest" else item.policy.method_provenance_digest,
                                           max_evidence_age_seconds=value if field == "max_evidence_age_seconds" else item.policy.max_evidence_age_seconds,
                                           requirements=item.policy.requirements)
    assert not issuer.verifies(replace(item, policy=changed_policy), at=NOW)


def test_foreign_tenant_secret_rotation_expiry_and_subclasses_cannot_verify_or_issue():
    issuer = authority()
    item = reference(issuer)
    assert not authority(tenant="tenant-b").verifies(item, at=NOW)
    assert not authority(secret=b"r" * 32).verifies(item, at=NOW)
    assert not issuer.verifies(item, at=NOW + timedelta(days=91))
    with pytest.raises(PrivacyEvidenceAuthorityError):
        PrivacyEvidenceAttestationAuthority(tenant="tenant-a", issuer_key_id="issuer-utility",
                                             expires_at=NOW - timedelta(seconds=1), _secret=b"s" * 32)

    # Authority expiry is part of the opaque key commitment, so changing the
    # authority configuration cannot relabel an older attestation.
    same_key_new_expiry = PrivacyEvidenceAttestationAuthority(
        tenant="tenant-a", issuer_key_id="issuer-utility", expires_at=NOW + timedelta(days=91), _secret=b"s" * 32)
    assert same_key_new_expiry.authority_id != issuer.authority_id
    assert not same_key_new_expiry.verifies(item, at=NOW)

    class Subclass(PrivacyEvidenceReference):
        pass

    with pytest.raises(PrivacyEvidenceAuthorityError):
        Subclass(**{name: getattr(item, name) for name in item.__dataclass_fields__})


def test_wrong_policy_issuer_or_time_window_cannot_be_issued_and_reference_never_bypasses_policy_attestation():
    issuer = authority()
    current_binding = binding()
    current_policy = policy(issuer)
    with pytest.raises(PrivacyEvidenceAuthorityError):
        issuer.issue(kind=PrivacyEvidenceKind.RESIDUAL_SCAN, evidence_reference="evidence:v1:" + "A" * 43,
                     evidence_digest=DIGESTS[6], binding=current_binding, policy=current_policy, observed_value=0,
                     measured_at=NOW, expires_at=NOW + timedelta(hours=1), at=NOW)
    with pytest.raises(PrivacyEvidenceAuthorityError):
        issuer.issue(kind=PrivacyEvidenceKind.UTILITY, evidence_reference="evidence:v1:" + "A" * 43,
                     evidence_digest=DIGESTS[6], binding=current_binding, policy=current_policy, observed_value=950_000,
                     measured_at=NOW, expires_at=NOW + timedelta(days=32), at=NOW)
    with pytest.raises(PrivacyEvidenceAuthorityError):
        issuer.issue(kind=PrivacyEvidenceKind.UTILITY, evidence_reference="evidence:v1:" + "A" * 43,
                     evidence_digest=DIGESTS[6], binding=current_binding, policy=current_policy, observed_value=950_000,
                     measured_at=NOW + timedelta(seconds=1), expires_at=NOW + timedelta(hours=1), at=NOW)
    item = reference(issuer)
    decision = assess_privacy_evidence(decision_id="raw-reference", binding=current_binding, policy=current_policy,
                                       evidence=(item,), authorities=(issuer.policy_verifier,), at=NOW)
    assert decision.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.EVIDENCE_UNVERIFIED in decision.reasons


def test_issue_and_verify_enforce_candidate_and_evidence_time_windows():
    issuer = authority()
    current_policy = policy(issuer)
    short_lived_binding = replace(binding(), candidate_expires_at=NOW + timedelta(hours=1))
    with pytest.raises(PrivacyEvidenceAuthorityError):
        issuer.issue(kind=PrivacyEvidenceKind.UTILITY, evidence_reference="evidence:v1:" + "A" * 43,
                     evidence_digest=DIGESTS[6], binding=short_lived_binding, policy=current_policy,
                     observed_value=950_000, measured_at=NOW, expires_at=NOW + timedelta(hours=2), at=NOW)
    with pytest.raises(PrivacyEvidenceAuthorityError):
        issuer.issue(kind=PrivacyEvidenceKind.UTILITY, evidence_reference="evidence:v1:" + "A" * 43,
                     evidence_digest=DIGESTS[6], binding=short_lived_binding, policy=current_policy,
                     observed_value=950_000, measured_at=short_lived_binding.candidate_expires_at,
                     expires_at=short_lived_binding.candidate_expires_at, at=NOW)
    item = reference(issuer)
    future = replace(item, measured_at=NOW + timedelta(seconds=1), expires_at=NOW + timedelta(hours=2, seconds=1))
    expired = replace(item, measured_at=NOW - timedelta(hours=2), expires_at=NOW - timedelta(hours=1))
    assert not issuer.verifies(future, at=NOW)
    assert not issuer.verifies(expired, at=NOW)


def test_default_clock_is_normalized_to_seconds_for_active_issue_and_verify_paths():
    instant = datetime.now(UTC).replace(microsecond=0)
    issuer = PrivacyEvidenceAttestationAuthority(
        tenant="tenant-live", issuer_key_id="issuer-utility", expires_at=instant + timedelta(minutes=10),
        _secret=b"z" * 32)
    current_binding = PrivacyEvidenceBinding(
        candidate_artifact_digest=DIGESTS[0], processing_policy_digest=DIGESTS[1], rights_digest="c" * 64,
        recipient_reference=DIGESTS[2], purpose_code="external-model-training",
        method_provenance_digest=DIGESTS[5], candidate_expires_at=instant + timedelta(minutes=5))
    current_policy = policy(issuer, current_binding.method_provenance_digest)
    item = issuer.issue(kind=PrivacyEvidenceKind.UTILITY, evidence_reference="evidence:v1:" + "Z" * 43,
                        evidence_digest=DIGESTS[6], binding=current_binding, policy=current_policy,
                        observed_value=950_000, measured_at=instant - timedelta(seconds=1),
                        expires_at=instant + timedelta(minutes=1))
    assert issuer.is_active()
    assert issuer.verifies(item)
