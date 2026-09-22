"""Tests for the tenant-bound privacy evidence attestation boundary."""
import base64
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
    PrivacyEvidenceAttestationProfile,
    PrivacyEvidenceBinding,
    PrivacyEvidenceKind,
    PrivacyEvidenceOutcome,
    PrivacyEvidencePolicy,
    PrivacyEvidencePolicyError,
    PrivacyEvidenceAuthority,
    PrivacyEvidencePublicVerifier,
    PrivacyEvidenceReason,
    assess_privacy_evidence,
)


# This is a synthetic issuer-time fixture, not a historical date test.  Keep
# it in the future so the production authority's intentional expiry check does
# not turn the suite into a calendar-dependent failure.
NOW = datetime.now(UTC).replace(microsecond=0)
DIGESTS = ["sha256:" + char * 64 for char in "abcdef123456789"]


def binding(method=DIGESTS[5]):
    return PrivacyEvidenceBinding(
        candidate_artifact_digest=DIGESTS[0], processing_policy_digest=DIGESTS[1], rights_digest="c" * 64,
        recipient_reference=DIGESTS[2], purpose_code="external-model-training",
        method_provenance_digest=method, candidate_expires_at=NOW + timedelta(days=2),
    )


def authority(kind=PrivacyEvidenceKind.UTILITY, *, tenant="tenant-a", secret=b"s" * 32):
    return PrivacyEvidenceAttestationAuthority(tenant=tenant, issuer_key_id="issuer-" + kind.value.lower(),
                                               expires_at=NOW + timedelta(days=90),
                                               private_key_b64=base64.b64encode(secret).decode("ascii"))


def policy(issuer, method=DIGESTS[5]):
    requirements = []
    for index, kind in enumerate(PrivacyEvidenceKind):
        configured = issuer.get(kind) if type(issuer) is dict else (issuer if kind is PrivacyEvidenceKind.UTILITY else None)
        requirements.append(EvidenceRequirement(
            kind, configured.issuer_key_id if configured else "issuer-" + kind.value.lower(),
            900_000 if kind in {PrivacyEvidenceKind.UTILITY, PrivacyEvidenceKind.BENCHMARK} else 10,
            authority_id=(configured.authority_id if configured else "privacy-authority:v2:" + chr(65 + index) * 43),
            public_key_fingerprint=(configured.policy_verifier.public_key_fingerprint if configured else "sha256:" + chr(97 + index) * 64),
        ))
    return PrivacyEvidencePolicy(policy_id="privacy-policy", method_provenance_digest=method,
                                 max_evidence_age_seconds=3600,
                                 requirements=tuple(sorted(requirements, key=lambda item: item.kind.value)),
                                 attestation_profile=PrivacyEvidenceAttestationProfile.ED25519_V2)


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
    assert item.authority_id.startswith("privacy-authority:v2:")
    assert item.digest.startswith("sha256:")
    policy_item = issuer.to_policy_evidence(item, at=NOW)
    verifier = issuer.policy_verifier
    assert verifier.verifies(policy_item, at=NOW)
    assert type(verifier).__name__ == "PrivacyEvidencePublicVerifier"
    assert not hasattr(verifier, "issue") and not hasattr(verifier, "_private_key")
    with pytest.raises(AttributeError):
        verifier._public_key.sign(b"cannot-sign-with-public-key")
    assert policy_item.kind is PrivacyEvidenceKind.UTILITY
    record = json.dumps(item.to_record(), sort_keys=True)
    for forbidden in ("secret", "b'", "alice@example.test", "Spirit Airlines", "recipient-name"):
        assert forbidden not in record


def test_verification_only_capability_cannot_mint_or_accept_arbitrary_five_kind_evidence():
    issuers = {kind: authority(kind, secret=bytes([index + 1]) * 32)
               for index, kind in enumerate(PrivacyEvidenceKind)}
    current_binding = binding()
    current_policy = policy(issuers, current_binding.method_provenance_digest)
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
    assert all(not issuers[item.kind].policy_verifier.verifies(item, at=NOW) for item in forged)
    decision = assess_privacy_evidence(decision_id="forged-evidence", binding=current_binding,
                                       policy=current_policy, evidence=forged,
                                       authorities=tuple(item.policy_verifier for item in issuers.values()), at=NOW)
    assert decision.outcome is PrivacyEvidenceOutcome.QUARANTINED
    assert PrivacyEvidenceReason.EVIDENCE_UNVERIFIED in decision.reasons


def test_adapter_output_is_directly_consumable_by_existing_policy_contract():
    issuers = {kind: authority(kind, secret=bytes([index + 1]) * 32)
               for index, kind in enumerate(PrivacyEvidenceKind)}
    current_binding = binding()
    current_policy = policy(issuers, current_binding.method_provenance_digest)
    records = tuple(issuers[kind].to_policy_evidence(issuers[kind].issue(
        kind=kind, evidence_reference="evidence:v1:" + chr(65 + index) * 43,
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
    ("tenant", "tenant-b"), ("authority_id", "privacy-authority:v2:" + "A" * 43),
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
                                           requirements=tuple(requirements), attestation_profile=item.policy.attestation_profile)
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
                                               requirements=item.policy.requirements, attestation_profile=item.policy.attestation_profile)
    assert not issuer.verifies(replace(item, policy=changed_policy), at=NOW)


def test_foreign_tenant_secret_rotation_expiry_and_subclasses_cannot_verify_or_issue():
    issuer = authority()
    item = reference(issuer)
    assert not authority(tenant="tenant-b").verifies(item, at=NOW)
    assert not authority(secret=b"r" * 32).verifies(item, at=NOW)
    assert not issuer.verifies(item, at=NOW + timedelta(days=91))
    with pytest.raises(PrivacyEvidenceAuthorityError):
        PrivacyEvidenceAttestationAuthority(tenant="tenant-a", issuer_key_id="issuer-utility",
                                             expires_at=NOW - timedelta(seconds=1),
                                             private_key_b64=base64.b64encode(b"s" * 32).decode("ascii"))

    # Authority expiry is part of the opaque key commitment, so changing the
    # authority configuration cannot relabel an older attestation.
    same_key_new_expiry = PrivacyEvidenceAttestationAuthority(
        tenant="tenant-a", issuer_key_id="issuer-utility", expires_at=NOW + timedelta(days=91),
        private_key_b64=base64.b64encode(b"s" * 32).decode("ascii"))
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
        private_key_b64=base64.b64encode(b"z" * 32).decode("ascii"))
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


def test_ed25519_key_encodings_are_strict_and_public_verifier_never_accepts_hmac_or_bad_signatures():
    with pytest.raises(PrivacyEvidenceAuthorityError):
        PrivacyEvidenceAttestationAuthority(tenant="tenant-key", issuer_key_id="issuer-utility",
                                             expires_at=NOW + timedelta(days=2), private_key_b64="not-base64")
    with pytest.raises(PrivacyEvidencePolicyError):
        PrivacyEvidencePublicVerifier(tenant="tenant-key", key_id="issuer-utility",
                                      authority_id="privacy-authority:v2:" + "A" * 43,
                                      public_key_b64="A" * 44, expires_at=NOW + timedelta(days=1))
    issuer = authority()
    item = reference(issuer)
    policy_item = issuer.to_policy_evidence(item, at=NOW)
    with pytest.raises(PrivacyEvidencePolicyError):
        replace(policy_item, signature="privacy-evidence-sig:v1:" + "A" * 43)
    malformed = replace(policy_item, signature="privacy-evidence-sig:v2:" + "A" * 86)
    assert not issuer.policy_verifier.verifies(malformed, at=NOW)


def test_expired_old_private_key_cannot_verify_or_directly_forge_for_a_replaced_authority():
    encoded = base64.b64encode(b"o" * 32).decode("ascii")
    old = PrivacyEvidenceAttestationAuthority(tenant="tenant-a", issuer_key_id="issuer-utility",
                                               expires_at=NOW + timedelta(days=1), private_key_b64=encoded)
    old_policy = policy(old)
    old_reference = old.issue(kind=PrivacyEvidenceKind.UTILITY, evidence_reference="evidence:v1:" + "O" * 43,
                              evidence_digest=DIGESTS[6], binding=binding(), policy=old_policy,
                              observed_value=950_000, measured_at=NOW, expires_at=NOW + timedelta(hours=1), at=NOW)
    old_evidence = old.to_policy_evidence(old_reference, at=NOW)
    replacement = PrivacyEvidenceAttestationAuthority(tenant="tenant-a", issuer_key_id="issuer-utility",
                                                       expires_at=NOW + timedelta(days=2),
                                                       private_key_b64=base64.b64encode(b"r" * 32).decode("ascii"))
    assert not old.policy_verifier.verifies(old_evidence, at=NOW + timedelta(hours=1))
    assert not replacement.policy_verifier.verifies(old_evidence, at=NOW)
    replacement_policy = policy(replacement)
    provisional = AttestedPrivacyEvidence(
        binding_digest=binding().digest, evidence_digest=DIGESTS[6],
        evidence_policy_digest=replacement_policy.digest, evidence_reference="evidence:v1:" + "F" * 43,
        issuer_key_id="issuer-utility", kind=PrivacyEvidenceKind.UTILITY,
        method_provenance_digest=binding().method_provenance_digest, observed_value=950_000,
        measured_at=NOW, expires_at=NOW + timedelta(hours=1),
        authority_tenant=replacement.tenant, authority_id=replacement.authority_id,
        authority_public_key_fingerprint=replacement.policy_verifier.public_key_fingerprint,
        signature="privacy-evidence-sig:v2:" + "A" * 86,
    )
    old_signature = old._private_key.sign(b"privacy-evidence-v2:" + json.dumps(
        provisional.canonical(), ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii"))
    forged = replace(provisional, signature="privacy-evidence-sig:v2:" + base64.urlsafe_b64encode(old_signature).decode("ascii").rstrip("="))
    assert not replacement.policy_verifier.verifies(forged, at=NOW)


def test_v2_profile_rejects_legacy_hmac_downgrade_and_legacy_profile_rejects_v2_descriptors():
    issuer = authority()
    current_policy = policy(issuer)
    hmac_authority = PrivacyEvidenceAuthority(key_id=issuer.issuer_key_id, secret=b"h" * 32)
    hmac_evidence = hmac_authority.issue(kind=PrivacyEvidenceKind.UTILITY, evidence_reference="evidence:v1:" + "H" * 43,
                                         evidence_digest=DIGESTS[6], binding=binding(), policy=current_policy,
                                         observed_value=950_000, measured_at=NOW, expires_at=NOW + timedelta(hours=2))
    decision = assess_privacy_evidence(decision_id="no-downgrade", binding=binding(), policy=current_policy,
                                       evidence=(hmac_evidence,), authorities=(issuer.policy_verifier,), at=NOW)
    assert decision.outcome is PrivacyEvidenceOutcome.QUARANTINED
    with pytest.raises(PrivacyEvidencePolicyError):
        PrivacyEvidencePolicy(policy_id=current_policy.policy_id,
                              method_provenance_digest=current_policy.method_provenance_digest,
                              max_evidence_age_seconds=current_policy.max_evidence_age_seconds,
                              requirements=current_policy.requirements)
