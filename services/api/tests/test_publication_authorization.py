import base64
import json
from datetime import UTC, datetime, timedelta, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.postgres_publication_intents import PublicationIntent, _plan_digest
from app.publication_authorization import (PinnedPublicationAuthorizationVerifier,
                                           PublicationAuthorizationAttestation,
                                           PublicationAuthorizationError, _time)
from app.publication_payload_binding import PublicationPayloadBinding, payload_digest


NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
TENANT = "tenantref:v1:" + "A" * 43
PUBLICATION = "publicationref:v1:" + "B" * 43
OBJECT = "objectref:v1:" + "C" * 43
KEY = "keyref:v1:release-key"
TARGET = "metarecord:v1:" + "D" * 43


def _intent():
    return PublicationIntent(TENANT, PUBLICATION, "metatx:v1:" + "E" * 43, OBJECT, KEY,
                             "workref:v1:" + "F" * 43, TARGET, "release_output",
                             "sha256:" + "1" * 64, "sha256:" + "2" * 64, 0, {})


def _binding(intent):
    data = b'{"approved":true}\n'
    return PublicationPayloadBinding.create(tenant_ref=intent.tenant_ref,
        publication_ref=intent.publication_ref, object_ref=intent.object_ref, key_ref=intent.key_ref,
        plan_digest=_plan_digest(intent), payload_digest=payload_digest(data),
        payload_size_bytes=len(data), serialization_id="jsonl-utf8-v1")


def _signed(private, intent, binding, *, issued_at=NOW, expires_at=NOW + timedelta(minutes=5), **changes):
    values = dict(tenant_ref=intent.tenant_ref, publication_ref=intent.publication_ref,
        plan_digest=_plan_digest(intent), target_ref=intent.target_ref, metadata_kind=intent.metadata_kind,
        binding_digest=binding.binding_digest, release_case_id="release-case:v1:" + "G" * 43,
        release_case_digest="sha256:" + "3" * 64,
        privacy_decision_id="privacy-decision:v1:" + "H" * 43,
        privacy_decision_digest="sha256:" + "4" * 64,
        approval_digests=("sha256:" + "5" * 64, "sha256:" + "6" * 64),
        rights_digest="7" * 64, contract_digest="sha256:" + "8" * 64,
        recipient_commitment="recipient-commitment:v1:" + "I" * 43,
        purpose_code="model_training", issuer_key_id="issuer-a", issued_at=issued_at,
        expires_at=expires_at)
    values.update(changes)
    blank = "publication-authorization-sig:v1:" + "A" * 86
    unsigned = PublicationAuthorizationAttestation(signature=blank, **values)
    signature = "publication-authorization-sig:v1:" + base64.urlsafe_b64encode(
        private.sign(b"anonflow-publication-authorization-attestation:v1:\x00" +
                     json.dumps(unsigned.canonical(), ensure_ascii=True,
                         allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii"))).decode("ascii").rstrip("=")
    return PublicationAuthorizationAttestation(signature=signature, **values)


def _verifier(private):
    return PinnedPublicationAuthorizationVerifier({(TENANT, "issuer-a"): private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)})


def test_verifies_exact_signed_scope_and_strict_wire_round_trip():
    private = Ed25519PrivateKey.generate(); intent = _intent(); binding = _binding(intent)
    attestation = _signed(private, intent, binding)
    assert _verifier(private).verify(attestation=attestation, intent=intent, binding=binding, at=NOW)
    assert PublicationAuthorizationAttestation.from_record(attestation.to_record()) == attestation


def test_rejects_tampered_signature_and_noncanonical_wire_shape():
    private = Ed25519PrivateKey.generate(); intent = _intent(); binding = _binding(intent)
    attestation = _signed(private, intent, binding)
    forged = PublicationAuthorizationAttestation(
        tenant_ref=attestation.tenant_ref, publication_ref=attestation.publication_ref,
        plan_digest=attestation.plan_digest, target_ref=attestation.target_ref,
        metadata_kind=attestation.metadata_kind, binding_digest=attestation.binding_digest,
        release_case_id=attestation.release_case_id, release_case_digest=attestation.release_case_digest,
        privacy_decision_id=attestation.privacy_decision_id,
        privacy_decision_digest=attestation.privacy_decision_digest,
        approval_digests=attestation.approval_digests, rights_digest=attestation.rights_digest,
        contract_digest=attestation.contract_digest, recipient_commitment=attestation.recipient_commitment,
        purpose_code="other", issuer_key_id=attestation.issuer_key_id,
        issued_at=attestation.issued_at, expires_at=attestation.expires_at,
        signature=attestation.signature)
    assert not _verifier(private).verify(attestation=forged, intent=intent, binding=binding, at=NOW)
    changed = attestation.to_record(); changed["purpose_code"] = "other"
    # The digest protects stored records before the signature verifier sees them.
    try:
        PublicationAuthorizationAttestation.from_record(changed)
        assert False, "tampered record accepted"
    except ValueError:
        pass
    changed = attestation.to_record(); changed["extra"] = "nope"
    try:
        PublicationAuthorizationAttestation.from_record(changed)
        assert False, "compatibility shape accepted"
    except ValueError:
        pass


def test_rejects_non_distinct_approval_digests():
    private = Ed25519PrivateKey.generate(); intent = _intent(); binding = _binding(intent)
    try:
        _signed(private, intent, binding, approval_digests=("sha256:" + "5" * 64,) * 2)
        assert False, "duplicate approvals accepted"
    except ValueError:
        pass


def test_from_record_rejects_normalizing_approval_and_timestamp_spellings():
    private = Ed25519PrivateKey.generate(); intent = _intent(); binding = _binding(intent)
    attestation = _signed(private, intent, binding)
    swapped = attestation.to_record(); swapped["approval_digests"] = list(reversed(swapped["approval_digests"]))
    try:
        PublicationAuthorizationAttestation.from_record(swapped)
        assert False, "unordered approval list accepted"
    except ValueError:
        pass
    alternate_offset = attestation.to_record(); alternate_offset["issued_at"] = "2026-09-24T13:00:00+01:00"
    try:
        PublicationAuthorizationAttestation.from_record(alternate_offset)
        assert False, "non-UTC timestamp spelling accepted"
    except ValueError:
        pass
    malformed_time = attestation.to_record(); malformed_time["expires_at"] = 1
    try:
        PublicationAuthorizationAttestation.from_record(malformed_time)
        assert False, "malformed timestamp accepted"
    except ValueError:
        pass


def test_rejects_cross_publication_binding_and_plan_scope_drift():
    private = Ed25519PrivateKey.generate(); intent = _intent(); binding = _binding(intent)
    attestation = _signed(private, intent, binding); verifier = _verifier(private)
    other = PublicationIntent(TENANT, "publicationref:v1:" + "J" * 43,
        "metatx:v1:" + "K" * 43, OBJECT, KEY, "workref:v1:" + "F" * 43, TARGET,
        "release_output", "sha256:" + "1" * 64, "sha256:" + "2" * 64, 0, {})
    other_binding = PublicationPayloadBinding.create(tenant_ref=TENANT, publication_ref=other.publication_ref,
        object_ref=OBJECT, key_ref=KEY, plan_digest=_plan_digest(other), payload_digest=payload_digest(b"x"),
        payload_size_bytes=1, serialization_id="binary-v1")
    assert not verifier.verify(attestation=attestation, intent=other, binding=other_binding, at=NOW)
    changed_plan = PublicationIntent(TENANT, PUBLICATION, "metatx:v1:" + "E" * 43, OBJECT, KEY,
        "workref:v1:" + "F" * 43, TARGET, "other_kind", "sha256:" + "1" * 64,
        "sha256:" + "2" * 64, 0, {})
    assert not verifier.verify(attestation=attestation, intent=changed_plan, binding=binding, at=NOW)


def test_rejects_expired_future_and_untrusted_issuer():
    private = Ed25519PrivateKey.generate(); intent = _intent(); binding = _binding(intent)
    verifier = _verifier(private)
    assert not verifier.verify(attestation=_signed(private, intent, binding, expires_at=NOW + timedelta(seconds=1)),
                               intent=intent, binding=binding, at=NOW + timedelta(seconds=1))
    future = NOW + timedelta(seconds=1)
    assert not verifier.verify(attestation=_signed(private, intent, binding, issued_at=future,
        expires_at=future + timedelta(minutes=1)), intent=intent, binding=binding, at=NOW)
    outsider = Ed25519PrivateKey.generate()
    assert not verifier.verify(attestation=_signed(outsider, intent, binding), intent=intent, binding=binding, at=NOW)


def test_rejects_a_valid_signature_when_the_pin_is_for_another_tenant():
    private = Ed25519PrivateKey.generate()
    other_tenant = "tenantref:v1:" + "J" * 43
    other_intent = PublicationIntent(other_tenant, "publicationref:v1:" + "K" * 43,
        "metatx:v1:" + "L" * 43, "objectref:v1:" + "M" * 43, KEY,
        "workref:v1:" + "N" * 43, TARGET, "release_output", "sha256:" + "1" * 64,
        "sha256:" + "2" * 64, 0, {})
    other_binding = _binding(other_intent)
    other_attestation = _signed(private, other_intent, other_binding)
    assert not _verifier(private).verify(attestation=other_attestation, intent=other_intent,
                                         binding=other_binding, at=NOW)


def test_extreme_aware_timestamp_is_a_fixed_validation_error():
    try:
        _time(datetime.max.replace(tzinfo=timezone(-timedelta(hours=1))))
        assert False, "overflowing timestamp accepted"
    except PublicationAuthorizationError:
        pass
