import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib

import pytest

from app.release_case import (
    ReleaseCaseAuthority,
    ReleaseCaseBinding,
    ReleaseCaseError,
)


NOW = datetime(2026, 10, 1, tzinfo=UTC)
PRIVATE_KEY_B64 = base64.b64encode(bytes(range(32))).decode("ascii")
SALT = b"r" * 32


def digest(character: str) -> str:
    return "sha256:" + character * 64


def authority(*, tenant: str = "tenant-a", salt: bytes = SALT,
              commitment_key_id: str = "recipient-key-1") -> ReleaseCaseAuthority:
    return ReleaseCaseAuthority(
        tenant=tenant, issuer_key_id="release-issuer-1", expires_at=NOW + timedelta(days=30),
        recipient_commitment_key_id=commitment_key_id,
        private_key_b64=PRIVATE_KEY_B64, recipient_commitment_salt=salt,
    )


def issue(issuer: ReleaseCaseAuthority, **changes):
    values = {
        "case_id": "release-case:v1:" + "A" * 43,
        "candidate_artifact_digest": digest("a"),
        "processing_run_id": "run-1",
        "processing_run_digest": digest("b"),
        "processing_request_digest": digest("c"),
        "processing_mode": "batch-v1",
        "processing_policy_digest": digest("d"),
        "dataset_provenance_digest": digest("e"),
        "ingestion_provenance_digest": digest("f"),
        "rights_digest": "1" * 64,
        "recipient": "openai-labs",
        "purpose_code": "model-training",
        "method_provenance_digest": digest("2"),
        "contract_reference": "contract-reference:v1:" + "B" * 43,
        "contract_digest": digest("3"),
        "candidate_expires_at": NOW + timedelta(days=10),
        "processing_run_expires_at": NOW + timedelta(days=9),
        "rights_expires_at": NOW + timedelta(days=8),
        "contract_expires_at": NOW + timedelta(days=7),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(days=6),
        "at": NOW,
    }
    values.update(changes)
    return issuer.issue(**values)


def test_case_is_ed25519_signed_complete_and_source_safe():
    issuer = authority()
    case = issue(issuer)

    assert issuer.verifies(case, at=NOW + timedelta(seconds=1))
    assert issuer.public_verifier.verifies(case, at=NOW + timedelta(seconds=1))
    assert case.posture == "NO_RELEASE_AUTHORIZATION"
    assert case.binding.processing_request_digest == digest("c")
    assert case.binding.dataset_provenance_digest == digest("e")
    assert case.binding.ingestion_provenance_digest == digest("f")
    rendered = repr(case) + repr(issuer) + str(case.to_record())
    assert "openai-labs" not in rendered
    assert SALT.hex() not in rendered
    assert "APPROVED" not in str(case.to_record())
    assert not hasattr(issuer.public_verifier, "issue")


def test_recipient_commitment_is_salted_and_binds_full_counterparty_scope():
    first = issue(authority())
    alternate_salt = issue(authority(salt=b"s" * 32))
    rotated_commitment_key = issue(authority(commitment_key_id="recipient-key-2"))
    changed_run = issue(authority(), processing_run_id="run-2")
    changed_purpose = issue(authority(), purpose_code="research")
    changed_rights = issue(authority(), rights_digest="4" * 64)

    plain = hashlib.sha256(b"openai-labs").hexdigest()
    assert first.binding.recipient_commitment != "sha256:" + plain
    assert first.binding.recipient_commitment != alternate_salt.binding.recipient_commitment
    assert first.binding.recipient_commitment != rotated_commitment_key.binding.recipient_commitment
    assert first.authority_id != rotated_commitment_key.authority_id
    assert first.binding.recipient_commitment != changed_run.binding.recipient_commitment
    assert first.binding.recipient_commitment != changed_purpose.binding.recipient_commitment
    assert first.binding.recipient_commitment != changed_rights.binding.recipient_commitment


def test_cross_run_and_context_replay_are_detectable_by_the_signed_binding():
    issuer = authority()
    original = issue(issuer)
    other = issue(issuer, case_id="release-case:v1:" + "C" * 43,
                  processing_run_id="run-2", processing_run_digest=digest("4"),
                  processing_request_digest=digest("5"), dataset_provenance_digest=digest("6"),
                  ingestion_provenance_digest=digest("7"))

    assert original.binding.candidate_artifact_digest == other.binding.candidate_artifact_digest
    assert original.binding.digest != other.binding.digest
    assert original.binding.processing_run_id != other.binding.processing_run_id
    tampered = replace(original, binding=other.binding)
    assert not issuer.verifies(tampered, at=NOW + timedelta(seconds=1))


def test_authority_and_public_verifier_fail_closed_for_rotation_tampering_and_expiry():
    issuer = authority()
    case = issue(issuer)
    rotated_tenant = authority(tenant="tenant-b")
    altered = replace(case, expires_at=NOW + timedelta(days=5))

    assert not rotated_tenant.public_verifier.verifies(case, at=NOW + timedelta(seconds=1))
    assert not issuer.public_verifier.verifies(altered, at=NOW + timedelta(seconds=1))
    assert not issuer.public_verifier.verifies(case, at=case.expires_at)
    assert not issuer.public_verifier.verifies(case, at=issuer.expires_at)


@pytest.mark.parametrize("field", ["candidate_expires_at", "processing_run_expires_at", "rights_expires_at", "contract_expires_at"])
def test_expiry_is_conservative_minimum_of_every_bound_context(field):
    issuer = authority()
    with pytest.raises(ReleaseCaseError):
        issue(issuer, **{field: NOW + timedelta(days=5)})


def test_invalid_commitment_and_subsecond_times_are_rejected():
    with pytest.raises(ReleaseCaseError):
        ReleaseCaseBinding(
            candidate_artifact_digest=digest("a"), processing_run_id="run-1", processing_run_digest=digest("b"),
            processing_request_digest=digest("c"), processing_mode="batch-v1", processing_policy_digest=digest("d"),
            dataset_provenance_digest=digest("e"), ingestion_provenance_digest=digest("f"), rights_digest="1" * 64,
            recipient_commitment_key_id="recipient-key-1",
            recipient_commitment=digest("0"), purpose_code="model-training", method_provenance_digest=digest("2"),
            contract_reference="contract-reference:v1:" + "B" * 43, contract_digest=digest("3"),
            candidate_expires_at=NOW + timedelta(days=1), processing_run_expires_at=NOW + timedelta(days=1),
            rights_expires_at=NOW + timedelta(days=1), contract_expires_at=NOW + timedelta(days=1),
        )
    with pytest.raises(ReleaseCaseError):
        issue(authority(), issued_at=NOW.replace(microsecond=1))


def test_lifecycle_invalidation_is_external_but_changed_context_cannot_share_a_case_binding():
    """A future store must invalidate old cases; this pure value has no store state."""
    issuer = authority()
    original = issue(issuer)
    rotated_rights = issue(issuer, rights_digest="9" * 64)

    # A future admission/store comparison must require this exact digest rather
    # than treating a valid historical signature as authorization after a rights change.
    assert original.binding.rights_digest != rotated_rights.binding.rights_digest
    assert original.binding.digest != rotated_rights.binding.digest
