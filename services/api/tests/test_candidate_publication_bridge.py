"""M44a exact private-candidate byte bridge regressions."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import secrets

import pytest

from app.candidate import CandidateArtifact, CandidateError, PayloadKind, SchemaContract
from app.candidate_publication_bridge import (CandidatePublicationBridgeError,
                                              ExactCandidatePublication,
                                              derive_exact_candidate_publication)
from app.postgres_publication_intents import PublicationIntent, _plan_digest
from app.publication_payload_binding import payload_digest
from app.release_case import ReleaseCaseBinding


NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)


def digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("ascii")).hexdigest()


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def candidate(value: str | dict) -> CandidateArtifact:
    kind = PayloadKind.TEXT if type(value) is str else PayloadKind.STRUCTURED
    return CandidateArtifact.create(
        run_id="run-1", input_digest=digest("input"), policy_digest=digest("policy"),
        transformed=value, schema=SchemaContract.from_value(value, kind=kind))


def case_for(item: CandidateArtifact, **overrides) -> ReleaseCaseBinding:
    values = dict(
        candidate_artifact_digest=item.metadata.artifact_digest, processing_run_id="run-1",
        processing_run_digest=digest("run"), processing_request_digest=digest("request"),
        processing_mode="batch-v1", processing_policy_digest=digest("policy"),
        dataset_provenance_digest=digest("dataset"), ingestion_provenance_digest=digest("ingestion"),
        rights_digest="a" * 64, recipient_commitment_key_id="recipient-key-v1",
        recipient_commitment=opaque("recipient-commitment:v1:"), purpose_code="model_training",
        method_provenance_digest=digest("method"),
        contract_reference=opaque("contract-reference:v1:"), contract_digest=digest("contract"),
        candidate_expires_at=NOW + timedelta(days=1), processing_run_expires_at=NOW + timedelta(days=1),
        rights_expires_at=NOW + timedelta(days=1), contract_expires_at=NOW + timedelta(days=1))
    values.update(overrides)
    return ReleaseCaseBinding(**values)


def intent(**overrides) -> PublicationIntent:
    values = dict(
        tenant_ref=opaque("tenantref:v1:"), publication_ref=opaque("publicationref:v1:"),
        transaction_id=opaque("metatx:v1:"), object_ref=opaque("objectref:v1:"),
        key_ref="keyref:v1:release-key", work_ref=opaque("workref:v1:"),
        target_ref=opaque("metarecord:v1:"), metadata_kind="release_artifact",
        request_digest=digest("request"), policy_digest=digest("policy"), expected_version=0,
        attributes={})
    values.update(overrides)
    return PublicationIntent(**values)


def test_text_uses_the_exact_stored_utf8_candidate_bytes_and_is_repr_safe():
    artifact = candidate("safe\ntext")
    result = derive_exact_candidate_publication(candidate=artifact, case_binding=case_for(artifact), intent=intent())

    assert result.bytes_for_private_worker() == b"safe\ntext"
    assert result.binding.payload_digest == payload_digest(b"safe\ntext")
    assert result.binding.payload_size_bytes == len(b"safe\ntext")
    assert result.binding.serialization_id == "binary-v1"
    assert "safe" not in repr(result)


def test_structured_uses_canonical_candidate_bytes_without_json_reserialization():
    artifact = candidate({"z": [2, 1], "a": "safe"})
    plan = intent()
    result = derive_exact_candidate_publication(candidate=artifact, case_binding=case_for(artifact), intent=plan)

    assert result.bytes_for_private_worker() == b'{"a":"safe","z":[2,1]}'
    assert result.binding.payload_digest == payload_digest(b'{"a":"safe","z":[2,1]}')
    assert result.binding.plan_digest == _plan_digest(plan)


def test_same_size_alternate_bytes_cannot_be_substituted_into_the_derived_binding():
    artifact = candidate("safe")
    result = derive_exact_candidate_publication(candidate=artifact, case_binding=case_for(artifact), intent=intent())

    alternate = b"evil"
    assert len(alternate) == len(result.bytes_for_private_worker())
    assert payload_digest(alternate) != result.binding.payload_digest
    with pytest.raises(CandidatePublicationBridgeError):
        ExactCandidatePublication(binding=result.binding, _payload=alternate)


def test_mutated_in_memory_candidate_bytes_fail_before_any_binding_is_issued():
    artifact = candidate("safe")
    object.__setattr__(artifact, "_encoded", b"evil")

    with pytest.raises(CandidatePublicationBridgeError):
        derive_exact_candidate_publication(candidate=artifact, case_binding=case_for(artifact), intent=intent())


@pytest.mark.parametrize("change", ("candidate_digest", "run", "case_policy", "intent_request", "intent_policy"))
def test_scope_drift_fails_closed(change: str):
    artifact = candidate("safe")
    case, plan = case_for(artifact), intent()
    if change == "candidate_digest":
        case = case_for(artifact, candidate_artifact_digest=digest("other"))
    elif change == "run":
        case = case_for(artifact, processing_run_id="run-2")
    elif change == "case_policy":
        case = case_for(artifact, processing_policy_digest=digest("other-policy"))
    elif change == "intent_request":
        plan = intent(request_digest=digest("other-request"))
    else:
        plan = intent(policy_digest=digest("other-policy"))

    with pytest.raises(CandidatePublicationBridgeError):
        derive_exact_candidate_publication(candidate=artifact, case_binding=case, intent=plan)


def test_empty_input_cannot_be_coerced_into_an_empty_release_payload():
    """The existing candidate contract rejects empty text before M44a runs."""
    with pytest.raises(CandidateError):
        candidate("")
