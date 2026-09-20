import json

import pytest

from app.candidate import (CandidateArtifact, CandidateError, CandidateMetadata,
                           LedgerAction, LedgerReason, PayloadKind,
                           SchemaContract, TransformLedgerEntry, canonical_json)


INPUT = "sha256:" + "a" * 64
POLICY = "sha256:" + "b" * 64


def ledger():
    return (TransformLedgerEntry("EMAIL", LedgerAction.REDACT, LedgerReason.POLICY_RULE, 2),)


def text_schema():
    return SchemaContract.from_value("source private input", kind=PayloadKind.TEXT)


def records_schema(*, nullable=False):
    return SchemaContract.from_value([{"email": "a@example.test", "count": 7, "active": True}],
                                     kind=PayloadKind.STRUCTURED, allow_scalar_nulls=nullable)


def test_text_candidate_binds_digests_and_never_shows_private_output_in_repr_or_metadata():
    artifact = CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                         transformed="[REDACTED_EMAIL]", schema=text_schema(), ledger=ledger())
    assert artifact.metadata.artifact_digest.startswith("sha256:")
    assert artifact.metadata.media_type == "text/plain"
    assert artifact.metadata.ledger == ledger()
    assert "REDACTED_EMAIL" not in repr(artifact)
    assert "REDACTED_EMAIL" not in repr(artifact.metadata)
    assert artifact.materialize_for_private_worker() == "[REDACTED_EMAIL]"


def test_text_schema_accepts_a_bounded_artifact_larger_than_structured_scalar_limit():
    source = "x" * 65_537
    schema = SchemaContract.from_value(source, kind=PayloadKind.TEXT)
    artifact = CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                         transformed=source, schema=schema)
    assert artifact.metadata.byte_count == len(source)


def test_structured_candidate_digest_is_canonical_and_materializes_detached_value():
    schema = SchemaContract.from_value({"a": "original", "b": [1, 2]}, kind=PayloadKind.STRUCTURED)
    first = CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                     transformed={"b": [1, 2], "a": "changed"}, schema=schema)
    second = CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                      transformed={"a": "changed", "b": [1, 2]}, schema=schema)
    assert first.metadata.artifact_digest == second.metadata.artifact_digest
    value = first.materialize_for_private_worker()
    value["b"].append(3)
    assert first.materialize_for_private_worker() == {"a": "changed", "b": [1, 2]}


def test_schema_preserves_object_keys_shapes_and_scalar_types():
    schema = records_schema()
    good = CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                    transformed=[{"email": "[REDACTED_EMAIL]", "count": 7, "active": True}],
                                    schema=schema, ledger=ledger())
    assert good.metadata.payload_kind is PayloadKind.STRUCTURED
    for bad in ([{"email": "safe", "count": "7", "active": True}],
                [{"email": "safe", "count": 7}],
                {"email": "safe", "count": 7, "active": True}):
        with pytest.raises(CandidateError) as error:
            CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                     transformed=bad, schema=schema)
        assert str(error.value) == "Invalid private candidate artifact."


def test_explicit_nullable_schema_allows_policy_nullification_without_other_type_drift():
    schema = records_schema(nullable=True)
    result = CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                      transformed=[{"email": "[REDACTED_EMAIL]", "count": None, "active": True}],
                                      schema=schema,
                                      ledger=(TransformLedgerEntry("PAYMENT", LedgerAction.NULLIFY,
                                                                   LedgerReason.SCHEMA_SAFE_NULL, 1),))
    assert result.materialize_for_private_worker()[0]["count"] is None


def test_ledger_is_typed_aggregate_only_sorted_and_has_no_original_value_slot():
    with pytest.raises(CandidateError):
        TransformLedgerEntry("email", LedgerAction.REDACT, LedgerReason.POLICY_RULE, 1)
    schema = text_schema()
    first = TransformLedgerEntry("EMAIL", LedgerAction.REDACT, LedgerReason.POLICY_RULE, 1)
    second = TransformLedgerEntry("PII", LedgerAction.SUPPRESS, LedgerReason.DETECTOR_FINDING, 1)
    with pytest.raises(CandidateError):
        CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                 transformed="safe", schema=schema, ledger=(second, first))
    assert "original" not in TransformLedgerEntry.__dataclass_fields__
    assert "value" not in TransformLedgerEntry.__dataclass_fields__


def deep_value():
    value = 1
    for _ in range(35):
        value = {"x": value}
    return value


@pytest.mark.parametrize("bad", [float("nan"), {"x": "\ud800"}, deep_value()])
def test_malformed_json_unicode_and_deep_graphs_have_safe_errors(bad):
    with pytest.raises(CandidateError) as error:
        canonical_json(bad)
    assert str(error.value) == "Invalid private candidate artifact."


def test_oversized_candidate_and_bad_digests_are_rejected_without_echoing_input():
    schema = SchemaContract.from_value("x", kind=PayloadKind.TEXT)
    private = "private-value-" + "x" * 2_000_000
    with pytest.raises(CandidateError) as error:
        CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                 transformed=private, schema=schema)
    assert private[:30] not in str(error.value)
    with pytest.raises(CandidateError):
        CandidateArtifact.create(run_id="run-1", input_digest="not-a-digest", policy_digest=POLICY,
                                 transformed="safe", schema=schema)


def test_schema_contract_direct_tampering_fails_and_canonical_json_is_deterministic():
    source = {"z": 1, "a": [True, None]}
    assert canonical_json(source) == canonical_json({"a": [True, None], "z": 1})
    contract = SchemaContract.from_value(source, kind=PayloadKind.STRUCTURED)
    with pytest.raises(CandidateError):
        SchemaContract(kind=contract.kind, digest=contract.digest, _descriptor=b'{"type":"text"}')
    assert "source" not in repr(contract)


def test_private_schema_descriptor_round_trips_without_exposing_values():
    contract = SchemaContract.from_value({"email": "source@example.test", "count": 1}, kind=PayloadKind.STRUCTURED)
    restored = SchemaContract.from_private_descriptor(kind=contract.kind, digest=contract.digest,
                                                      descriptor=contract.private_descriptor)
    assert restored.accepts({"email": "[REDACTED_EMAIL]", "count": 1})
    assert "source@example.test" not in repr(restored)


def test_candidate_has_no_authorization_or_export_capability():
    artifact = CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                         transformed="private candidate", schema=text_schema())
    metadata = artifact.metadata
    rendered = json.dumps({"run_id": metadata.run_id, "artifact_digest": metadata.artifact_digest,
                           "ledger": [entry.entity_type for entry in metadata.ledger]})
    assert "private candidate" not in rendered
    assert not hasattr(artifact, "authorize") and not hasattr(artifact, "export")


def test_direct_artifact_or_metadata_construction_cannot_bypass_integrity():
    with pytest.raises(CandidateError):
        CandidateMetadata(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                          artifact_digest=INPUT, schema_digest=POLICY, payload_kind=PayloadKind.TEXT,
                          media_type="application/json", byte_count=5, ledger=())
    artifact = CandidateArtifact.create(run_id="run-1", input_digest=INPUT, policy_digest=POLICY,
                                         transformed="safe", schema=text_schema())
    with pytest.raises(CandidateError):
        CandidateArtifact(_metadata=artifact.metadata, _encoded=b"other")
