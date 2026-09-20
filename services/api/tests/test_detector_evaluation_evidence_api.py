"""M9 aggregate detector-evaluation evidence API integration tests."""
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from app.benchmark_evidence import CategoryMetrics
from app.evaluation_harness import EvaluationHarnessError, ScoredEvaluation, ScoringBinding
from app.main import detector_evaluation_evidence_view
from app.processing import RULES_METHOD_CONFIG_DIGEST, RULES_METHOD_VERSION, rules_method_config_digest
from app.rules_policy_execution import RULES_TAXONOMY_MAPPING_DIGEST, rules_taxonomy_mapping_digest
from test_access import auth
from test_control_plane_api import client, controls, ingested_dataset, run_request


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


def report(*, false_negatives: int = 0, detector_id: str = "rules-v1",
           detector_version: str = RULES_METHOD_VERSION,
           detector_config_digest: str = RULES_METHOD_CONFIG_DIGEST,
           taxonomy_mapping_digest: str = RULES_TAXONOMY_MAPPING_DIGEST,
           corpus_digest: str = digest("d")) -> dict:
    result = ScoredEvaluation(
        binding=ScoringBinding(
            evaluator_id="m8-harness", evaluator_version="v1", evaluator_config_digest=digest("a"),
            detector_id=detector_id, detector_version=detector_version, detector_config_digest=detector_config_digest,
            taxonomy_mapping_digest=taxonomy_mapping_digest, corpus_digest=corpus_digest, prediction_set_digest=digest("e"),
        ),
        metrics=(CategoryMetrics("PII", 3, 1, false_negatives),),
        evaluated_at=datetime(2030, 1, 1, tzinfo=UTC),
    )
    return result.to_record()


def registered_run(client):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    response = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m9-run-0001"},
                           json=run_request(dataset_id, policy["id"], rights["id"]))
    assert response.status_code == 201, response.text
    return response.json()


def submit(client, run_id, payload=None, key="m9-evidence-0001", name="evaluator", signature=None):
    report_payload = report() if payload is None else payload
    run = client.get(f"/processing-runs/{run_id}", headers=auth("processor")).json()
    if signature is None:
        try:
            report_model = ScoredEvaluation.from_record(report_payload)
            authority = client.app.state.evaluator_authorities[0]
            signature = authority.sign_for_test_or_worker(run_id=run_id,
                                                           processing_request_digest=run["request_digest"],
                                                           report=report_model)
        except EvaluationHarnessError:
            signature = "evalsig:v1:" + "A" * 43
    return client.post(f"/processing-runs/{run_id}/detector-evaluation-evidence",
                       headers={**auth(name), "Idempotency-Key": key},
                       json={"report": report_payload, "attestation_signature": signature})


def test_persists_only_verified_aggregate_method_evidence_without_lifecycle_authority(client):
    run = registered_run(client)
    response = submit(client, run["id"])
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["run_id"] == run["id"]
    assert item["processing_request_digest"] == run["request_digest"]
    assert item["posture"] == "OBSERVATIONAL_ONLY"
    assert "NO_RELEASE_AUTHORIZATION" in item["limitations"]
    assert item["report"]["digest"] == item["report_digest"]
    assert item["report"]["binding"]["detector_id"] == "rules-v1"
    assert item["report"]["binding"]["detector_config_digest"] == run["method_config_digest"]
    assert item["report"]["binding"]["taxonomy_mapping_digest"] == run["taxonomy_mapping_digest"]
    assert "case_id" not in response.text and "reference_digest" not in response.text
    assert "evalsig:" not in response.text
    # Benchmark scores cannot progress, qualify, or otherwise modify a run.
    assert client.get(f"/processing-runs/{run['id']}", headers=auth()).json() == run
    actions = [event["action"] for event in client.get("/audit", headers=auth("reviewer")).json()["events"]]
    assert actions[-1] == "detector_evaluation_evidence.created"
    stored = client.app.state.store.get_control("detector_evaluation_evidence", item["id"], "tenant-a")["payload"]
    assert set(stored) == {"run_id", "processing_request_digest", "policy_digest", "rights_digest",
                           "method_id", "method_version", "method_config_digest", "taxonomy_mapping_digest",
                           "idempotency_key", "evaluator_subject", "evaluator_authority_id",
                           "attestation_signature", "report"}
    assert "candidate_digest" not in str(stored)


def test_replay_is_idempotent_but_different_evidence_conflicts(client):
    run = registered_run(client)
    created = submit(client, run["id"])
    replay = submit(client, run["id"])
    assert created.status_code == 201 and replay.status_code == 200
    assert replay.json() == created.json()
    conflict = submit(client, run["id"], report(false_negatives=1))
    assert conflict.status_code == 409
    assert len(client.app.state.store.list_controls("detector_evaluation_evidence", "tenant-a")) == 1


def test_role_tenant_and_path_boundaries(client):
    run = registered_run(client)
    assert submit(client, run["id"], name="processor").status_code == 403
    assert submit(client, run["id"], name="reviewer").status_code == 403
    assert submit(client, run["id"], name="buyer").status_code == 401
    item = submit(client, run["id"]).json()
    endpoint = f"/processing-runs/{run['id']}/detector-evaluation-evidence/{item['id']}"
    assert client.get(endpoint, headers=auth("reviewer")).json() == item
    assert client.get(endpoint, headers=auth("buyer")).status_code == 401
    assert client.get(endpoint, headers=auth("other")).status_code == 404
    assert submit(client, run["id"], name="evaluator-other", key="m9-cross-tenant").status_code == 404
    assert client.get(f"/processing-runs/not-the-run/detector-evaluation-evidence/{item['id']}",
                      headers=auth("reviewer")).status_code == 404


def test_invalid_or_mismatched_report_is_rejected_without_retaining_sensitive_input(client):
    run = registered_run(client)
    secret = "private-corpus-path/customer@example.test"
    malformed = report()
    malformed["source_path"] = secret
    response = submit(client, run["id"], malformed)
    assert response.status_code == 422
    assert secret not in response.text
    assert not client.app.state.store.controls["detector_evaluation_evidence"]
    for mismatched in (
        report(detector_id="independent-detector"),
        report(detector_version="rules-processor-v999"),
        report(detector_config_digest=digest("f")),
        report(taxonomy_mapping_digest=digest("f")),
    ):
        mismatch = submit(client, run["id"], mismatched, key="m9-evidence-" + str(len(mismatched)))
        assert mismatch.status_code == 409
    assert not client.app.state.store.controls["detector_evaluation_evidence"]


def test_tampered_persisted_report_or_method_identity_is_not_rendered(client):
    run = registered_run(client)
    item = submit(client, run["id"]).json()
    stored = client.app.state.store.get_control("detector_evaluation_evidence", item["id"], "tenant-a")
    stored["payload"]["report"]["metrics"][0]["true_positives"] = 999
    with pytest.raises(HTTPException) as error:
        detector_evaluation_evidence_view(stored, evaluator_authorities=client.app.state.evaluator_authorities)
    assert error.value.status_code == 503
    stored = client.app.state.store.get_control("detector_evaluation_evidence", item["id"], "tenant-a")
    stored["payload"]["attestation_signature"] = "evalsig:v1:" + "A" * 43
    with pytest.raises(HTTPException) as error:
        detector_evaluation_evidence_view(stored, evaluator_authorities=client.app.state.evaluator_authorities)
    assert error.value.status_code == 503
    stored = client.app.state.store.get_control("detector_evaluation_evidence", item["id"], "tenant-a")
    stored["payload"]["method_config_digest"] = digest("f")
    with pytest.raises(HTTPException) as error:
        detector_evaluation_evidence_view(stored, evaluator_authorities=client.app.state.evaluator_authorities)
    assert error.value.status_code == 503


def test_method_and_taxonomy_identity_digests_change_when_processing_semantics_drift():
    assert rules_method_config_digest(algorithm_revision="rules-processing-algorithm-v999") != RULES_METHOD_CONFIG_DIGEST
    assert rules_taxonomy_mapping_digest({"EMAIL": "PAYMENT"}) != RULES_TAXONOMY_MAPPING_DIGEST


def test_only_distinct_allowlisted_evaluator_can_attest_a_report(client):
    run = registered_run(client)
    # A regular processor cannot submit at all, while a dual-role processing
    # subject is rejected even before a signature can make it appear trusted.
    assert submit(client, run["id"], name="processor").status_code == 403
    dual_run = client.post("/processing-runs", headers={**auth("dual"), "Idempotency-Key": "m9-dual-run-0001"},
                           json=run_request(ingested_dataset(client), *[item["id"] for item in controls(client)])).json()
    assert submit(client, dual_run["id"], name="dual").status_code == 403
    # A correct evaluator role without a valid signature cannot fabricate a
    # self-consistent report/corpus/provenance declaration.
    assert submit(client, run["id"], signature="evalsig:v1:" + "A" * 43).status_code == 409
    assert not client.app.state.store.list_controls("detector_evaluation_evidence", "tenant-a")


def test_signature_tenant_and_allowlisted_corpus_bindings_fail_closed(client):
    run = registered_run(client)
    # Altering a signed report makes the signature invalid even though its own
    # report digest remains internally valid.
    original = report()
    authority = client.app.state.evaluator_authorities[0]
    signature = authority.sign_for_test_or_worker(run_id=run["id"], processing_request_digest=run["request_digest"],
                                                   report=ScoredEvaluation.from_record(original))
    assert submit(client, run["id"], report(false_negatives=1), key="m9-signature-drift", signature=signature).status_code == 409
    # A self-consistent score against a corpus outside the authority allowlist
    # still cannot obtain a matching authority.
    assert submit(client, run["id"], report(corpus_digest=digest("f")), key="m9-corpus-drift").status_code == 409


def test_dependency_invalidation_removes_method_evidence_with_its_run(client):
    run = registered_run(client)
    item = submit(client, run["id"]).json()
    assert client.delete(f"/datasets/{run['dataset_id']}", headers=auth()).status_code == 204
    response = client.get(f"/processing-runs/{run['id']}/detector-evaluation-evidence/{item['id']}", headers=auth())
    assert response.status_code == 404
