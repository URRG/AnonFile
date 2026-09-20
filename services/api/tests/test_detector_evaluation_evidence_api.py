"""M9 aggregate detector-evaluation evidence API integration tests."""
from datetime import UTC, datetime

import pytest
from fastapi import HTTPException
from app.benchmark_evidence import CategoryMetrics
from app.evaluation_harness import ScoredEvaluation, ScoringBinding
from app.main import detector_evaluation_evidence_view
from test_access import auth
from test_control_plane_api import client, controls, ingested_dataset, run_request


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


def report(*, false_negatives: int = 0, detector_id: str = "rules-v1") -> dict:
    result = ScoredEvaluation(
        binding=ScoringBinding(
            evaluator_id="m8-harness", evaluator_version="v1", evaluator_config_digest=digest("a"),
            detector_id=detector_id, detector_version="v1", detector_config_digest=digest("b"),
            taxonomy_mapping_digest=digest("c"), corpus_digest=digest("d"), prediction_set_digest=digest("e"),
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


def submit(client, run_id, payload=None, key="m9-evidence-0001", name="processor"):
    return client.post(f"/processing-runs/{run_id}/detector-evaluation-evidence",
                       headers={**auth(name), "Idempotency-Key": key}, json={"report": report() if payload is None else payload})


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
    assert "case_id" not in response.text and "reference_digest" not in response.text
    # Benchmark scores cannot progress, qualify, or otherwise modify a run.
    assert client.get(f"/processing-runs/{run['id']}", headers=auth()).json() == run
    actions = [event["action"] for event in client.get("/audit", headers=auth("reviewer")).json()["events"]]
    assert actions[-1] == "detector_evaluation_evidence.created"
    stored = client.app.state.store.get_control("detector_evaluation_evidence", item["id"], "tenant-a")["payload"]
    assert set(stored) == {"run_id", "processing_request_digest", "policy_digest", "rights_digest",
                           "method_id", "idempotency_key", "report"}
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
    assert submit(client, run["id"], name="reviewer").status_code == 403
    # This fixture deliberately does not configure a buyer principal; an
    # unconfigured bearer token is denied before resource lookup.
    assert submit(client, run["id"], name="buyer").status_code == 401
    item = submit(client, run["id"]).json()
    endpoint = f"/processing-runs/{run['id']}/detector-evaluation-evidence/{item['id']}"
    assert client.get(endpoint, headers=auth("reviewer")).json() == item
    assert client.get(endpoint, headers=auth("buyer")).status_code == 401
    assert client.get(endpoint, headers=auth("other")).status_code == 404
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
    mismatch = submit(client, run["id"], report(detector_id="independent-detector"), key="m9-evidence-0002")
    assert mismatch.status_code == 409
    assert not client.app.state.store.controls["detector_evaluation_evidence"]


def test_tampered_persisted_report_is_not_rendered(client):
    run = registered_run(client)
    item = submit(client, run["id"]).json()
    stored = client.app.state.store.get_control("detector_evaluation_evidence", item["id"], "tenant-a")
    stored["payload"]["report"]["metrics"][0]["true_positives"] = 999
    with pytest.raises(HTTPException) as error:
        detector_evaluation_evidence_view(stored)
    assert error.value.status_code == 503


def test_dependency_invalidation_removes_method_evidence_with_its_run(client):
    run = registered_run(client)
    item = submit(client, run["id"]).json()
    assert client.delete(f"/datasets/{run['dataset_id']}", headers=auth()).status_code == 204
    response = client.get(f"/processing-runs/{run['id']}/detector-evaluation-evidence/{item['id']}", headers=auth())
    assert response.status_code == 404
