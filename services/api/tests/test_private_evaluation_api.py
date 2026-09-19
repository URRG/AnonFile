"""M3 integration: private candidate/evidence, never buyer delivery."""
from fastapi.testclient import TestClient
import pytest
from fastapi import HTTPException

from app.main import create_app
from test_access import auth
from test_control_plane_api import client, controls, ingested_dataset, run_request, setup


def register(client):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    response = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m3-private-run-0001"},
                           json=run_request(dataset_id, policy["id"], rights["id"]))
    assert response.status_code == 201, response.text
    return response.json()


def test_execute_persists_private_candidate_and_residual_evidence_without_output(client):
    run = register(client)
    executed = client.post(f"/processing-runs/{run['id']}/execute", headers=auth())
    assert executed.status_code == 200, executed.text
    view = executed.json()
    assert view["state"] == "CANDIDATE" and view["attempts"] == 1
    assert view["candidate"]["artifact_digest"].startswith("sha256:")
    assert "body" not in view["candidate"] and "synthetic@example.test" not in executed.text
    assert client.post(f"/processing-runs/{run['id']}/execute", headers=auth()).status_code == 409
    # A candidate byte endpoint must not exist; reviewers receive only evidence.
    assert client.get(f"/processing-runs/{run['id']}/candidate", headers=auth("reviewer")).status_code == 404
    assert client.post(f"/processing-runs/{run['id']}/residual-evaluations", headers=auth()).status_code == 403
    evidence = client.post(f"/processing-runs/{run['id']}/residual-evaluations", headers=auth("reviewer"))
    assert evidence.status_code == 201, evidence.text
    report = evidence.json()
    assert report["evidence_status"] == "INSUFFICIENT_EVIDENCE"
    assert report["candidate_digest"] == view["candidate"]["artifact_digest"]
    assert "synthetic@example.test" not in evidence.text
    qualification = client.post(f"/processing-runs/{run['id']}/qualifications", headers=auth("reviewer"),
                                json={"evaluation_id": report["id"]})
    assert qualification.status_code == 201, qualification.text
    assert qualification.json()["outcome"] == "INSUFFICIENT_EVIDENCE"
    assert "APPROVED" not in qualification.text and "synthetic@example.test" not in qualification.text
    forged = client.app.state.store.get_control("qualification", qualification.json()["id"], "tenant-a")
    forged["id"] = "forged-qualification"
    forged["size_bytes"] = 0
    forged["payload"]["buyer"] = "buyer-b"
    with pytest.raises(HTTPException) as error:
        client.app.state.store.record_qualification(run["id"], "tenant-a", forged, report["id"], "reviewer")
    assert error.value.status_code == 503
    audit = client.get("/audit", headers=auth("reviewer")).json()
    assert "synthetic@example.test" not in str(audit)
    assert {"private_candidate.created", "evaluation_report.created"} <= {event["action"] for event in audit["events"]}


def test_sqlite_candidate_body_is_encrypted_and_never_available_after_dependency_deletion(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path, "sqlite")
    with TestClient(create_app()) as client:
        run = register(client)
        assert client.post(f"/processing-runs/{run['id']}/execute", headers=auth()).status_code == 200
        assert client.delete(f"/datasets/{run['dataset_id']}", headers=auth()).status_code == 204
        assert client.get(f"/processing-runs/{run['id']}", headers=auth()).status_code == 404
        assert client.post(f"/processing-runs/{run['id']}/residual-evaluations", headers=auth("reviewer")).status_code == 404
    raw = (tmp_path / "controls.db").read_bytes()
    assert b"synthetic@example.test" not in raw and b"REDACTED_EMAIL" not in raw


def test_candidate_storage_capacity_failure_becomes_terminal_not_stuck_running(client):
    run = register(client)
    # policy, rights and run already occupy the three permitted control slots.
    client.app.state.store.MAX_CONTROLS = 3
    response = client.post(f"/processing-runs/{run['id']}/execute", headers=auth())
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "FAILED"
    assert response.json()["events"][-1]["error_code"] == "STORAGE_FAILURE"


def test_store_rejects_private_body_that_does_not_match_artifact_metadata(client):
    run = register(client)
    store = client.app.state.store
    claimed, dataset = store.claim_processing_run(run["id"], "tenant-a", "processor")
    bad = {"id": "candidate-mismatch", "kind": "private_candidate", "tenant": "tenant-a",
           "created_at": "2030-01-01T00:00:00Z", "expires_at": dataset["expires_at"], "size_bytes": 0,
           "payload": {"run_id": run["id"], "input_digest": claimed["payload"]["source_digest"],
                       "policy_digest": claimed["payload"]["policy_digest"], "artifact_digest": "sha256:" + "0" * 64,
                       "schema_digest": "sha256:" + "1" * 64, "evaluation_schema_digest": None,
                       "payload_kind": "text", "media_type": "text/plain", "byte_count": 4,
                       "ledger": [], "body": "safe"}}
    with pytest.raises(HTTPException) as error:
        store.complete_processing_run(run["id"], "tenant-a", bad, "processor")
    assert error.value.status_code == 503
