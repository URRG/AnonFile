"""M3 integration: private candidate/evidence, never buyer delivery."""
from fastapi.testclient import TestClient
import pytest
from fastapi import HTTPException

from app.main import _residual_detector, create_app, run_view
from test_access import auth
from test_control_plane_api import client, controls, ingested_dataset, run_request, setup


def register(client):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    response = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m3-private-run-0001"},
                           json=run_request(dataset_id, policy["id"], rights["id"]))
    assert response.status_code == 201, response.text
    return response.json()


def test_rules_limited_coverage_quarantines_private_candidate_without_output(client):
    run = register(client)
    executed = client.post(f"/processing-runs/{run['id']}/execute", headers=auth())
    assert executed.status_code == 200, executed.text
    view = executed.json()
    assert view["state"] == "QUARANTINED" and view["attempts"] == 1
    assert view["events"][-1]["error_code"] == "POLICY_UNCOVERED"
    assert view["candidate"]["artifact_digest"].startswith("sha256:")
    assert "body" not in view["candidate"] and "synthetic@example.test" not in executed.text
    assert client.post(f"/processing-runs/{run['id']}/execute", headers=auth()).status_code == 409
    # A candidate byte endpoint must not exist; reviewers receive only evidence.
    assert client.get(f"/processing-runs/{run['id']}/candidate", headers=auth("reviewer")).status_code == 404
    assert client.post(f"/processing-runs/{run['id']}/residual-evaluations", headers=auth()).status_code == 403
    assert client.post(f"/processing-runs/{run['id']}/residual-evaluations", headers=auth("reviewer")).status_code == 409
    audit = client.get("/audit", headers=auth("reviewer")).json()
    assert "synthetic@example.test" not in str(audit)
    assert "private_candidate.created" in {event["action"] for event in audit["events"]}


def test_policy_block_quarantines_private_candidate_without_exposing_it(client):
    dataset = client.post("/ingestions", headers=auth(), json={
        "name": "synthetic-credential", "format": "csv", "content": "password\nsynthetic-secret\n",
    })
    assert dataset.status_code == 201
    policy, rights = controls(client)
    run = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m5-blocked-run-0001"},
                      json=run_request(dataset.json()["id"], policy["id"], rights["id"])).json()
    response = client.post(f"/processing-runs/{run['id']}/execute", headers=auth())
    assert response.status_code == 200, response.text
    view = response.json()
    assert view["state"] == "QUARANTINED"
    assert view["events"][-1]["error_code"] == "POLICY_BLOCKED"
    assert view["candidate"]["ledger"] == [{"entity_type": "CREDENTIAL", "action": "REDACT",
                                              "reason": "POLICY_RULE", "count": 1}]
    assert "synthetic-secret" not in response.text
    assert client.post(f"/processing-runs/{run['id']}/residual-evaluations", headers=auth("reviewer")).status_code == 409


def test_residual_detector_uses_the_same_taxonomy_mapping_as_processing():
    result = _residual_detector("ABCPD1234E")
    assert dict(result.residual_counts) == {"PII": 1, "PAYMENT": 0, "CREDENTIAL": 0}
    assert result.assessed_categories == frozenset({"PII", "PAYMENT", "CREDENTIAL"})


def test_processor_can_terminally_recover_a_lease_expired_run(client):
    run = register(client)
    store = client.app.state.store
    store.claim_processing_run(run["id"], "tenant-a", "processor")
    store.RUN_LEASE_SECONDS = 0
    response = client.post(f"/processing-runs/{run['id']}/recover", headers=auth())
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "FAILED"
    assert response.json()["events"][-1]["error_code"] == "LEASE_EXPIRED"


def test_legacy_run_view_is_explicitly_unavailable_for_execution(client):
    run = register(client)
    record = client.app.state.store.get_control("processing_run", run["id"], "tenant-a")
    del record["payload"]["method_id"]
    del record["payload"]["language"]
    view = run_view(record)
    assert view.method_id == "legacy-unavailable" and view.language == "und"


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
