"""M10 trusted-worker utility-evidence API integration tests."""
from __future__ import annotations

import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import create_app, utility_evidence_view
from test_access import auth
from test_control_plane_api import client, controls, ingested_dataset, run_request, setup


def executed_run(client, *, key="m10-run-0001"):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    run = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": key},
                      json=run_request(dataset_id, policy["id"], rights["id"])).json()
    response = client.post(f"/processing-runs/{run['id']}/execute", headers=auth())
    assert response.status_code == 200, response.text
    return response.json()


def assess(client, run_id, *, key="m10-utility-0001", content=None, name="processor"):
    return client.post(f"/processing-runs/{run_id}/utility-evidence",
                       headers={**auth(name), "Idempotency-Key": key}, content=content)


def test_trusted_worker_retains_only_source_safe_aggregate_evidence_without_lifecycle_authority(client):
    run = executed_run(client, key="m10-run-0002")
    before = client.get(f"/processing-runs/{run['id']}", headers=auth()).json()
    response = assess(client, run["id"])
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["run_id"] == run["id"]
    assert item["processing_request_digest"] == run["request_digest"]
    assert item["candidate_artifact_digest"] == run["candidate"]["artifact_digest"]
    assert item["posture"] == "OBSERVATIONAL_ONLY"
    assert "NO_RELEASE_AUTHORIZATION" in item["limitations"]
    assert item["report"]["status"] == "ASSESSED"
    assert item["report"]["digest"] == item["report_digest"]
    assert item["report"]["candidate_artifact_digest"] == run["candidate"]["artifact_digest"]
    assert item["report"]["source_commitment"].startswith("utilsrc:v1:")
    rendered = response.text
    for forbidden in ("synthetic@example.test", "contact", "code", "development-utility-a", "u" * 32):
        assert forbidden not in rendered
    # Utility evidence is observational. It cannot make a quarantined M5 run
    # candidate-ready, qualified, releasable, or deliverable.
    assert client.get(f"/processing-runs/{run['id']}", headers=auth()).json() == before
    actions = [event["action"] for event in client.get("/audit", headers=auth("reviewer")).json()["events"]]
    assert actions[-1] == "utility_evidence.created"
    stored = client.app.state.store.get_control("utility_evidence", item["id"], "tenant-a")
    assert set(stored["payload"]) == {
        "run_id", "processing_request_digest", "candidate_artifact_digest", "policy_digest", "rights_digest",
        "method_id", "method_version", "method_config_digest", "taxonomy_mapping_digest", "idempotency_key",
        "utility_authority_id", "report",
    }
    assert "body" not in json.dumps(stored) and "source_digest" not in json.dumps(stored)
    assert stored["expires_at"] <= client.app.state.store.get_control("processing_run", run["id"], "tenant-a")["expires_at"]


def test_endpoint_rejects_all_client_supplied_source_candidate_commitment_or_key_material(client):
    run = executed_run(client)
    secret = "private-source/customer@example.test"
    for payload in ({}, {"source": secret}, {"candidate": secret}, {"source_commitment": "utilsrc:v1:" + "A" * 43},
                    {"key": "u" * 32}, {"report": {"input_byte_count": 1}}):
        response = assess(client, run["id"], content=json.dumps(payload).encode())
        assert response.status_code == 422
        assert secret not in response.text
    assert not client.app.state.store.controls["utility_evidence"]


def test_idempotency_roles_tenant_and_path_boundaries(client):
    run = executed_run(client)
    created = assess(client, run["id"])
    replay = assess(client, run["id"])
    assert created.status_code == 201 and replay.status_code == 200
    assert replay.json() == created.json()
    item = created.json()
    assert assess(client, run["id"], name="reviewer", key="m10-reviewer").status_code == 403
    assert assess(client, run["id"], name="evaluator", key="m10-evaluator").status_code == 403
    assert assess(client, run["id"], name="other", key="m10-other").status_code == 404
    endpoint = f"/processing-runs/{run['id']}/utility-evidence/{item['id']}"
    assert client.get(endpoint, headers=auth("reviewer")).json() == item
    assert client.get(endpoint, headers=auth("buyer")).status_code == 401
    assert client.get(endpoint, headers=auth("other")).status_code == 404
    assert client.get(f"/processing-runs/not-the-run/utility-evidence/{item['id']}",
                      headers=auth("reviewer")).status_code == 404


def test_absent_or_invalid_server_authority_fails_closed_without_report(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    monkeypatch.delenv("ANONFLOW_UTILITY_EVIDENCE_AUTHORITIES")
    with TestClient(create_app()) as isolated:
        run = executed_run(isolated)
        response = assess(isolated, run["id"])
        assert response.status_code == 409
        assert not isolated.app.state.store.controls["utility_evidence"]
    setup(monkeypatch, tmp_path)
    monkeypatch.setenv("ANONFLOW_UTILITY_EVIDENCE_AUTHORITIES", "[{]")
    with pytest.raises(RuntimeError):
        create_app()


def test_tampering_or_dependency_invalidation_makes_retained_evidence_unavailable(client):
    run = executed_run(client)
    item = assess(client, run["id"]).json()
    stored = client.app.state.store.get_control("utility_evidence", item["id"], "tenant-a")
    stored["payload"]["report"]["input_byte_count"] = 999
    with pytest.raises(HTTPException) as error:
        utility_evidence_view(stored)
    assert error.value.status_code == 503
    # Restore the test fixture through a fresh run, then prove parent deletion
    # tombstones its aggregate evidence with the run and private candidate.
    run = executed_run(client, key="m10-run-0003")
    item = assess(client, run["id"], key="m10-utility-0002").json()
    assert client.delete(f"/datasets/{run['dataset_id']}", headers=auth()).status_code == 204
    assert client.get(f"/processing-runs/{run['id']}/utility-evidence/{item['id']}", headers=auth()).status_code == 404
