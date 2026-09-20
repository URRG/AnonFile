"""M11 server-owned disclosure-risk evidence control path."""
from __future__ import annotations
import json
import pytest
from fastapi import HTTPException
from app.main import disclosure_risk_evidence_view
from test_access import auth
from test_control_plane_api import client, controls, ingested_dataset, run_request

def run(client):
    dataset = ingested_dataset(client); policy, rights = controls(client)
    item = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m11-run-0001"},
        json=run_request(dataset, policy["id"], rights["id"])).json()
    executed = client.post(f"/processing-runs/{item['id']}/execute", headers=auth())
    assert executed.status_code == 200
    return executed.json()

def submit(client, run_id, *, key="m11-risk-0001", content=None, who="processor"):
    return client.post(f"/processing-runs/{run_id}/disclosure-risk-evidence",
        headers={**auth(who), "Idempotency-Key": key}, content=content)

def test_server_owned_qids_sign_and_retain_only_aggregate_risk_without_lifecycle_authority(client):
    item = run(client); before = client.get(f"/processing-runs/{item['id']}", headers=auth()).json()
    response = submit(client, item["id"]); assert response.status_code == 201, response.text
    view = response.json(); assert view["posture"] == "OBSERVATIONAL_ONLY"
    assert view["candidate_artifact_digest"] == item["candidate"]["artifact_digest"]
    assert view["report"]["status"] == "ASSESSED" and "NO_RELEASE_AUTHORIZATION" in view["limitations"]
    for forbidden in ("synthetic@example.test", "contact", "code", "development-risk-a", "risksig:"):
        assert forbidden not in response.text
    assert client.get(f"/processing-runs/{item['id']}", headers=auth()).json() == before
    stored = client.app.state.store.get_control("disclosure_risk_evidence", view["id"], "tenant-a")
    assert "body" not in json.dumps(stored) and "quasi_identifier_fields" not in json.dumps(stored)
    assert "risksig:" in json.dumps(stored)
    assert submit(client, item["id"]).status_code == 200

def test_no_client_data_qids_commitments_or_keys_and_role_tenant_boundaries(client):
    item = run(client); secret = "customer@example.test"
    for value in ({}, {"qid_fields": ["code"]}, {"candidate": secret}, {"commitment": "qidcfg:v1:" + "A" * 43}, {"key": "x" * 32}):
        response = submit(client, item["id"], content=json.dumps(value).encode()); assert response.status_code == 422
        assert secret not in response.text
    assert submit(client, item["id"], who="reviewer", key="m11-review").status_code == 403
    assert submit(client, item["id"], who="other", key="m11-other").status_code == 404
    view = submit(client, item["id"], key="m11-view").json()
    endpoint = f"/processing-runs/{item['id']}/disclosure-risk-evidence/{view['id']}"
    assert client.get(endpoint, headers=auth("reviewer")).json() == view
    assert client.get(endpoint, headers=auth("other")).status_code == 404

def test_tampered_report_signature_or_authority_cannot_render_or_be_admitted(client):
    item = run(client); view = submit(client, item["id"]).json()
    stored = client.app.state.store.get_control("disclosure_risk_evidence", view["id"], "tenant-a")
    stored["payload"]["report"]["record_count"] = 99
    with pytest.raises(HTTPException) as error:
        disclosure_risk_evidence_view(stored, disclosure_risk_authorities=client.app.state.disclosure_risk_authorities)
    assert error.value.status_code == 503
    stored = client.app.state.store.get_control("disclosure_risk_evidence", view["id"], "tenant-a")
    stored["payload"]["attestation_signature"] = "risksig:v1:" + "A" * 43
    with pytest.raises(HTTPException):
        disclosure_risk_evidence_view(stored, disclosure_risk_authorities=client.app.state.disclosure_risk_authorities)
    assert client.delete(f"/datasets/{item['dataset_id']}", headers=auth()).status_code == 204
    assert client.get(f"/processing-runs/{item['id']}/disclosure-risk-evidence/{view['id']}", headers=auth()).status_code == 404
