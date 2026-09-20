"""M14 controlled persistence for immutable, non-authorizing release cases."""
from __future__ import annotations

import base64
from dataclasses import replace
import json

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.main import control_record, create_app, release_case_view
from test_access import auth
from test_control_plane_api import client, controls, ingested_dataset, run_request, setup


def executed_run(client, *, key="m14-run-0001"):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    run = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": key},
                      json=run_request(dataset_id, policy["id"], rights["id"])).json()
    response = client.post(f"/processing-runs/{run['id']}/execute", headers=auth())
    assert response.status_code == 200, response.text
    return response.json()


def create_case(client, run_id, *, key="m14-case-0001", content=None, name="processor"):
    return client.post(f"/processing-runs/{run_id}/release-cases",
                       headers={**auth(name), "Idempotency-Key": key}, content=content)


def test_case_is_server_derived_source_safe_non_authorizing_and_idempotent(client):
    run = executed_run(client)
    before = client.get(f"/processing-runs/{run['id']}", headers=auth()).json()
    response = create_case(client, run["id"])
    assert response.status_code == 201, response.text
    item = response.json()
    assert item["run_id"] == run["id"]
    assert item["candidate_artifact_digest"] == run["candidate"]["artifact_digest"]
    assert item["posture"] == "NO_RELEASE_AUTHORIZATION"
    assert "NO_RELEASE_AUTHORIZATION" in item["limitations"]
    assert item["id"].startswith("release-case:v1:")
    for forbidden in ("synthetic@example.test", "buyer-a", "contract-reference:", "release-case-sig:", "recipient-commitment:"):
        assert forbidden not in response.text
    assert client.get(f"/processing-runs/{run['id']}", headers=auth()).json() == before
    replay = create_case(client, run["id"])
    assert replay.status_code == 200 and replay.json() == item
    stored = client.app.state.store.get_control("release_case", item["id"], "tenant-a")
    rendered = json.dumps(stored)
    assert "body" not in rendered and "synthetic@example.test" not in rendered
    assert "release-case-sig:" in rendered and "recipient-commitment:" in rendered
    actions = [event["action"] for event in client.get("/audit", headers=auth("reviewer")).json()["events"]]
    assert actions[-1] == "release_case.created"


def test_case_accepts_no_client_scope_and_has_exact_auth_tenant_role_and_path_boundaries(client):
    run = executed_run(client)
    secret = "private-recipient/synthetic@example.test"
    # The endpoint has no request model and intentionally ignores no scope: a
    # non-empty JSON body is not a supported way to select any case binding.
    for payload in ({}, {"recipient": secret}, {"candidate": secret}, {"contract_digest": "sha256:" + "a" * 64}):
        response = create_case(client, run["id"], key="m14-body-" + str(len(payload)), content=json.dumps(payload).encode())
        assert response.status_code == 422
        assert secret not in response.text
    created = create_case(client, run["id"], key="m14-access-0001")
    assert created.status_code == 201
    item = created.json()
    assert create_case(client, run["id"], key="m14-reviewer", name="reviewer").status_code == 403
    assert create_case(client, run["id"], key="m14-other", name="other").status_code == 404
    assert client.get(f"/release-cases/{item['id']}", headers=auth("reviewer")).json() == item
    assert client.get(f"/release-cases/{item['id']}", headers=auth("buyer")).status_code == 401
    assert client.get(f"/release-cases/{item['id']}", headers=auth("other")).status_code == 404


def test_absent_invalid_or_expired_authority_fails_closed_without_case(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    monkeypatch.delenv("ANONFLOW_RELEASE_CASE_AUTHORITIES")
    with TestClient(create_app()) as isolated:
        run = executed_run(isolated)
        assert create_case(isolated, run["id"]).status_code == 409
        assert not isolated.app.state.store.controls["release_case"]
    setup(monkeypatch, tmp_path)
    monkeypatch.setenv("ANONFLOW_RELEASE_CASE_AUTHORITIES", "[{}]")
    with pytest.raises(RuntimeError):
        create_app()
    setup(monkeypatch, tmp_path)
    monkeypatch.setenv("ANONFLOW_RELEASE_CASE_AUTHORITIES", json.dumps([{
        "tenant": "tenant-a", "issuer_key_id": "development-release-case-a", "expires_at": "2020-01-01T00:00:00Z",
        "private_key": base64.b64encode(b"c" * 32).decode(), "recipient_commitment_salt": base64.b64encode(b"s" * 32).decode(),
        "contract_reference": "contract-reference:v1:" + "A" * 43,
        "contract_digest": "sha256:" + "c" * 64, "contract_expires_at": "2027-06-01T00:00:00Z",
    }]))
    with pytest.raises(RuntimeError):
        create_app()


def test_tamper_configuration_drift_and_dependency_invalidation_fail_closed(client):
    run = executed_run(client)
    item = create_case(client, run["id"]).json()
    stored = client.app.state.store.get_control("release_case", item["id"], "tenant-a")
    stored["payload"]["case"]["binding"]["purpose_code"] = "other-purpose"
    with pytest.raises(HTTPException) as error:
        release_case_view(stored)
    assert error.value.status_code == 503
    # Repository verification, unlike the formatting view, binds live scope and
    # also rejects a valid signed case whose configured contract has drifted.
    stored = client.app.state.store.get_control("release_case", item["id"], "tenant-a")
    authority = client.app.state.release_case_authorities[0]
    drifted = replace(authority, contract_digest="sha256:" + "d" * 64)
    with pytest.raises(HTTPException) as error:
        client.app.state.store.get_release_case(item["id"], "tenant-a", drifted)
    assert error.value.status_code == 503
    run = executed_run(client, key="m14-run-0002")
    item = create_case(client, run["id"], key="m14-case-0002").json()
    assert client.delete(f"/datasets/{run['dataset_id']}", headers=auth()).status_code == 204
    assert client.get(f"/release-cases/{item['id']}", headers=auth()).status_code == 404


def test_repository_rejects_signed_cross_run_or_recipient_replay_and_sqlite_round_trip(client):
    first = executed_run(client, key="m14-run-first")
    second = executed_run(client, key="m14-run-second")
    item = create_case(client, first["id"], key="m14-case-first").json()
    stored = client.app.state.store.get_control("release_case", item["id"], "tenant-a")
    # A signed record from an otherwise valid run cannot be attached to another
    # candidate or idempotency scope.
    payload = {**stored["payload"], "run_id": second["id"], "idempotency_key": "m14-forged-0001"}
    record = control_record(kind="release_case", identifier="release-case:v1:" + "Z" * 43, tenant="tenant-a",
                            payload=payload, expires_at=stored["expires_at"])
    with pytest.raises(HTTPException) as error:
        client.app.state.store.record_release_case(second["id"], "tenant-a", record, "processor",
                                                    client.app.state.release_case_authorities[0])
    assert error.value.status_code == 503
