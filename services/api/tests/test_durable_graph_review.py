import base64
import hashlib
import json
import os

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.durable_graph_review import DurableGraphReviewAdapter
from app.durable_repository import DurableStore
from app.main import create_app
from app.revisioned_graph_review import GraphClaimSnapshot, GraphNodeSnapshot, GraphReviewConflict, GraphSnapshot
from test_access import TOKENS, auth
from test_control_plane_api import setup


def ref(kind, value):
    return f"{kind}:v1:" + base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip("=")


def snapshot(tenant):
    person, org, claim = ref("graphnode", "person"), ref("graphnode", "org"), ref("graphclaim", "claim")
    return GraphSnapshot(tenant, ref("graphsnap", "snapshot"),
        (GraphNodeSnapshot(person, "person"), GraphNodeSnapshot(org, "organization")),
        (GraphClaimSnapshot(claim, "works_at", person, org, ref("graphevidence", "proof")),))


def adapter(tmp_path):
    return DurableGraphReviewAdapter(DurableStore(str(tmp_path / "reviews.db"), b"x" * 32))


def test_durable_adapter_persists_source_free_cas_state(tmp_path):
    tenant = ref("tenantref", "a"); item = snapshot(tenant); service = adapter(tmp_path)
    service.create_snapshot(item)
    before = service._store.get_control("graph_review", item.snapshot_ref, tenant)
    result = service.decide(tenant_ref=tenant, snapshot_ref=item.snapshot_ref, claim_ref=item.claims[0].identifier,
        expected_revision=0, decision="ACCEPT", reviewer_ref=ref("reviewerref", "r"))
    assert result["revision"] == 1 and "graphevidence" not in str(result)
    after = service._store.get_control("graph_review", item.snapshot_ref, tenant)
    assert after["expires_at"] == before["expires_at"]
    assert adapter(tmp_path).read(tenant_ref=tenant, snapshot_ref=item.snapshot_ref)["revision"] == 1
    with pytest.raises(GraphReviewConflict):
        service.decide(tenant_ref=tenant, snapshot_ref=item.snapshot_ref, claim_ref=item.claims[0].identifier,
            expected_revision=0, decision="REJECT", reviewer_ref=ref("reviewerref", "r"))


def test_expired_review_cannot_be_revived_by_decision(tmp_path, monkeypatch):
    tenant = ref("tenantref", "a"); item = snapshot(tenant); service = adapter(tmp_path)
    service.create_snapshot(item)
    expiry = service._store.get_control("graph_review", item.snapshot_ref, tenant)["expires_at"]
    monkeypatch.setattr("app.durable_graph_review.time.time", lambda: expiry + 1)
    with pytest.raises(HTTPException) as error:
        service.decide(tenant_ref=tenant, snapshot_ref=item.snapshot_ref, claim_ref=item.claims[0].identifier,
            expected_revision=0, decision="ACCEPT", reviewer_ref=ref("reviewerref", "r"))
    assert error.value.status_code == 404


def test_tenant_isolation_is_indistinguishable_from_missing(tmp_path):
    tenant = ref("tenantref", "a"); service = adapter(tmp_path); item = snapshot(tenant); service.create_snapshot(item)
    with pytest.raises(Exception):
        service.read(tenant_ref=ref("tenantref", "b"), snapshot_ref=item.snapshot_ref)


def test_routes_require_durable_store_reviewer_and_tenant_bound_revision(tmp_path, monkeypatch):
    setup(monkeypatch, tmp_path, "memory")
    with TestClient(create_app()) as memory_client:
        assert memory_client.get("/graph-reviews/unknown", headers=auth("reviewer")).status_code == 404

    setup(monkeypatch, tmp_path, "sqlite")
    principals = json.loads(os.environ["ANONFLOW_DEV_PRINCIPALS"])
    principals.append({"token": "other-reviewer".ljust(40, "-"), "subject": "other-reviewer",
                       "tenant": "tenant-b", "roles": ["reviewer"]})
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", json.dumps(principals))
    app = create_app()
    item = snapshot(ref("tenantref", "tenant-a"))
    app.state.graph_reviews.create_snapshot(item)
    path = f"/graph-reviews/{item.snapshot_ref}"
    with TestClient(app) as client:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=auth("processor")).status_code == 403
        assert client.get(path, headers={"Authorization": "Bearer " + "other-reviewer".ljust(40, "-")}).status_code == 404
        assert client.get(path, headers=auth("reviewer")).json()["revision"] == 0
        body = {"claim_ref": item.claims[0].identifier, "expected_revision": 0, "decision": "ACCEPT"}
        assert client.post(path + "/decisions", headers=auth("reviewer"),
                           json={**body, "claim_ref": ref("graphclaim", "missing")}).status_code == 404
        assert client.post(path + "/decisions", headers=auth("reviewer"), json=body).json()["revision"] == 1
        assert client.post(path + "/decisions", headers=auth("reviewer"), json=body).status_code == 409
