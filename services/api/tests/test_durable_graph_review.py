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
from app.revisioned_graph_review import (GraphClaimSnapshot, GraphIdentityMerge, GraphIdentitySplit,
    GraphNodeSnapshot, GraphReviewConflict, GraphSnapshot, GraphSplitEndpointAssignment)
from test_access import TOKENS, auth
from test_control_plane_api import setup


def ref(kind, value):
    return f"{kind}:v1:" + base64.urlsafe_b64encode(hashlib.sha256(value.encode()).digest()).decode().rstrip("=")


def snapshot(tenant):
    person, org, claim = ref("graphnode", "person"), ref("graphnode", "org"), ref("graphclaim", "claim")
    return GraphSnapshot(tenant, ref("graphsnap", "snapshot"),
        (GraphNodeSnapshot(person, "person"), GraphNodeSnapshot(org, "organization")),
        (GraphClaimSnapshot(claim, "works_at", person, org, ref("graphevidence", "proof")),))


def identity_snapshot(tenant):
    first, second, third = (ref("graphnode", value) for value in ("first", "second", "third"))
    org, project = ref("graphnode", "org"), ref("graphnode", "project")
    claims = (
        GraphClaimSnapshot(ref("graphclaim", "first-org"), "works_at", first, org, ref("graphevidence", "one")),
        GraphClaimSnapshot(ref("graphclaim", "second-org"), "works_at", second, org, ref("graphevidence", "two")),
        GraphClaimSnapshot(ref("graphclaim", "first-project"), "works_on", first, project, ref("graphevidence", "three")),
    )
    return GraphSnapshot(tenant, ref("graphsnap", "identity-snapshot"),
        (GraphNodeSnapshot(first, "person"), GraphNodeSnapshot(second, "person"), GraphNodeSnapshot(third, "person"),
         GraphNodeSnapshot(org, "organization"), GraphNodeSnapshot(project, "project")), claims)


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


def test_durable_merge_replays_after_restart_without_evidence(tmp_path):
    tenant = ref("tenantref", "a"); item = identity_snapshot(tenant); service = adapter(tmp_path)
    service.create_snapshot(item)
    first, second = item.nodes[0].identifier, item.nodes[1].identifier
    result = service.merge_identities(tenant_ref=tenant, snapshot_ref=item.snapshot_ref,
        merge=GraphIdentityMerge(first, (first, second)), expected_revision=0, reviewer_ref=ref("reviewerref", "r"))
    assert result["revision"] == 1 and result["identity_actions"][0]["action"] == "MERGE"
    assert "graphevidence" not in str(result)
    restarted = adapter(tmp_path).read(tenant_ref=tenant, snapshot_ref=item.snapshot_ref)
    assert restarted["revision"] == 1 and restarted["identity_actions"] == result["identity_actions"]


def test_durable_split_is_atomic_and_replays_after_restart(tmp_path):
    tenant = ref("tenantref", "a"); item = identity_snapshot(tenant); service = adapter(tmp_path)
    service.create_snapshot(item)
    first, second, third = (node.identifier for node in item.nodes[:3])
    assignments = (GraphSplitEndpointAssignment(item.claims[0].identifier, "source", second),
                   GraphSplitEndpointAssignment(item.claims[2].identifier, "source", third))
    result = service.split_identity(tenant_ref=tenant, snapshot_ref=item.snapshot_ref,
        split=GraphIdentitySplit(first, (second, third), assignments), expected_revision=0, reviewer_ref=ref("reviewerref", "r"))
    assert result["revision"] == 1 and result["identity_actions"][0]["action"] == "SPLIT"
    with pytest.raises(GraphReviewConflict):
        service.split_identity(tenant_ref=tenant, snapshot_ref=item.snapshot_ref,
            split=GraphIdentitySplit(first, (second, third), assignments), expected_revision=0, reviewer_ref=ref("reviewerref", "r"))
    replayed = adapter(tmp_path).read(tenant_ref=tenant, snapshot_ref=item.snapshot_ref)
    assert replayed["revision"] == 1 and replayed["identity_actions"] == result["identity_actions"]


def test_invalid_durable_split_rolls_back_record_and_audit(tmp_path):
    tenant = ref("tenantref", "a"); item = identity_snapshot(tenant); service = adapter(tmp_path)
    service.create_snapshot(item)
    first, second, third = (node.identifier for node in item.nodes[:3])
    before = service._store.get_control("graph_review", item.snapshot_ref, tenant)
    # Omitting one active endpoint is rejected by the domain primitive. The
    # durable wrapper must not leave a revision or audit append behind.
    invalid = GraphIdentitySplit(first, (second, third),
        (GraphSplitEndpointAssignment(item.claims[0].identifier, "source", second),))
    with pytest.raises(HTTPException):
        service.split_identity(tenant_ref=tenant, snapshot_ref=item.snapshot_ref, split=invalid,
            expected_revision=0, reviewer_ref=ref("reviewerref", "r"))
    after = service._store.get_control("graph_review", item.snapshot_ref, tenant)
    assert after["payload"]["events"] == before["payload"]["events"] == []
    assert service.read(tenant_ref=tenant, snapshot_ref=item.snapshot_ref)["revision"] == 0


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


def test_identity_routes_are_reviewer_only_cas_and_source_free(tmp_path, monkeypatch):
    setup(monkeypatch, tmp_path, "sqlite")
    app = create_app(); item = identity_snapshot(ref("tenantref", "tenant-a")); app.state.graph_reviews.create_snapshot(item)
    first, second = item.nodes[0].identifier, item.nodes[1].identifier
    path = f"/graph-reviews/{item.snapshot_ref}/merges"
    body = {"canonical_person_ref": first, "member_person_refs": [first, second], "expected_revision": 0}
    with TestClient(app) as client:
        assert client.post(path, headers=auth("processor"), json=body).status_code == 403
        merged = client.post(path, headers=auth("reviewer"), json=body)
        assert merged.status_code == 200 and merged.json()["revision"] == 1
        assert "graphevidence" not in merged.text
        assert client.post(path, headers=auth("reviewer"), json=body).status_code == 409
