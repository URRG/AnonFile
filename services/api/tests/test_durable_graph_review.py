import base64
import hashlib

import pytest

from app.durable_graph_review import DurableGraphReviewAdapter
from app.durable_repository import DurableStore
from app.revisioned_graph_review import GraphClaimSnapshot, GraphNodeSnapshot, GraphReviewConflict, GraphSnapshot


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
    result = service.decide(tenant_ref=tenant, snapshot_ref=item.snapshot_ref, claim_ref=item.claims[0].identifier,
        expected_revision=0, decision="ACCEPT", reviewer_ref=ref("reviewerref", "r"))
    assert result["revision"] == 1 and "graphevidence" not in str(result)
    with pytest.raises(GraphReviewConflict):
        service.decide(tenant_ref=tenant, snapshot_ref=item.snapshot_ref, claim_ref=item.claims[0].identifier,
            expected_revision=0, decision="REJECT", reviewer_ref=ref("reviewerref", "r"))


def test_tenant_isolation_is_indistinguishable_from_missing(tmp_path):
    tenant = ref("tenantref", "a"); service = adapter(tmp_path); item = snapshot(tenant); service.create_snapshot(item)
    with pytest.raises(Exception):
        service.read(tenant_ref=ref("tenantref", "b"), snapshot_ref=item.snapshot_ref)
