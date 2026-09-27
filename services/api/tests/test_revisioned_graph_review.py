import pytest

from app.revisioned_graph_review import (GraphClaimSnapshot, GraphNodeSnapshot, GraphReviewConflict,
    GraphReviewError, GraphSnapshot, RevisionedGraphReviewStore)


def opaque(prefix, character):
    return f"{prefix}:v1:" + character * 43


TENANT_A = opaque("tenantref", "a")
TENANT_B = opaque("tenantref", "b")
SNAPSHOT = opaque("graphsnap", "c")
REVIEWER = opaque("reviewerref", "d")


def snapshot(tenant=TENANT_A):
    person, organization = opaque("graphnode", "e"), opaque("graphnode", "f")
    return GraphSnapshot(tenant, SNAPSHOT,
        (GraphNodeSnapshot(person, "person"), GraphNodeSnapshot(organization, "organization")),
        (GraphClaimSnapshot(opaque("graphclaim", "g"), "works_at", person, organization,
                            opaque("graphevidence", "h")),))


def test_server_owned_snapshot_accept_reject_is_revisioned_and_append_only():
    store = RevisionedGraphReviewStore()
    initial = store.create_snapshot(snapshot())
    claim = initial.snapshot.claims[0].identifier
    accepted = store.decide(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, claim_ref=claim,
                            expected_revision=0, decision="ACCEPT", reviewer_ref=REVIEWER)
    assert initial.revision == 0 and initial.decisions == () and initial.audit == ()
    assert accepted.revision == 1 and accepted.decisions == ((claim, "ACCEPT"),)
    assert accepted.audit[0].sequence == 1 and accepted.audit[0].revision == 1
    assert store.read(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT) == accepted


def test_public_projection_never_exposes_private_evidence_bindings():
    private = snapshot()
    view = RevisionedGraphReviewStore().create_snapshot(private)
    assert not hasattr(view.snapshot.claims[0], "evidence_binding_ref")
    assert private.claims[0].evidence_binding_ref not in str(view)


def test_stale_fabricated_and_cross_tenant_operations_fail_closed():
    store = RevisionedGraphReviewStore(); state = store.create_snapshot(snapshot())
    claim = state.snapshot.claims[0].identifier
    store.decide(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, claim_ref=claim,
                 expected_revision=0, decision="REJECT", reviewer_ref=REVIEWER)
    with pytest.raises(GraphReviewConflict, match="^Stale graph review revision\\.$"):
        store.decide(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, claim_ref=claim,
                     expected_revision=0, decision="ACCEPT", reviewer_ref=REVIEWER)
    for tenant, submitted_claim in ((TENANT_B, claim), (TENANT_A, opaque("graphclaim", "z"))):
        with pytest.raises(GraphReviewError, match="^Invalid revisioned graph review operation\\.$"):
            store.decide(tenant_ref=tenant, snapshot_ref=SNAPSHOT, claim_ref=submitted_claim,
                         expected_revision=1, decision="ACCEPT", reviewer_ref=REVIEWER)


def test_tenant_and_reviewer_references_are_trusted_server_inputs_not_authorization():
    store = RevisionedGraphReviewStore(); view = store.create_snapshot(snapshot())
    # Any syntactically opaque actor is accepted: upstream authentication and
    # reviewer-role authorization must happen before this domain primitive.
    arbitrary_reviewer = opaque("reviewerref", "q")
    result = store.decide(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT,
                          claim_ref=view.snapshot.claims[0].identifier, expected_revision=0,
                          decision="REJECT", reviewer_ref=arbitrary_reviewer)
    assert result.audit[0].reviewer_ref == arbitrary_reviewer
    # A different tenant tuple cannot locate this in-process state. This is
    # lookup isolation only; it is not an authorization boundary.
    with pytest.raises(GraphReviewError):
        store.read(tenant_ref=TENANT_B, snapshot_ref=SNAPSHOT)


def test_snapshot_rejects_source_values_and_badly_typed_or_reused_bindings():
    value = snapshot()
    sourceful = GraphSnapshot(value.tenant_ref, value.snapshot_ref, value.nodes,
        (GraphClaimSnapshot(value.claims[0].identifier, "works_at", value.nodes[0].identifier,
                            value.nodes[1].identifier, "raw-source-path"),))
    with pytest.raises(GraphReviewError):
        RevisionedGraphReviewStore().create_snapshot(sourceful)
    duplicated = GraphSnapshot(value.tenant_ref, value.snapshot_ref, value.nodes, value.claims + value.claims)
    with pytest.raises(GraphReviewError):
        RevisionedGraphReviewStore().create_snapshot(duplicated)


def test_identity_merge_and_split_are_not_part_of_the_d06_state_machine():
    state = RevisionedGraphReviewStore().create_snapshot(snapshot())
    assert not hasattr(state, "identity_actions")
    assert "merge" not in str(state).lower() and "split" not in str(state).lower()
