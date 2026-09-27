import pytest

from app.revisioned_graph_review import (GraphClaimSnapshot, GraphNodeSnapshot, GraphReviewConflict,
    GraphReviewError, GraphConflictResolution, GraphIdentityMerge, GraphIdentitySplit, GraphSnapshot,
    GraphSplitEndpointAssignment, RevisionedGraphReviewStore)


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


def overlay_snapshot():
    people = tuple(opaque("graphnode", character) for character in "efgh")
    organizations = tuple(opaque("graphnode", character) for character in "ij")
    project = opaque("graphnode", "k")
    nodes = tuple(GraphNodeSnapshot(person, "person") for person in people) + tuple(
        GraphNodeSnapshot(org, "organization") for org in organizations) + (GraphNodeSnapshot(project, "project"),)
    claims = (
        GraphClaimSnapshot(opaque("graphclaim", "l"), "works_at", people[0], organizations[0], opaque("graphevidence", "m")),
        GraphClaimSnapshot(opaque("graphclaim", "n"), "works_at", people[1], organizations[1], opaque("graphevidence", "o")),
        GraphClaimSnapshot(opaque("graphclaim", "p"), "assigned_to", project, people[2], opaque("graphevidence", "q")),
        GraphClaimSnapshot(opaque("graphclaim", "r"), "assistant_to", people[2], people[3], opaque("graphevidence", "s")),
    )
    return GraphSnapshot(TENANT_A, SNAPSHOT, nodes, claims)


def test_identity_merge_is_revisioned_recalculates_conflicts_and_keeps_three_document_claims_immutable():
    store = RevisionedGraphReviewStore()
    initial = store.create_snapshot(overlay_snapshot())
    first, second = initial.snapshot.nodes[0].identifier, initial.snapshot.nodes[1].identifier
    claims = initial.snapshot.claims
    accepted = initial
    for claim in claims[:2]:
        accepted = store.decide(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, claim_ref=claim.identifier,
                                expected_revision=accepted.revision, decision="ACCEPT", reviewer_ref=REVIEWER)
    merged = store.merge_identities(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT,
                                    merge=GraphIdentityMerge(first, (first, second)),
                                    expected_revision=accepted.revision, reviewer_ref=REVIEWER)
    assert merged.revision == 3 and merged.identity_audit[0].action == "MERGE"
    assert merged.conflicts == (("POTENTIAL_MULTIPLE_WORKS_AT", 1, 2),)
    assert merged.snapshot.claims == initial.snapshot.claims
    private_evidence = overlay_snapshot().claims[0].evidence_binding_ref
    assert private_evidence not in str(merged)


def test_exact_conflict_resolution_is_one_shot_cas_and_does_not_change_claims():
    store = RevisionedGraphReviewStore(); initial = store.create_snapshot(overlay_snapshot())
    first, second = (node.identifier for node in initial.snapshot.nodes[:2])
    accepted = initial
    for claim in initial.snapshot.claims[:2]:
        accepted = store.decide(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, claim_ref=claim.identifier,
                                expected_revision=accepted.revision, decision="ACCEPT", reviewer_ref=REVIEWER)
    conflicted = store.merge_identities(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT,
                                        merge=GraphIdentityMerge(first, (first, second)),
                                        expected_revision=accepted.revision, reviewer_ref=REVIEWER)
    kind, subject, claims = __import__('app.revisioned_graph_review', fromlist=['conflict_groups']).conflict_groups(conflicted)[0]
    resolved = store.resolve_conflict(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT,
        resolution=GraphConflictResolution(kind, subject, claims, "RETAIN_ALL"),
        expected_revision=conflicted.revision, reviewer_ref=REVIEWER)
    assert resolved.revision == conflicted.revision + 1
    assert resolved.snapshot.claims == initial.snapshot.claims
    assert resolved.conflict_resolutions[0].claim_refs == claims
    with pytest.raises(GraphReviewConflict):
        store.resolve_conflict(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT,
            resolution=GraphConflictResolution(kind, subject, claims, "RETAIN_ALL"),
            expected_revision=conflicted.revision, reviewer_ref=REVIEWER)
    with pytest.raises(GraphReviewError):
        store.resolve_conflict(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT,
            resolution=GraphConflictResolution(kind, subject, tuple(reversed(claims)), "RETAIN_ALL"),
            expected_revision=resolved.revision, reviewer_ref=REVIEWER)


def test_merge_rejects_post_overlay_person_self_link_and_stale_update():
    store = RevisionedGraphReviewStore(); state = store.create_snapshot(overlay_snapshot())
    first, second = state.snapshot.nodes[0].identifier, state.snapshot.nodes[1].identifier
    edge = GraphClaimSnapshot(opaque("graphclaim", "t"), "assistant_to", first, second, opaque("graphevidence", "u"))
    snapshot_with_edge = GraphSnapshot(TENANT_A, opaque("graphsnap", "v"), overlay_snapshot().nodes,
                                       overlay_snapshot().claims + (edge,))
    store = RevisionedGraphReviewStore(); state = store.create_snapshot(snapshot_with_edge)
    with pytest.raises(GraphReviewError):
        store.merge_identities(tenant_ref=TENANT_A, snapshot_ref=snapshot_with_edge.snapshot_ref,
                               merge=GraphIdentityMerge(first, (first, second)), expected_revision=0, reviewer_ref=REVIEWER)
    clean = RevisionedGraphReviewStore(); state = clean.create_snapshot(overlay_snapshot())
    clean.merge_identities(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, merge=GraphIdentityMerge(first, (first, second)),
                           expected_revision=0, reviewer_ref=REVIEWER)
    with pytest.raises(GraphReviewConflict, match="^Stale graph review revision\\.$"):
        clean.merge_identities(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, merge=GraphIdentityMerge(first, (first, second)),
                               expected_revision=0, reviewer_ref=REVIEWER)


def test_split_requires_every_active_endpoint_exactly_once_and_redacts_evidence():
    store = RevisionedGraphReviewStore(); initial = store.create_snapshot(overlay_snapshot())
    child_one, child_two, source, peer = (node.identifier for node in initial.snapshot.nodes[:4])
    assigned, person_edge = initial.snapshot.claims[2:]
    incomplete = GraphIdentitySplit(source, (child_one, child_two),
        (GraphSplitEndpointAssignment(assigned.identifier, "target", child_one),))
    with pytest.raises(GraphReviewError):
        store.split_identity(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, split=incomplete,
                             expected_revision=0, reviewer_ref=REVIEWER)
    duplicated = GraphIdentitySplit(source, (child_one, child_two), (
        GraphSplitEndpointAssignment(assigned.identifier, "target", child_one),
        GraphSplitEndpointAssignment(assigned.identifier, "target", child_two),
        GraphSplitEndpointAssignment(person_edge.identifier, "source", child_two),))
    with pytest.raises(GraphReviewError):
        store.split_identity(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, split=duplicated,
                             expected_revision=0, reviewer_ref=REVIEWER)
    complete = GraphIdentitySplit(source, (child_one, child_two), (
        GraphSplitEndpointAssignment(assigned.identifier, "target", child_one),
        GraphSplitEndpointAssignment(person_edge.identifier, "source", child_two),))
    split = store.split_identity(tenant_ref=TENANT_A, snapshot_ref=SNAPSHOT, split=complete,
                                 expected_revision=0, reviewer_ref=REVIEWER)
    assert split.revision == 1 and split.identity_audit[0].action == "SPLIT"
    assert overlay_snapshot().claims[2].evidence_binding_ref not in str(split)
