import pytest

from app.graph_adjudication import (GraphAdjudicationError, GraphClaim, GraphNode, IdentityMerge,
                                    IdentitySplit, ReviewDecision, adjudicate)


def fixture_graph():
    nodes = (GraphNode("E1", "person"), GraphNode("E2", "person"), GraphNode("E3", "person"),
             GraphNode("E4", "person"), GraphNode("E5", "person"), GraphNode("E6", "person"),
             GraphNode("organization_1", "organization"), GraphNode("organization_2", "organization"),
             GraphNode("project_1", "project"))
    claims = (GraphClaim("claim_1", "works_at", "E1", "organization_1", "doc_1"),
              GraphClaim("claim_2", "works_at", "E2", "organization_1", "doc_2"),
              GraphClaim("claim_3", "works_at", "E1", "organization_2", "doc_3"),
              GraphClaim("claim_4", "assigned_to", "project_1", "E3", "doc_3"),
              GraphClaim("claim_5", "assigned_to", "project_1", "E4", "doc_2"),
              GraphClaim("claim_6", "assistant_to", "E2", "E3", "doc_1"))
    return nodes, claims


def test_ephemeral_review_accept_reject_merge_split_and_typed_conflicts_across_three_documents():
    nodes, claims = fixture_graph()
    report = adjudicate(nodes=nodes, claims=claims,
                        decisions=(ReviewDecision("claim_1", "ACCEPT"), ReviewDecision("claim_2", "ACCEPT"),
                                   ReviewDecision("claim_3", "ACCEPT"), ReviewDecision("claim_4", "ACCEPT"),
                                   ReviewDecision("claim_5", "ACCEPT"), ReviewDecision("claim_6", "REJECT")),
                        merges=(IdentityMerge("E1", ("E1", "E2")),),
                        splits=(IdentitySplit("E3", ("E5", "E6"),
                                              (("claim_4", "E5"),)),))
    assert report["state"] == "EPHEMERAL_STATELESS" and report["release_authorized"] is False
    assert report["decisions"] == {"accepted": 5, "rejected": 1, "pending": 0}
    assert report["identity_actions"] == {"merges": 1, "splits": 1, "claims_reassigned_by_split": 1}
    assert report["relationships"]["works_at"] == {"accepted": 3, "rejected": 0, "pending": 0}
    assert {item["kind"] for item in report["conflicts"]} == {"POTENTIAL_MULTIPLE_WORKS_AT", "POTENTIAL_MULTIPLE_ASSIGNED_TO"}
    assert {item["status"] for item in report["conflicts"]} == {"UNRESOLVED_REVIEW_REQUIRED"}
    rendered = str(report)
    for private_value in ("E1", "organization_1", "project_1", "doc_1", "claim_1"):
        assert private_value not in rendered


@pytest.mark.parametrize("mutate", [
    lambda nodes, claims: dict(decisions=(ReviewDecision("claim_99", "ACCEPT"),)),
    lambda nodes, claims: dict(merges=(IdentityMerge("E1", ("E1", "organization_1")),)),
    lambda nodes, claims: dict(splits=(IdentitySplit("E3", ("E5", "E6"), (("claim_4", "E5"),)),)),
    lambda nodes, claims: dict(claims=claims + (GraphClaim("claim_7", "works_at", "E1", "E2", "doc_1"),)),
])
def test_invalid_actions_and_wrong_typed_endpoints_fail_closed(mutate):
    nodes, claims = fixture_graph()
    values = {"nodes": nodes, "claims": claims}
    values.update(mutate(nodes, claims))
    with pytest.raises(GraphAdjudicationError, match="^Invalid ephemeral graph adjudication input\\.$"):
        adjudicate(**values)


def test_split_rejects_one_claim_reassigned_by_two_person_splits():
    nodes, claims = fixture_graph()
    claims += (GraphClaim("claim_7", "assistant_to", "E3", "E4", "doc_1"),)
    with pytest.raises(GraphAdjudicationError, match="^Invalid ephemeral graph adjudication input\\.$"):
        adjudicate(nodes=nodes, claims=claims,
                   splits=(IdentitySplit("E3", ("E5", "E6"), (("claim_4", "E5"), ("claim_7", "E5"))),
                           IdentitySplit("E4", ("E5", "E6"), (("claim_5", "E5"), ("claim_7", "E6")))))


def test_accepted_person_edge_collapsed_by_merge_fails_closed():
    nodes, claims = fixture_graph()
    claims += (GraphClaim("claim_7", "assistant_to", "E1", "E2", "doc_1"),)
    with pytest.raises(GraphAdjudicationError, match="^Invalid ephemeral graph adjudication input\\.$"):
        adjudicate(nodes=nodes, claims=claims, decisions=(ReviewDecision("claim_7", "ACCEPT"),),
                   merges=(IdentityMerge("E1", ("E1", "E2")),))


@pytest.mark.parametrize("mutate", [
    lambda nodes, claims: dict(nodes=(GraphNode("E1", []),)),
    lambda nodes, claims: dict(claims=(GraphClaim("claim_1", [], "E1", "E2", "doc_1"),)),
    lambda nodes, claims: dict(decisions=(ReviewDecision([], "ACCEPT"),)),
    lambda nodes, claims: dict(merges=(IdentityMerge([], ("E1", "E2")),)),
    lambda nodes, claims: dict(merges=(IdentityMerge("E1", ("E1", [])),)),
    lambda nodes, claims: dict(splits=(IdentitySplit([], ("E5", "E6"), ()),)),
    lambda nodes, claims: dict(splits=(IdentitySplit("E3", ("E5", []), ()),)),
    lambda nodes, claims: dict(splits=(IdentitySplit("E3", ("E5", "E6"), (([], "E5"),)),)),
])
def test_malformed_direct_dataclass_fields_fail_with_the_fixed_error(mutate):
    nodes, claims = fixture_graph()
    values = {"nodes": nodes, "claims": claims}
    values.update(mutate(nodes, claims))
    with pytest.raises(GraphAdjudicationError, match="^Invalid ephemeral graph adjudication input\\.$"):
        adjudicate(**values)


def test_split_and_merge_cannot_share_any_person_identity():
    nodes, claims = fixture_graph()
    with pytest.raises(GraphAdjudicationError, match="^Invalid ephemeral graph adjudication input\\.$"):
        adjudicate(nodes=nodes, claims=claims,
                   decisions=(ReviewDecision("claim_4", "ACCEPT"),),
                   merges=(IdentityMerge("E5", ("E5", "E6")),),
                   splits=(IdentitySplit("E3", ("E5", "E6"), (("claim_4", "E6"),)),))
