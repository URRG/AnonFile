import pytest
from app.demo_batch import _public_entity_graph_with_ledger
from app.graph_adjudication import GraphAdjudicationError
from app.graph_live_adapter import adjudicate_private_ledger, build_private_graph_ledger


def test_empty_public_graph_builds_private_no_adjudication_ledger():
    ledger = build_private_graph_ledger({"nodes": [], "edges": []})
    assert ledger.nodes == () and ledger.claims_by_edge == ()
    report = adjudicate_private_ledger(ledger=ledger)
    assert report["status"] == "ABSTAINED" and report["reason"] == "NO_RELATIONSHIPS"
    with pytest.raises(GraphAdjudicationError):
        adjudicate_private_ledger(ledger=ledger, decisions=(("edge_0000000000000000", "ACCEPT"),))


def test_evidence_bound_matches_producer_limit():
    value, _ = graph()
    edge = value["edges"][0]
    base = edge["evidence"][0]
    edge["evidence"] = [{**base, "field": f"field_{index}"} for index in range(5)]
    assert build_private_graph_ledger(value).claims_by_edge
    edge["evidence"] = [{**base, "field": f"field_{index}"} for index in range(21)]
    with pytest.raises(GraphAdjudicationError):
        build_private_graph_ledger(value)


def graph():
    facts = [
        {"type":"works_at","source":"A","source_kind":"person","target":"O","target_kind":"organization","document_id":"upload-a","rule":"signature","field":"company","locator":{}},
        {"type":"assigned_to","source":"P","source_kind":"project","target":"A","target_kind":"person","document_id":"upload-b","rule":"statement","field":"text","locator":{}},
        {"type":"sent_to","source":"A","source_kind":"person","target":"B","target_kind":"person","document_id":"upload-c","rule":"header","field":"from","locator":{}},
    ]
    return _public_entity_graph_with_ledger(facts, {"a":"E1", "b":"E2"}, {"a":"Person 1", "b":"Person 2"})


def test_adapts_actual_three_document_graph_shape_without_leaking_ids():
    _, ledger = graph(); report = adjudicate_private_ledger(ledger=ledger)
    assert report["decisions"] == {"accepted": 0, "rejected": 0, "pending": 3}
    assert "upload-a" not in str(report) and "edge_" not in str(report)


def test_current_edge_decisions_map_to_transient_claims():
    value, ledger = graph()
    report = adjudicate_private_ledger(ledger=ledger,
                              decisions=((value["edges"][0]["id"], "ACCEPT"), (value["edges"][1]["id"], "REJECT")))
    assert report["decisions"] == {"accepted": 1, "rejected": 1, "pending": 1}


@pytest.mark.parametrize("change", [lambda g: g["edges"][0].update(id="edge_bad"),
                                  lambda g: g["edges"][0].update(type="client_of"),
                                  lambda g: g["edges"].append(dict(g["edges"][0])),
                                  lambda g: g["edges"][0]["evidence"][0].update(document_id="foreign"),
                                  lambda g: next(edge for edge in g["edges"] if edge["type"] == "works_at")["evidence"][0].update(document_id="upload-b"),
                                  lambda g: g["edges"][0]["evidence"][0].pop("locator")])
def test_tampered_live_graph_fails_closed(change):
    value, _ = graph(); change(value)
    with pytest.raises(GraphAdjudicationError): build_private_graph_ledger(value)


def test_unknown_or_repeated_edge_decisions_fail_closed():
    value, ledger = graph()
    current = value["edges"][0]["id"]
    for decisions in ((("edge_0000000000000000", "ACCEPT"),),
                      ((current, "ACCEPT"), (current, "REJECT"))):
        with pytest.raises(GraphAdjudicationError):
            adjudicate_private_ledger(ledger=ledger, decisions=decisions)
