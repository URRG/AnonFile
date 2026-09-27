import pytest
from app.demo_batch import _public_entity_graph
from app.graph_adjudication import GraphAdjudicationError
from app.graph_live_adapter import adapt_live_graph


def graph():
    facts = [
        {"type":"works_at","source":"A","source_kind":"person","target":"O","target_kind":"organization","document_id":"upload-a","rule":"signature","field":"company","locator":{}},
        {"type":"assigned_to","source":"P","source_kind":"project","target":"A","target_kind":"person","document_id":"upload-b","rule":"statement","field":"text","locator":{}},
        {"type":"sent_to","source":"A","source_kind":"person","target":"B","target_kind":"person","document_id":"upload-c","rule":"header","field":"from","locator":{}},
    ]
    return _public_entity_graph(facts, {"a":"E1", "b":"E2"}, {"a":"Person 1", "b":"Person 2"})


def test_adapts_actual_three_document_graph_shape_without_leaking_ids():
    report = adapt_live_graph(entity_graph=graph(), batch_document_ids=frozenset({"upload-a", "upload-b", "upload-c"}))
    assert report["decisions"] == {"accepted": 0, "rejected": 0, "pending": 3}
    assert "upload-a" not in str(report) and "edge_" not in str(report)


def test_current_edge_decisions_map_to_transient_claims():
    value = graph()
    report = adapt_live_graph(entity_graph=value, batch_document_ids=frozenset({"upload-a", "upload-b", "upload-c"}),
                              decisions=((value["edges"][0]["id"], "ACCEPT"), (value["edges"][1]["id"], "REJECT")))
    assert report["decisions"] == {"accepted": 1, "rejected": 1, "pending": 1}


@pytest.mark.parametrize("change", [lambda g: g["edges"][0].update(id="edge_bad"), lambda g: g["edges"][0]["evidence"][0].update(document_id="foreign"), lambda g: g["edges"][0]["evidence"][0].pop("locator")])
def test_tampered_live_graph_fails_closed(change):
    value = graph(); change(value)
    with pytest.raises(GraphAdjudicationError): adapt_live_graph(entity_graph=value, batch_document_ids=frozenset({"upload-a", "upload-b", "upload-c"}))
