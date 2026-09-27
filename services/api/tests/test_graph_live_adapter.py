import pytest
from app.graph_adjudication import GraphAdjudicationError
from app.graph_live_adapter import adapt_live_graph

def graph():
    return {"nodes": [{"id":"E1","kind":"person"},{"id":"E2","kind":"person"},{"id":"organization_1","kind":"organization"},{"id":"project_1","kind":"project"}], "edges": [
      {"id":"edge_0123456789abcdef","type":"WORKS_AT","source_id":"E1","target_id":"organization_1","evidence":[{"document_id":"upload-a"}]},
      {"id":"edge_1111111111111111","type":"ASSIGNED_TO","source_id":"project_1","target_id":"E1","evidence":[{"document_id":"upload-b"}]},
      {"id":"edge_2222222222222222","type":"EMAILED","source_id":"E1","target_id":"E2","evidence":[{"document_id":"upload-c"}]}]}

def test_adapts_three_document_live_graph_without_leaking_ids():
    report=adapt_live_graph(entity_graph=graph(), batch_document_ids=frozenset({"upload-a","upload-b","upload-c"}))
    assert report["decisions"] == {"accepted":0,"rejected":0,"pending":3}
    assert "upload-a" not in str(report) and "edge_" not in str(report)

@pytest.mark.parametrize("change", [lambda g: g["edges"][0].update(id="not-edge"), lambda g: g["edges"][0]["evidence"][0].update(document_id="foreign")])
def test_tampered_live_graph_fails_closed(change):
    value=graph(); change(value)
    with pytest.raises(GraphAdjudicationError): adapt_live_graph(entity_graph=value, batch_document_ids=frozenset({"upload-a","upload-b","upload-c"}))
