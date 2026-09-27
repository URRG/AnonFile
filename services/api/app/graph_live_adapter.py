"""Bounded in-process adapter from a server-produced demo graph to D06 claims.

It is not an API contract, persistence layer, or authority for response-local
edge IDs.  Only the current batch's graph and document membership are accepted.
"""
from __future__ import annotations

from typing import Any

from app.graph_adjudication import GraphAdjudicationError, GraphClaim, GraphNode, adjudicate

_TYPES = {"ASSISTANT_TO": "assistant_to", "ASSISTANT_FOR": "assistant_for", "WORKS_AT": "works_at",
          "CLIENT_OF": "client_of", "WORKS_ON": "works_on", "ASSIGNED_TO": "assigned_to", "EMAILED": "sent_to"}
_KIND = {"person", "organization", "project"}


def adapt_live_graph(*, entity_graph: dict[str, Any], batch_document_ids: frozenset[str]) -> dict[str, object]:
    """Prove membership and return only the source-free ephemeral D06 summary."""
    try:
        if type(entity_graph) is not dict or set(entity_graph) != {"nodes", "edges"} or type(batch_document_ids) is not frozenset:
            raise ValueError
        if not batch_document_ids or not all(isinstance(value, str) and value for value in batch_document_ids):
            raise ValueError
        nodes_raw, edges_raw = entity_graph["nodes"], entity_graph["edges"]
        if type(nodes_raw) is not list or type(edges_raw) is not list or not nodes_raw or len(nodes_raw) > 100 or len(edges_raw) > 200:
            raise ValueError
        nodes = tuple(GraphNode(item["id"], item["kind"]) for item in nodes_raw
                      if type(item) is dict and isinstance(item.get("id"), str) and item.get("kind") in _KIND)
        if len(nodes) != len(nodes_raw): raise ValueError
        node_ids = {node.identifier for node in nodes}
        claims = []
        for index, edge in enumerate(edges_raw, 1):
            if (type(edge) is not dict or set(edge) != {"id", "type", "source_id", "target_id", "evidence"}
                    or not isinstance(edge["id"], str) or not edge["id"].startswith("edge_")
                    or edge["type"] not in _TYPES or edge["source_id"] not in node_ids or edge["target_id"] not in node_ids
                    or type(edge["evidence"]) is not list or not edge["evidence"]): raise ValueError
            evidence = edge["evidence"]
            if any(type(item) is not dict or not isinstance(item.get("document_id"), str)
                   or item["document_id"] not in batch_document_ids for item in evidence): raise ValueError
            claims.append(GraphClaim(f"claim_{index}", _TYPES[edge["type"]], edge["source_id"], edge["target_id"], f"doc_{index}"))
        return adjudicate(nodes=nodes, claims=tuple(claims))
    except (GraphAdjudicationError, KeyError, TypeError, ValueError):
        raise GraphAdjudicationError("Invalid ephemeral graph adjudication input.") from None
