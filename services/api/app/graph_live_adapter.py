"""Bounded in-process adapter from a server-produced demo graph to D06 claims.

It is not an API contract, persistence layer, or authority for response-local
edge IDs.  Only the current batch's graph and document membership are accepted.
"""
from __future__ import annotations

import re
from typing import Any

from app.graph_adjudication import GraphAdjudicationError, GraphClaim, GraphNode, ReviewDecision, adjudicate

_TYPES = {"assistant_to", "assistant_for", "works_at", "client_of", "works_on", "assigned_to", "sent_to"}
_KIND = {"person", "organization", "project"}
_EDGE_ID = re.compile(r"^edge_[0-9a-f]{16}$")


def adapt_live_graph(*, entity_graph: dict[str, Any], batch_document_ids: frozenset[str],
                     decisions: tuple[tuple[str, str], ...] = ()) -> dict[str, object]:
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
                      if type(item) is dict and set(item) == {"id", "kind", "label", "document_ids"}
                      and isinstance(item.get("id"), str) and item.get("kind") in _KIND
                      and isinstance(item.get("label"), str) and type(item.get("document_ids")) is list
                      and all(isinstance(value, str) and value in batch_document_ids for value in item["document_ids"]))
        if len(nodes) != len(nodes_raw): raise ValueError
        node_ids = {node.identifier for node in nodes}
        claims = []
        for index, edge in enumerate(edges_raw, 1):
            if (type(edge) is not dict or set(edge) != {"id", "type", "source_id", "target_id", "evidence"}
                    or not isinstance(edge["id"], str) or not _EDGE_ID.fullmatch(edge["id"])
                    or edge["type"] not in _TYPES or edge["source_id"] not in node_ids or edge["target_id"] not in node_ids
                    or type(edge["evidence"]) is not list or not edge["evidence"]): raise ValueError
            evidence = edge["evidence"]
            if any(type(item) is not dict or set(item) != {"document_id", "rule", "field", "locator"}
                   or not isinstance(item.get("document_id"), str) or not isinstance(item.get("rule"), str)
                   or not isinstance(item.get("field"), str) or type(item.get("locator")) is not dict
                   or item["document_id"] not in batch_document_ids for item in evidence): raise ValueError
            claims.append(GraphClaim(f"claim_{index}", edge["type"], edge["source_id"], edge["target_id"], f"doc_{index}"))
        if type(decisions) is not tuple or any(type(item) is not tuple or len(item) != 2 or not isinstance(item[0], str)
                                               or item[0] not in {edge["id"] for edge in edges_raw}
                                               or item[1] not in {"ACCEPT", "REJECT"} for item in decisions): raise ValueError
        if len({item[0] for item in decisions}) != len(decisions): raise ValueError
        edge_claims = {edge["id"]: f"claim_{index}" for index, edge in enumerate(edges_raw, 1)}
        return adjudicate(nodes=nodes, claims=tuple(claims),
                          decisions=tuple(ReviewDecision(edge_claims[edge], decision) for edge, decision in decisions))
    except (GraphAdjudicationError, KeyError, TypeError, ValueError):
        raise GraphAdjudicationError("Invalid ephemeral graph adjudication input.") from None
