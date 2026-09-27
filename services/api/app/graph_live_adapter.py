"""Bounded in-process adapter from a server-produced demo graph to D06 claims.

It is not an API contract, persistence layer, or authority for response-local
edge IDs.  Only the current batch's graph and document membership are accepted.
"""
from __future__ import annotations

import re
import hashlib
import json
from dataclasses import dataclass
from typing import Any

from app.graph_adjudication import GraphAdjudicationError, GraphClaim, GraphNode, ReviewDecision, adjudicate

_TYPES = {"assistant_to", "assistant_for", "works_at", "client_of", "works_on", "assigned_to", "sent_to"}
_KIND = {"person", "organization", "project"}
_EDGE_ID = re.compile(r"^edge_[0-9a-f]{16}$")
_MAX_NODE_DOCUMENTS = 3
# Must match demo_batch.MAX_GRAPH_EVIDENCE_PER_EDGE; duplicated to avoid a
# demo_batch import cycle in this low-level ledger helper.
_MAX_EVIDENCE = 20


@dataclass(frozen=True)
class PrivateGraphLedger:
    """Producer-owned, request-local graph review input; never serialize it."""
    nodes: tuple[GraphNode, ...]
    claims_by_edge: tuple[tuple[str, GraphClaim], ...]


def build_private_graph_ledger(entity_graph: dict[str, Any]) -> PrivateGraphLedger:
    """Called only beside the server graph producer, before any response serialization."""
    try:
        if type(entity_graph) is not dict or set(entity_graph) != {"nodes", "edges"}:
            raise ValueError
        nodes_raw, edges_raw = entity_graph["nodes"], entity_graph["edges"]
        if type(nodes_raw) is not list or type(edges_raw) is not list or len(nodes_raw) > 100 or len(edges_raw) > 200:
            raise ValueError
        if not nodes_raw and not edges_raw:
            return PrivateGraphLedger((), ())
        if not nodes_raw:
            raise ValueError
        nodes = tuple(GraphNode(item["id"], item["kind"]) for item in nodes_raw
                      if type(item) is dict and set(item) == {"id", "kind", "label", "document_ids"}
                      and isinstance(item.get("id"), str) and item.get("kind") in _KIND
                       and isinstance(item.get("label"), str) and type(item.get("document_ids")) is list
                       and len(item["document_ids"]) <= _MAX_NODE_DOCUMENTS and len(set(item["document_ids"])) == len(item["document_ids"])
                       and all(isinstance(value, str) and value for value in item["document_ids"]))
        if len(nodes) != len(nodes_raw) or len({node.identifier for node in nodes}) != len(nodes): raise ValueError
        node_ids = {node.identifier for node in nodes}
        node_documents = {item["id"]: set(item["document_ids"]) for item in nodes_raw}
        claims: list[tuple[str, GraphClaim]] = []
        edge_ids: set[str] = set()
        for index, edge in enumerate(edges_raw, 1):
            if (type(edge) is not dict or set(edge) != {"id", "type", "source_id", "target_id", "evidence"}
                    or not isinstance(edge["id"], str) or not _EDGE_ID.fullmatch(edge["id"])
                    or edge["type"] not in _TYPES or edge["source_id"] not in node_ids or edge["target_id"] not in node_ids
                    or type(edge["evidence"]) is not list or not edge["evidence"] or len(edge["evidence"]) > _MAX_EVIDENCE): raise ValueError
            expected = "edge_" + hashlib.sha256(f"{edge['type']}\x1f{edge['source_id']}\x1f{edge['target_id']}".encode("utf-8")).hexdigest()[:16]
            if edge["id"] != expected or edge["id"] in edge_ids: raise ValueError
            edge_ids.add(edge["id"])
            evidence = edge["evidence"]
            if any(type(item) is not dict or set(item) != {"document_id", "rule", "field", "locator"}
                   or not isinstance(item.get("document_id"), str) or not isinstance(item.get("rule"), str)
                   or not isinstance(item.get("field"), str) or type(item.get("locator")) is not dict
                    or item["document_id"] not in node_documents[edge["source_id"]]
                    or item["document_id"] not in node_documents[edge["target_id"]] for item in evidence): raise ValueError
            canonical_evidence = {json.dumps(item, sort_keys=True, separators=(",", ":")) for item in evidence}
            if len(canonical_evidence) != len(evidence): raise ValueError
            claims.append((edge["id"], GraphClaim(f"claim_{index}", edge["type"], edge["source_id"], edge["target_id"], f"doc_{index}")))
        return PrivateGraphLedger(nodes, tuple(claims))
    except (GraphAdjudicationError, KeyError, TypeError, ValueError):
        raise GraphAdjudicationError("Invalid ephemeral graph adjudication input.") from None


def adjudicate_private_ledger(*, ledger: PrivateGraphLedger, decisions: tuple[tuple[str, str], ...] = ()) -> dict[str, object]:
    """Adjudicate producer-owned ledger only; response IDs are never accepted as graph input."""
    try:
        if type(ledger) is not PrivateGraphLedger or type(decisions) is not tuple or len(decisions) > len(ledger.claims_by_edge): raise ValueError
        if not ledger.claims_by_edge:
            if decisions:
                raise ValueError
            return {"schema_version": "ephemeral-graph-adjudication-v1", "state": "EPHEMERAL_STATELESS",
                    "release_authorized": False, "status": "ABSTAINED", "reason": "NO_RELATIONSHIPS",
                    "decisions": {"accepted": 0, "rejected": 0, "pending": 0}, "relationships": {}, "conflicts": [],
                    "limitations": ["No relationships were produced for this batch; no adjudication was attempted.",
                                    "This source-free in-process summary does not authorize release or delivery."]}
        edge_claims = dict(ledger.claims_by_edge)
        if len(edge_claims) != len(ledger.claims_by_edge) or any(type(item) is not tuple or len(item) != 2 or not isinstance(item[0], str)
                                               or item[0] not in edge_claims
                                               or item[1] not in {"ACCEPT", "REJECT"} for item in decisions): raise ValueError
        if len({item[0] for item in decisions}) != len(decisions): raise ValueError
        return adjudicate(nodes=ledger.nodes, claims=tuple(edge_claims.values()),
                          decisions=tuple(ReviewDecision(edge_claims[edge].identifier, decision) for edge, decision in decisions))
    except (GraphAdjudicationError, KeyError, TypeError, ValueError):
        raise GraphAdjudicationError("Invalid ephemeral graph adjudication input.") from None
