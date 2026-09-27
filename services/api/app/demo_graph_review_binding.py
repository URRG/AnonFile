"""Trusted-server bridge from a synthetic batch graph to durable D06 review.

This is deliberately not an HTTP input contract.  It converts only the graph
that this process has just generated into an immutable, source-free snapshot.
The returned mapping is an optional navigation seam for a future reviewer UI;
it does not enable adjudication, release, or delivery.
"""
from __future__ import annotations

import secrets
from typing import Any

from app.revisioned_graph_review import GraphClaimSnapshot, GraphNodeSnapshot, GraphSnapshot


def _ref(kind: str) -> str:
    # 32 random bytes encode to the exact 43-character opaque grammar.  These
    # are not derived from source data, graph labels, or bearer tokens.
    return f"{kind}:v1:{secrets.token_urlsafe(32)}"


def snapshot_binding(*, tenant_ref: str, graph: object) -> tuple[GraphSnapshot, dict[str, Any]] | None:
    """Build a bounded snapshot from an already-public server-generated graph.

    An empty, malformed, or ontology-incompatible graph intentionally produces
    no snapshot.  Evidence is represented only by a fresh opaque binding and
    never copied from public locators into durable review state.
    """
    if not isinstance(graph, dict):
        return None
    nodes, edges = graph.get("nodes"), graph.get("edges")
    if not isinstance(nodes, list) or not isinstance(edges, list) or not nodes or not edges:
        return None
    node_refs: dict[str, str] = {}
    snapshots: list[GraphNodeSnapshot] = []
    for node in nodes:
        if (not isinstance(node, dict) or set(node) != {"id", "kind", "label", "document_ids"}
                or not isinstance(node["id"], str) or not isinstance(node["kind"], str)
                or node["kind"] not in {"person", "organization", "project"}
                or node["id"] in node_refs):
            return None
        node_refs[node["id"]] = _ref("graphnode")
        snapshots.append(GraphNodeSnapshot(node_refs[node["id"]], node["kind"]))
    claims: list[GraphClaimSnapshot] = []
    claim_bindings: list[dict[str, str]] = []
    seen_edges: set[str] = set()
    for edge in edges:
        if (not isinstance(edge, dict) or set(edge) != {"id", "type", "source_id", "target_id", "evidence"}
                or not isinstance(edge["id"], str) or edge["id"] in seen_edges
                or not isinstance(edge["type"], str) or edge["source_id"] not in node_refs
                or edge["target_id"] not in node_refs or not isinstance(edge["evidence"], list)
                or not edge["evidence"]):
            return None
        seen_edges.add(edge["id"])
        claim_ref = _ref("graphclaim")
        claims.append(GraphClaimSnapshot(claim_ref, edge["type"], node_refs[edge["source_id"]],
                                         node_refs[edge["target_id"]], _ref("graphevidence")))
        claim_bindings.append({"graph_edge_id": edge["id"], "claim_ref": claim_ref})
    try:
        snapshot = GraphSnapshot(tenant_ref, _ref("graphsnap"), tuple(snapshots), tuple(claims))
        # The domain adapter validates ontology, endpoint kinds, cardinality,
        # and every opaque identifier before anything reaches durable storage.
        from app.revisioned_graph_review import RevisionedGraphReviewStore
        RevisionedGraphReviewStore().create_snapshot(snapshot)
    except (TypeError, ValueError):
        return None
    return snapshot, {"snapshot_ref": snapshot.snapshot_ref,
                      "nodes": [{"graph_node_id": node_id, "node_ref": node_ref}
                                for node_id, node_ref in node_refs.items()],
                      "claims": claim_bindings,
                      "posture": "DEVELOPMENT_BINDING_ONLY_NO_ADJUDICATION_OR_RELEASE"}
