"""Durable, source-free persistence boundary for D06 graph review.

Only a DurableStore may back an HTTP route.  State is encrypted as one bounded
control record and each successful CAS append is committed with its audit event
in the store's single SQLite transaction.
"""
from __future__ import annotations

import copy
import time
from typing import Any

from fastapi import HTTPException

from app.durable_repository import DurableStore
from app.repository import detached, unavailable
from app.revisioned_graph_review import (GraphClaimSnapshot, GraphIdentityMerge,
    GraphIdentitySplit, GraphNodeSnapshot, GraphReviewConflict, GraphReviewError,
    GraphSnapshot, RevisionedGraphReviewStore)


def _record(*, tenant: str, snapshot: GraphSnapshot, state: dict[str, Any]) -> dict[str, Any]:
    return {"id": snapshot.snapshot_ref, "kind": "graph_review", "tenant": tenant,
            "created_at": "server", "expires_at": time.time() + 3600,
            "size_bytes": 0, "payload": state}


class DurableGraphReviewAdapter:
    """Repository adapter; never accepts a snapshot from an HTTP request."""
    def __init__(self, store: DurableStore):
        if type(store) is not DurableStore:
            raise GraphReviewError()
        self._store = store

    def create_snapshot(self, snapshot: GraphSnapshot, *, actor: str = "system") -> None:
        state = RevisionedGraphReviewStore(); state.create_snapshot(snapshot)
        self._store.add_control(_record(tenant=snapshot.tenant_ref, snapshot=snapshot,
            state={"snapshot": _snapshot_dict(snapshot), "events": []}), actor)

    def read(self, *, tenant_ref: str, snapshot_ref: str) -> dict[str, Any]:
        raw = self._store.get_control("graph_review", snapshot_ref, tenant_ref)
        return _public(_load(raw))

    def decide(self, *, tenant_ref: str, snapshot_ref: str, claim_ref: str,
               expected_revision: int, decision: str, reviewer_ref: str) -> dict[str, Any]:
        # Direct use of the durable store transaction makes the read/CAS/write
        # indivisible across processes sharing the SQLite database.
        with self._store._transaction():
            raw = self._store._control("graph_review", snapshot_ref, tenant_ref)
            engine = _load(raw)
            view = engine.decide(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                                 claim_ref=claim_ref, expected_revision=expected_revision,
                                 decision=decision, reviewer_ref=reviewer_ref)
            replacement = _record(tenant=tenant_ref, snapshot=engine._states[(tenant_ref, snapshot_ref)].snapshot,
                state={"snapshot": raw["payload"]["snapshot"], "events": _events(engine)})
            self._store._validate_control(replacement)
            self._store._append_event(tenant_ref, "graph_review.updated", snapshot_ref, reviewer_ref, record=replacement)
            self._store.controls["graph_review"][snapshot_ref] = replacement
            return _public(engine)


def _snapshot_dict(s: GraphSnapshot) -> dict[str, Any]:
    return {"tenant": s.tenant_ref, "snapshot": s.snapshot_ref,
            "nodes": [[x.identifier, x.kind] for x in s.nodes],
            "claims": [[x.identifier, x.relation, x.source_node_ref, x.target_node_ref, x.evidence_binding_ref] for x in s.claims]}

def _load(raw: dict[str, Any]) -> RevisionedGraphReviewStore:
    try:
        payload = raw["payload"]; s = payload["snapshot"]
        snapshot = GraphSnapshot(s["tenant"], s["snapshot"], tuple(GraphNodeSnapshot(*x) for x in s["nodes"]),
            tuple(GraphClaimSnapshot(*x) for x in s["claims"]))
        engine = RevisionedGraphReviewStore(); engine.create_snapshot(snapshot)
        for event in payload["events"]:
            engine.decide(tenant_ref=snapshot.tenant_ref, snapshot_ref=snapshot.snapshot_ref,
                claim_ref=event["claim"], expected_revision=event["revision"] - 1,
                decision=event["decision"], reviewer_ref=event["reviewer"])
        return engine
    except (KeyError, TypeError, ValueError, GraphReviewError):
        raise unavailable() from None

def _events(engine: RevisionedGraphReviewStore) -> list[dict[str, Any]]:
    state = next(iter(engine._states.values()))
    return [{"claim": x.claim_ref, "revision": x.revision, "decision": x.decision, "reviewer": x.reviewer_ref} for x in state.audit]

def _public(engine: RevisionedGraphReviewStore) -> dict[str, Any]:
    view = engine.read(tenant_ref=next(iter(engine._states))[0], snapshot_ref=next(iter(engine._states))[1])
    return {"snapshot_ref": view.snapshot.snapshot_ref, "revision": view.revision,
            "nodes": [{"id": x.identifier, "kind": x.kind} for x in view.snapshot.nodes],
            "claims": [{"id": x.identifier, "relation": x.relation, "source": x.source_node_ref, "target": x.target_node_ref} for x in view.snapshot.claims],
            "decisions": [{"claim_ref": x[0], "decision": x[1]} for x in view.decisions],
            "conflicts": [{"kind": x[0], "subjects": x[1], "relationships": x[2]} for x in view.conflicts],
            "posture": "REVIEW_ONLY_NO_RELEASE_OR_DELIVERY"}
