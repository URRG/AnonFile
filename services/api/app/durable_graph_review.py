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
    GraphSnapshot, GraphSplitEndpointAssignment, RevisionedGraphReviewStore)
from app.revisioned_graph_review import conflict_groups


DEMO_BATCH_SNAPSHOT_CAP = 8
_DEMO_BATCH_ORIGIN = "demo_batch_snapshot_binding_v1"


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

    def create_demo_batch_snapshot(self, snapshot: GraphSnapshot, *, actor: str = "demo-batch-bridge") -> bool:
        """Atomically register one optional demo snapshot, subject to a small cap.

        This deliberately does not alter generic ``create_snapshot`` semantics:
        explicit trusted-server review snapshots and unrelated controls remain
        governed only by their existing capacity rules.  Expired controls are
        purged within the same DurableStore transaction before counting.
        """
        state = RevisionedGraphReviewStore(); state.create_snapshot(snapshot)
        data = _record(tenant=snapshot.tenant_ref, snapshot=snapshot,
                       state={"snapshot": _snapshot_dict(snapshot), "events": [], "origin": _DEMO_BATCH_ORIGIN})
        with self._store._transaction():
            self._store._purge()
            self._store._purge_controls()
            existing = sum(record["tenant"] == snapshot.tenant_ref
                           and record["payload"].get("origin") == _DEMO_BATCH_ORIGIN
                           for record in self._store.controls["graph_review"].values())
            if existing >= DEMO_BATCH_SNAPSHOT_CAP:
                return False
            self._store._validate_control(data)
            if data["id"] in self._store.controls["graph_review"] or self._store._used_identifier(data["id"], "graph_review"):
                raise HTTPException(409, "Object already exists")
            if (sum(len(values) for values in self._store.controls.values()) >= self._store.MAX_CONTROLS
                    or sum(item["tenant"] == data["tenant"] for values in self._store.controls.values()
                           for item in values.values()) >= self._store.MAX_CONTROLS_PER_TENANT):
                raise HTTPException(429, "Development control capacity exceeded")
            self._store._append_event(data["tenant"], "graph_review.created", data["id"], actor, record=data)
            self._store.controls["graph_review"][data["id"]] = data
            return True

    def read(self, *, tenant_ref: str, snapshot_ref: str) -> dict[str, Any]:
        raw = self._store.get_control("graph_review", snapshot_ref, tenant_ref)
        return _public(_load(raw))

    def decide(self, *, tenant_ref: str, snapshot_ref: str, claim_ref: str,
               expected_revision: int, decision: str, reviewer_ref: str) -> dict[str, Any]:
        return self._update(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                            expected_revision=expected_revision, reviewer_ref=reviewer_ref,
                            event={"type": "decision", "claim": claim_ref, "decision": decision})

    def merge_identities(self, *, tenant_ref: str, snapshot_ref: str, merge: GraphIdentityMerge,
                         expected_revision: int, reviewer_ref: str) -> dict[str, Any]:
        return self._update(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                            expected_revision=expected_revision, reviewer_ref=reviewer_ref,
                            event={"type": "merge", "canonical": merge.canonical_person_ref,
                                   "members": list(merge.member_person_refs)})

    def split_identity(self, *, tenant_ref: str, snapshot_ref: str, split: GraphIdentitySplit,
                       expected_revision: int, reviewer_ref: str) -> dict[str, Any]:
        return self._update(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                            expected_revision=expected_revision, reviewer_ref=reviewer_ref,
                            event={"type": "split", "source": split.source_person_ref,
                                   "replacements": list(split.replacement_person_refs),
                                   "assignments": [{"claim": item.claim_ref, "endpoint": item.endpoint,
                                                    "replacement": item.replacement_person_ref}
                                                   for item in split.endpoint_assignments]})

    def _update(self, *, tenant_ref: str, snapshot_ref: str, expected_revision: int,
                reviewer_ref: str, event: dict[str, Any]) -> dict[str, Any]:
        # Direct use of the durable store transaction makes the read/CAS/write
        # indivisible across processes sharing the SQLite database.
        try:
            with self._store._transaction():
                raw = self._store._control("graph_review", snapshot_ref, tenant_ref)
                if raw["expires_at"] <= time.time():
                    raise HTTPException(404, "Control record not found")
                engine = _load(raw)
                try:
                    _apply(engine, event, tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                           expected_revision=expected_revision, reviewer_ref=reviewer_ref)
                except GraphReviewConflict:
                    # DurableStore rolls back and preserves HTTPException, but
                    # normalizes other exceptions to a storage failure.
                    raise HTTPException(409, "Graph review revision is stale") from None
                except GraphReviewError:
                    raise HTTPException(404, "Graph review unavailable") from None
                replacement = copy.deepcopy(raw)
                replacement["size_bytes"] = 0
                replacement["payload"]["events"] = _events(engine)
                self._store._validate_control(replacement)
                self._store._append_event(tenant_ref, "graph_review.updated", snapshot_ref, reviewer_ref, record=replacement)
                self._store.controls["graph_review"][snapshot_ref] = replacement
                return _public(engine)
        except HTTPException as error:
            if error.status_code == 409 and error.detail == "Graph review revision is stale":
                raise GraphReviewConflict() from None
            raise


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
            if (not isinstance(event, dict) or type(event.get("revision")) is not int
                    or isinstance(event["revision"], bool) or event["revision"] < 1
                    or type(event.get("reviewer")) is not str):
                raise GraphReviewError()
            # PR108 persisted terminal decisions before action tags existed.
            # Retain exactly that authenticated on-disk representation, and no
            # broader guesswork, so unknown stored shapes still fail closed.
            if set(event) == {"claim", "revision", "decision", "reviewer"}:
                replay = {"type": "decision", "claim": event["claim"], "decision": event["decision"]}
            else:
                replay = event
            _apply(engine, replay, tenant_ref=snapshot.tenant_ref, snapshot_ref=snapshot.snapshot_ref,
                   expected_revision=event["revision"] - 1, reviewer_ref=event["reviewer"])
        return engine
    except (KeyError, TypeError, ValueError, GraphReviewError):
        raise unavailable() from None

def _apply(engine: RevisionedGraphReviewStore, event: dict[str, Any], *, tenant_ref: str,
           snapshot_ref: str, expected_revision: int, reviewer_ref: str) -> None:
    """Replay exactly the serialized public action vocabulary, fail closed."""
    if not isinstance(event, dict) or type(event.get("type")) is not str:
        raise GraphReviewError()
    # Persisted entries carry immutable replay metadata; newly submitted action
    # dictionaries do not. Nothing else is accepted in either representation.
    action = {key: value for key, value in event.items() if key not in {"revision", "reviewer"}}
    if event["type"] == "decision" and set(action) == {"type", "claim", "decision"}:
        engine.decide(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref, claim_ref=action["claim"],
                      expected_revision=expected_revision, decision=action["decision"], reviewer_ref=reviewer_ref)
        return
    if event["type"] == "merge" and set(action) == {"type", "canonical", "members"}:
        members = action["members"]
        if type(members) is not list:
            raise GraphReviewError()
        engine.merge_identities(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                                merge=GraphIdentityMerge(action["canonical"], tuple(members)),
                                expected_revision=expected_revision, reviewer_ref=reviewer_ref)
        return
    if event["type"] == "split" and set(action) == {"type", "source", "replacements", "assignments"}:
        replacements, assignments = action["replacements"], action["assignments"]
        if type(replacements) is not list or type(assignments) is not list:
            raise GraphReviewError()
        parsed = []
        for item in assignments:
            if not isinstance(item, dict) or set(item) != {"claim", "endpoint", "replacement"}:
                raise GraphReviewError()
            parsed.append(GraphSplitEndpointAssignment(item["claim"], item["endpoint"], item["replacement"]))
        engine.split_identity(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                              split=GraphIdentitySplit(action["source"], tuple(replacements), tuple(parsed)),
                              expected_revision=expected_revision, reviewer_ref=reviewer_ref)
        return
    raise GraphReviewError()


def _events(engine: RevisionedGraphReviewStore) -> list[dict[str, Any]]:
    state = next(iter(engine._states.values()))
    events: list[dict[str, Any]] = [{"type": "decision", "claim": x.claim_ref, "revision": x.revision,
                                     "decision": x.decision, "reviewer": x.reviewer_ref} for x in state.audit]
    for action, audit in zip(state.identity_actions, state.identity_audit):
        if type(action) is GraphIdentityMerge:
            events.append({"type": "merge", "canonical": action.canonical_person_ref,
                           "members": list(action.member_person_refs), "revision": audit.revision,
                           "reviewer": audit.reviewer_ref})
        else:
            events.append({"type": "split", "source": action.source_person_ref,
                           "replacements": list(action.replacement_person_refs),
                           "assignments": [{"claim": item.claim_ref, "endpoint": item.endpoint,
                                            "replacement": item.replacement_person_ref}
                                           for item in action.endpoint_assignments],
                           "revision": audit.revision, "reviewer": audit.reviewer_ref})
    return sorted(events, key=lambda item: item["revision"])

def _public(engine: RevisionedGraphReviewStore) -> dict[str, Any]:
    view = engine.read(tenant_ref=next(iter(engine._states))[0], snapshot_ref=next(iter(engine._states))[1])
    return {"snapshot_ref": view.snapshot.snapshot_ref, "revision": view.revision,
            "nodes": [{"id": x.identifier, "kind": x.kind} for x in view.snapshot.nodes],
            "claims": [{"id": x.identifier, "relation": x.relation, "source": x.source_node_ref, "target": x.target_node_ref} for x in view.snapshot.claims],
            "decisions": [{"claim_ref": x[0], "decision": x[1]} for x in view.decisions],
            "identity_actions": [{"action": "MERGE", "canonical": item.canonical_person_ref,
                                  "members": list(item.member_person_refs)} if type(item) is GraphIdentityMerge else
                                 {"action": "SPLIT", "source": item.source_person_ref,
                                  "replacements": list(item.replacement_person_refs),
                                  "assignments": [{"claim_ref": x.claim_ref, "endpoint": x.endpoint,
                                                   "replacement": x.replacement_person_ref}
                                                  for x in item.endpoint_assignments]}
                                 for item in view.identity_actions],
            "conflicts": [{"kind": x[0], "subjects": x[1], "relationships": x[2]} for x in view.conflicts],
            "conflict_groups": [{"kind": kind, "subject_ref": subject, "claim_refs": list(claims)}
                                for kind, subject, claims in conflict_groups(view)],
            "posture": "REVIEW_ONLY_NO_RELEASE_OR_DELIVERY"}
