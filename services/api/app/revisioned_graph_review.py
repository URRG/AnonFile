"""Bounded, source-free D06 graph-review state machine.

This is deliberately a trusted-server domain primitive, not an HTTP contract
or storage adapter.  Only trusted server code may supply its tenant and
reviewer references; their opaque syntax is validation, not authentication or
authorization.  A server creates an immutable graph snapshot whose identifiers
and evidence bindings are opaque.  Reviewers can append one terminal
accept/reject decision per claim only at the revision they read.

Identity overlays are revisioned review actions.  They only change the
effective endpoints used for review; the original claims and evidence bindings
remain immutable.  It also does not make process memory durable: a future
repository adapter must atomically retain the snapshot, current revision, and
complete audit stream before this can back a product route.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from threading import RLock
from typing import Literal


_OPAQUE = r"[A-Za-z0-9_-]{43}"
_TENANT = re.compile(r"tenantref:v1:" + _OPAQUE + r"\Z")
_SNAPSHOT = re.compile(r"graphsnap:v1:" + _OPAQUE + r"\Z")
_NODE = re.compile(r"graphnode:v1:" + _OPAQUE + r"\Z")
_CLAIM = re.compile(r"graphclaim:v1:" + _OPAQUE + r"\Z")
_EVIDENCE = re.compile(r"graphevidence:v1:" + _OPAQUE + r"\Z")
_REVIEWER = re.compile(r"reviewerref:v1:" + _OPAQUE + r"\Z")
_RELATIONS = frozenset({"assistant_to", "assistant_for", "works_at", "client_of", "works_on", "assigned_to", "sent_to"})
_KINDS = frozenset({"person", "organization", "project"})
_ENDPOINTS = {
    "assistant_to": ("person", "person"), "sent_to": ("person", "person"),
    "assistant_for": ("person", "organization"), "works_at": ("person", "organization"),
    "client_of": ("person", "organization"), "works_on": ("person", "project"),
    "assigned_to": ("project", "person"),
}
_MAX_NODES = 100
_MAX_CLAIMS = 200
_MAX_AUDIT_EVENTS = 200


class GraphReviewError(ValueError):
    """Fixed rejection that never reflects a submitted value."""

    def __init__(self) -> None:
        super().__init__("Invalid revisioned graph review operation.")


class GraphReviewConflict(GraphReviewError):
    """The caller read a revision that is no longer current."""

    def __init__(self) -> None:
        ValueError.__init__(self, "Stale graph review revision.")


def _fail() -> None:
    raise GraphReviewError()


def _opaque(value: object, pattern: re.Pattern[str]) -> str:
    if type(value) is not str or not pattern.fullmatch(value):
        _fail()
    return value


@dataclass(frozen=True, slots=True)
class GraphNodeSnapshot:
    identifier: str
    kind: Literal["person", "organization", "project"]


@dataclass(frozen=True, slots=True)
class GraphClaimSnapshot:
    identifier: str
    relation: str
    source_node_ref: str
    target_node_ref: str
    evidence_binding_ref: str


@dataclass(frozen=True, slots=True)
class GraphSnapshot:
    tenant_ref: str
    snapshot_ref: str
    nodes: tuple[GraphNodeSnapshot, ...]
    claims: tuple[GraphClaimSnapshot, ...]


@dataclass(frozen=True, slots=True)
class GraphReviewAuditEvent:
    sequence: int
    revision: int
    claim_ref: str
    decision: Literal["ACCEPT", "REJECT"]
    reviewer_ref: str


@dataclass(frozen=True, slots=True)
class GraphIdentityMerge:
    """Merge current persons into an existing canonical person."""
    canonical_person_ref: str
    member_person_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class GraphSplitEndpointAssignment:
    """One explicit replacement for one claim endpoint."""
    claim_ref: str
    endpoint: Literal["source", "target"]
    replacement_person_ref: str


@dataclass(frozen=True, slots=True)
class GraphIdentitySplit:
    """Split one current person with exhaustive active endpoint assignments."""
    source_person_ref: str
    replacement_person_refs: tuple[str, ...]
    endpoint_assignments: tuple[GraphSplitEndpointAssignment, ...]


@dataclass(frozen=True, slots=True)
class GraphIdentityAuditEvent:
    sequence: int
    revision: int
    action: Literal["MERGE", "SPLIT"]
    reviewer_ref: str


@dataclass(frozen=True, slots=True)
class _GraphReviewState:
    """Private store state. Evidence bindings must never leave this object."""
    snapshot: GraphSnapshot
    revision: int
    decisions: tuple[tuple[str, Literal["ACCEPT", "REJECT"]], ...]
    audit: tuple[GraphReviewAuditEvent, ...]
    identity_actions: tuple[GraphIdentityMerge | GraphIdentitySplit, ...]
    identity_audit: tuple[GraphIdentityAuditEvent, ...]


@dataclass(frozen=True, slots=True)
class GraphClaimView:
    identifier: str
    relation: str
    source_node_ref: str
    target_node_ref: str


@dataclass(frozen=True, slots=True)
class GraphSnapshotView:
    tenant_ref: str
    snapshot_ref: str
    nodes: tuple[GraphNodeSnapshot, ...]
    claims: tuple[GraphClaimView, ...]


@dataclass(frozen=True, slots=True)
class GraphReviewView:
    """Source-free public projection; it intentionally omits evidence bindings."""
    snapshot: GraphSnapshotView
    revision: int
    decisions: tuple[tuple[str, Literal["ACCEPT", "REJECT"]], ...]
    audit: tuple[GraphReviewAuditEvent, ...]
    identity_actions: tuple[GraphIdentityMerge | GraphIdentitySplit, ...]
    identity_audit: tuple[GraphIdentityAuditEvent, ...]
    conflicts: tuple[tuple[str, int, int], ...]


def _view(state: _GraphReviewState) -> GraphReviewView:
    snapshot = state.snapshot
    return GraphReviewView(
        snapshot=GraphSnapshotView(snapshot.tenant_ref, snapshot.snapshot_ref, snapshot.nodes,
            tuple(GraphClaimView(item.identifier, item.relation, item.source_node_ref, item.target_node_ref)
                  for item in snapshot.claims)),
        revision=state.revision, decisions=state.decisions, audit=state.audit,
        identity_actions=state.identity_actions, identity_audit=state.identity_audit,
        conflicts=_conflicts(state.snapshot, state.decisions, state.identity_actions))


def _validate_snapshot(snapshot: object) -> GraphSnapshot:
    if type(snapshot) is not GraphSnapshot:
        _fail()
    tenant_ref = _opaque(snapshot.tenant_ref, _TENANT)
    snapshot_ref = _opaque(snapshot.snapshot_ref, _SNAPSHOT)
    if type(snapshot.nodes) is not tuple or not snapshot.nodes or len(snapshot.nodes) > _MAX_NODES:
        _fail()
    kinds: dict[str, str] = {}
    for node in snapshot.nodes:
        if type(node) is not GraphNodeSnapshot:
            _fail()
        identifier = _opaque(node.identifier, _NODE)
        if type(node.kind) is not str or node.kind not in _KINDS or identifier in kinds:
            _fail()
        kinds[identifier] = node.kind
    if type(snapshot.claims) is not tuple or not snapshot.claims or len(snapshot.claims) > _MAX_CLAIMS:
        _fail()
    claim_ids: set[str] = set()
    evidence_ids: set[str] = set()
    for claim in snapshot.claims:
        if type(claim) is not GraphClaimSnapshot:
            _fail()
        identifier = _opaque(claim.identifier, _CLAIM)
        source = _opaque(claim.source_node_ref, _NODE)
        target = _opaque(claim.target_node_ref, _NODE)
        evidence = _opaque(claim.evidence_binding_ref, _EVIDENCE)
        if (identifier in claim_ids or evidence in evidence_ids or type(claim.relation) is not str
                or claim.relation not in _RELATIONS or source == target or source not in kinds or target not in kinds
                or (kinds[source], kinds[target]) != _ENDPOINTS[claim.relation]):
            _fail()
        claim_ids.add(identifier)
        evidence_ids.add(evidence)
    return snapshot


def _effective_people(snapshot: GraphSnapshot, decisions: tuple[tuple[str, str], ...],
                      actions: tuple[GraphIdentityMerge | GraphIdentitySplit, ...]) -> tuple[dict[tuple[str, str], str], set[str]]:
    """Fold validated overlays without ever changing the immutable snapshot."""
    kinds = {node.identifier: node.kind for node in snapshot.nodes}
    endpoints = {(claim.identifier, endpoint): getattr(claim, f"{endpoint}_node_ref")
                 for claim in snapshot.claims for endpoint in ("source", "target")
                 if kinds[getattr(claim, f"{endpoint}_node_ref")] == "person"}
    active = {node.identifier for node in snapshot.nodes if node.kind == "person"}
    rejected = {claim for claim, decision in decisions if decision == "REJECT"}
    claims = {claim.identifier: claim for claim in snapshot.claims}
    for action in actions:
        if type(action) is GraphIdentityMerge:
            for key, person in tuple(endpoints.items()):
                if person in action.member_person_refs:
                    endpoints[key] = action.canonical_person_ref
            active.difference_update(action.member_person_refs)
            active.add(action.canonical_person_ref)
        else:
            for assignment in action.endpoint_assignments:
                endpoints[(assignment.claim_ref, assignment.endpoint)] = assignment.replacement_person_ref
            active.remove(action.source_person_ref)
            active.update(action.replacement_person_refs)
        for claim in claims.values():
            if claim.identifier in rejected or _ENDPOINTS[claim.relation] != ("person", "person"):
                continue
            source = endpoints[(claim.identifier, "source")]
            target = endpoints[(claim.identifier, "target")]
            if source == target:
                _fail()
    return endpoints, active


def _conflicts(snapshot: GraphSnapshot, decisions: tuple[tuple[str, str], ...],
               actions: tuple[GraphIdentityMerge | GraphIdentitySplit, ...]) -> tuple[tuple[str, int, int], ...]:
    """Aggregate-only, unresolved conflict prompts recalculated after overlays."""
    endpoints, _ = _effective_people(snapshot, decisions, actions)
    decision_by_claim = dict(decisions)
    groups: dict[str, dict[str, set[str]]] = {"works_at": {}, "assigned_to": {}}
    for claim in snapshot.claims:
        if decision_by_claim.get(claim.identifier) != "ACCEPT" or claim.relation not in groups:
            continue
        source = endpoints.get((claim.identifier, "source"), claim.source_node_ref)
        target = endpoints.get((claim.identifier, "target"), claim.target_node_ref)
        subject, object_ = (source, target) if claim.relation == "works_at" else (target, source)
        groups[claim.relation].setdefault(subject, set()).add(object_)
    result: list[tuple[str, int, int]] = []
    for relation, label in (("works_at", "POTENTIAL_MULTIPLE_WORKS_AT"),
                            ("assigned_to", "POTENTIAL_MULTIPLE_ASSIGNED_TO")):
        affected = [objects for objects in groups[relation].values() if len(objects) > 1]
        if affected:
            result.append((label, len(affected), sum(len(objects) for objects in affected)))
    return tuple(result)


def _validate_merge(action: object, snapshot: GraphSnapshot, decisions: tuple[tuple[str, str], ...],
                    existing: tuple[GraphIdentityMerge | GraphIdentitySplit, ...]) -> GraphIdentityMerge:
    if type(action) is not GraphIdentityMerge:
        _fail()
    canonical = _opaque(action.canonical_person_ref, _NODE)
    members = action.member_person_refs
    kinds = {node.identifier: node.kind for node in snapshot.nodes}
    _, active = _effective_people(snapshot, decisions, existing)
    if (type(members) is not tuple or len(members) != 2 or any(type(member) is not str for member in members)
            or len(set(members)) != 2 or canonical not in members
            or any(_opaque(member, _NODE) not in active or kinds.get(member) != "person" for member in members)):
        _fail()
    candidate = GraphIdentityMerge(canonical, members)
    _effective_people(snapshot, decisions, existing + (candidate,))
    return candidate


def _validate_split(action: object, snapshot: GraphSnapshot, decisions: tuple[tuple[str, str], ...],
                    existing: tuple[GraphIdentityMerge | GraphIdentitySplit, ...]) -> GraphIdentitySplit:
    if type(action) is not GraphIdentitySplit:
        _fail()
    source = _opaque(action.source_person_ref, _NODE)
    children = action.replacement_person_refs
    kinds = {node.identifier: node.kind for node in snapshot.nodes}
    endpoints, active = _effective_people(snapshot, decisions, existing)
    if (source not in active or kinds.get(source) != "person" or type(children) is not tuple or len(children) < 2
            or any(type(child) is not str for child in children) or len(set(children)) != len(children)
            or source in children or any(_opaque(child, _NODE) not in active or kinds.get(child) != "person" for child in children)):
        _fail()
    if type(action.endpoint_assignments) is not tuple:
        _fail()
    assignments: dict[tuple[str, str], str] = {}
    for item in action.endpoint_assignments:
        if type(item) is not GraphSplitEndpointAssignment:
            _fail()
        claim = _opaque(item.claim_ref, _CLAIM)
        replacement = _opaque(item.replacement_person_ref, _NODE)
        if type(item.endpoint) is not str or item.endpoint not in {"source", "target"} or replacement not in children:
            _fail()
        key = (claim, item.endpoint)
        if key in assignments:
            _fail()
        assignments[key] = replacement
    rejected = {claim for claim, decision in decisions if decision == "REJECT"}
    required = {key for key, person in endpoints.items() if person == source and key[0] not in rejected}
    if set(assignments) != required:
        _fail()
    candidate = GraphIdentitySplit(source, children, action.endpoint_assignments)
    _effective_people(snapshot, decisions, existing + (candidate,))
    return candidate


class RevisionedGraphReviewStore:
    """Trusted-server in-process store with tenant/snapshot tuple isolation.

    Tenant and reviewer values must come from a prior authenticated server
    principal.  This class does not authenticate, authorize, or make a
    cross-tenant security guarantee from caller-supplied opaque strings.
    """

    def __init__(self) -> None:
        self._lock = RLock()
        self._states: dict[tuple[str, str], _GraphReviewState] = {}

    def create_snapshot(self, snapshot: GraphSnapshot) -> GraphReviewView:
        """Register a trusted-server-created immutable snapshot once per tuple."""
        snapshot = _validate_snapshot(snapshot)
        key = (snapshot.tenant_ref, snapshot.snapshot_ref)
        with self._lock:
            if key in self._states:
                _fail()
            state = _GraphReviewState(snapshot=snapshot, revision=0, decisions=(), audit=(),
                                      identity_actions=(), identity_audit=())
            self._states[key] = state
            return _view(state)

    def read(self, *, tenant_ref: object, snapshot_ref: object) -> GraphReviewView:
        tenant = _opaque(tenant_ref, _TENANT)
        reference = _opaque(snapshot_ref, _SNAPSHOT)
        with self._lock:
            state = self._states.get((tenant, reference))
            if state is None:
                _fail()
            return _view(state)

    def decide(self, *, tenant_ref: object, snapshot_ref: object, claim_ref: object,
               expected_revision: object, decision: object, reviewer_ref: object) -> GraphReviewView:
        tenant = _opaque(tenant_ref, _TENANT)
        reference = _opaque(snapshot_ref, _SNAPSHOT)
        claim = _opaque(claim_ref, _CLAIM)
        reviewer = _opaque(reviewer_ref, _REVIEWER)
        if type(expected_revision) is not int or isinstance(expected_revision, bool) or expected_revision < 0:
            _fail()
        if type(decision) is not str or decision not in {"ACCEPT", "REJECT"}:
            _fail()
        with self._lock:
            state = self._states.get((tenant, reference))
            if state is None or claim not in {item.identifier for item in state.snapshot.claims}:
                _fail()
            if expected_revision != state.revision:
                raise GraphReviewConflict()
            if claim in dict(state.decisions) or len(state.audit) + len(state.identity_audit) >= _MAX_AUDIT_EVENTS:
                _fail()
            revision = state.revision + 1
            event = GraphReviewAuditEvent(len(state.audit) + len(state.identity_audit) + 1,
                                          revision, claim, decision, reviewer)
            result = _GraphReviewState(snapshot=state.snapshot, revision=revision,
                                       decisions=state.decisions + ((claim, decision),), audit=state.audit + (event,),
                                       identity_actions=state.identity_actions, identity_audit=state.identity_audit)
            self._states[(tenant, reference)] = result
            return _view(result)

    def merge_identities(self, *, tenant_ref: object, snapshot_ref: object, merge: object,
                         expected_revision: object, reviewer_ref: object) -> GraphReviewView:
        """Append a two-current-person merge without mutating claims or evidence."""
        tenant = _opaque(tenant_ref, _TENANT)
        reference = _opaque(snapshot_ref, _SNAPSHOT)
        reviewer = _opaque(reviewer_ref, _REVIEWER)
        if type(expected_revision) is not int or isinstance(expected_revision, bool) or expected_revision < 0:
            _fail()
        with self._lock:
            state = self._states.get((tenant, reference))
            if state is None:
                _fail()
            if expected_revision != state.revision:
                raise GraphReviewConflict()
            if len(state.audit) + len(state.identity_audit) >= _MAX_AUDIT_EVENTS:
                _fail()
            action = _validate_merge(merge, state.snapshot, state.decisions, state.identity_actions)
            revision = state.revision + 1
            event = GraphIdentityAuditEvent(len(state.audit) + len(state.identity_audit) + 1, revision, "MERGE", reviewer)
            result = _GraphReviewState(state.snapshot, revision, state.decisions, state.audit,
                                       state.identity_actions + (action,), state.identity_audit + (event,))
            self._states[(tenant, reference)] = result
            return _view(result)

    def split_identity(self, *, tenant_ref: object, snapshot_ref: object, split: object,
                       expected_revision: object, reviewer_ref: object) -> GraphReviewView:
        """Append an exhaustive endpoint-level split without mutating claims or evidence."""
        tenant = _opaque(tenant_ref, _TENANT)
        reference = _opaque(snapshot_ref, _SNAPSHOT)
        reviewer = _opaque(reviewer_ref, _REVIEWER)
        if type(expected_revision) is not int or isinstance(expected_revision, bool) or expected_revision < 0:
            _fail()
        with self._lock:
            state = self._states.get((tenant, reference))
            if state is None:
                _fail()
            if expected_revision != state.revision:
                raise GraphReviewConflict()
            if len(state.audit) + len(state.identity_audit) >= _MAX_AUDIT_EVENTS:
                _fail()
            action = _validate_split(split, state.snapshot, state.decisions, state.identity_actions)
            revision = state.revision + 1
            event = GraphIdentityAuditEvent(len(state.audit) + len(state.identity_audit) + 1, revision, "SPLIT", reviewer)
            result = _GraphReviewState(state.snapshot, revision, state.decisions, state.audit,
                                       state.identity_actions + (action,), state.identity_audit + (event,))
            self._states[(tenant, reference)] = result
            return _view(result)
