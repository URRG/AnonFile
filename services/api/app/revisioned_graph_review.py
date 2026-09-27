"""Bounded, source-free D06 graph-review state machine.

This is deliberately a trusted-server domain primitive, not an HTTP contract
or storage adapter.  Only trusted server code may supply its tenant and
reviewer references; their opaque syntax is validation, not authentication or
authorization.  A server creates an immutable graph snapshot whose identifiers
and evidence bindings are opaque.  Reviewers can append one terminal
accept/reject decision per claim only at the revision they read.

It intentionally does not support identity merge or split.  It also does not
make process memory durable: a future repository adapter must atomically retain
the snapshot, current revision, and complete audit stream before this can back
a product route.
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
class _GraphReviewState:
    """Private store state. Evidence bindings must never leave this object."""
    snapshot: GraphSnapshot
    revision: int
    decisions: tuple[tuple[str, Literal["ACCEPT", "REJECT"]], ...]
    audit: tuple[GraphReviewAuditEvent, ...]


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


def _view(state: _GraphReviewState) -> GraphReviewView:
    snapshot = state.snapshot
    return GraphReviewView(
        snapshot=GraphSnapshotView(snapshot.tenant_ref, snapshot.snapshot_ref, snapshot.nodes,
            tuple(GraphClaimView(item.identifier, item.relation, item.source_node_ref, item.target_node_ref)
                  for item in snapshot.claims)),
        revision=state.revision, decisions=state.decisions, audit=state.audit)


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
            state = _GraphReviewState(snapshot=snapshot, revision=0, decisions=(), audit=())
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
            if claim in dict(state.decisions) or len(state.audit) >= _MAX_AUDIT_EVENTS:
                _fail()
            revision = state.revision + 1
            event = GraphReviewAuditEvent(len(state.audit) + 1, revision, claim, decision, reviewer)
            result = _GraphReviewState(snapshot=state.snapshot, revision=revision,
                                       decisions=state.decisions + ((claim, decision),), audit=state.audit + (event,))
            self._states[(tenant, reference)] = result
            return _view(result)
