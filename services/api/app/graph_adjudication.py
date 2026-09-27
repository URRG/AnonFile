"""Pure, ephemeral graph-review adjudication for synthetic fixtures only.

This module intentionally has no API route, storage, source text, or release
authority.  It validates opaque review inputs and returns an aggregate-only
summary so callers cannot turn a transient review exercise into durable graph
state or a release decision.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
import re
from typing import Literal

_RELATIONS = frozenset({"assistant_to", "assistant_for", "works_at", "client_of", "works_on", "assigned_to", "sent_to"})
_NODE_ID = re.compile(r"^(?:E[1-9][0-9]{0,5}|organization_[1-9][0-9]{0,5}|project_[1-9][0-9]{0,5})$")
_CLAIM_ID = re.compile(r"^claim_[1-9][0-9]{0,5}$")
_DOCUMENT_ID = re.compile(r"^doc_[1-9][0-9]{0,5}$")
_KIND = frozenset({"person", "organization", "project"})
_ENDPOINTS = {
    "assistant_to": ("person", "person"), "sent_to": ("person", "person"),
    "assistant_for": ("person", "organization"), "works_at": ("person", "organization"),
    "client_of": ("person", "organization"), "works_on": ("person", "project"),
    "assigned_to": ("project", "person"),
}
_MAX_NODES = 100
_MAX_CLAIMS = 200


class GraphAdjudicationError(ValueError):
    """Fixed error that never reflects a submitted identifier or source value."""


def _reject() -> None:
    raise GraphAdjudicationError("Invalid ephemeral graph adjudication input.")


@dataclass(frozen=True)
class GraphNode:
    identifier: str
    kind: Literal["person", "organization", "project"]


@dataclass(frozen=True)
class GraphClaim:
    identifier: str
    relation: str
    source_id: str
    target_id: str
    evidence_document_id: str


@dataclass(frozen=True)
class ReviewDecision:
    claim_id: str
    decision: Literal["ACCEPT", "REJECT"]


@dataclass(frozen=True)
class IdentityMerge:
    canonical_person_id: str
    member_person_ids: tuple[str, ...]


@dataclass(frozen=True)
class IdentitySplit:
    source_person_id: str
    replacement_person_ids: tuple[str, ...]
    claim_assignments: tuple[tuple[str, str], ...]


def _validate_nodes(nodes: tuple[GraphNode, ...]) -> dict[str, str]:
    if type(nodes) is not tuple or not nodes or len(nodes) > _MAX_NODES:
        _reject()
    result: dict[str, str] = {}
    for node in nodes:
        if (type(node) is not GraphNode or not isinstance(node.identifier, str)
                or not _NODE_ID.fullmatch(node.identifier) or not isinstance(node.kind, str) or node.kind not in _KIND
                or node.identifier in result):
            _reject()
        prefix_kind = "person" if node.identifier.startswith("E") else node.identifier.split("_", 1)[0]
        if prefix_kind != node.kind:
            _reject()
        result[node.identifier] = node.kind
    return result


def _validate_claims(claims: tuple[GraphClaim, ...], nodes: dict[str, str]) -> dict[str, GraphClaim]:
    if type(claims) is not tuple or not claims or len(claims) > _MAX_CLAIMS:
        _reject()
    result: dict[str, GraphClaim] = {}
    for claim in claims:
        if (type(claim) is not GraphClaim or not isinstance(claim.identifier, str)
                or not _CLAIM_ID.fullmatch(claim.identifier) or claim.identifier in result
                or not isinstance(claim.relation, str) or claim.relation not in _RELATIONS or not isinstance(claim.source_id, str)
                or not isinstance(claim.target_id, str) or not isinstance(claim.evidence_document_id, str)
                or not _DOCUMENT_ID.fullmatch(claim.evidence_document_id)
                or claim.source_id not in nodes or claim.target_id not in nodes or claim.source_id == claim.target_id
                or (nodes[claim.source_id], nodes[claim.target_id]) != _ENDPOINTS[claim.relation]):
            _reject()
        result[claim.identifier] = claim
    return result


def _validate_decisions(decisions: tuple[ReviewDecision, ...], claims: dict[str, GraphClaim]) -> dict[str, str]:
    if type(decisions) is not tuple or len(decisions) > len(claims):
        _reject()
    result: dict[str, str] = {}
    for item in decisions:
        if (type(item) is not ReviewDecision or not isinstance(item.claim_id, str) or item.claim_id not in claims
                or not isinstance(item.decision, str) or item.decision not in {"ACCEPT", "REJECT"} or item.claim_id in result):
            _reject()
        result[item.claim_id] = item.decision
    return result


def _identity_map(merges: tuple[IdentityMerge, ...], nodes: dict[str, str]) -> tuple[dict[str, str], frozenset[str]]:
    if type(merges) is not tuple or len(merges) > len(nodes):
        _reject()
    aliases = {identifier: identifier for identifier in nodes}
    seen: set[str] = set()
    for merge in merges:
        if type(merge) is not IdentityMerge:
            _reject()
        members = merge.member_person_ids
        if (not isinstance(merge.canonical_person_id, str) or merge.canonical_person_id not in nodes
                or nodes[merge.canonical_person_id] != "person" or type(members) is not tuple
                or len(members) < 2 or not all(isinstance(member, str) for member in members)
                or len(set(members)) != len(members)
                or merge.canonical_person_id not in members or any(member not in nodes or nodes[member] != "person" for member in members)
                or seen.intersection(members)):
            _reject()
        seen.update(members)
        for member in members:
            aliases[member] = merge.canonical_person_id
    return aliases, frozenset(seen)


def _apply_splits(splits: tuple[IdentitySplit, ...], claims: dict[str, GraphClaim], nodes: dict[str, str],
                  decisions: dict[str, str], aliases: dict[str, str], merged_people: frozenset[str]) -> tuple[dict[str, str], int]:
    if type(splits) is not tuple or len(splits) > len(nodes):
        _reject()
    replacements: dict[str, str] = {}
    assigned_claims: set[str] = set()
    affected_count = 0
    for split in splits:
        if (type(split) is not IdentitySplit or not isinstance(split.source_person_id, str)
                or split.source_person_id not in nodes or nodes[split.source_person_id] != "person"):
            _reject()
        children = split.replacement_person_ids
        if (type(children) is not tuple or len(children) < 2 or not all(isinstance(child, str) for child in children)
                or len(set(children)) != len(children)
                or split.source_person_id in children or any(child not in nodes or nodes[child] != "person" for child in children)
                or split.source_person_id in replacements or aliases[split.source_person_id] != split.source_person_id
                or split.source_person_id in merged_people or any(child in merged_people for child in children)):
            _reject()
        affected = {identifier for identifier, claim in claims.items()
                    if decisions.get(identifier) != "REJECT" and split.source_person_id in {claim.source_id, claim.target_id}}
        if type(split.claim_assignments) is not tuple:
            _reject()
        pairs = split.claim_assignments
        if any(type(pair) is not tuple or len(pair) != 2 or not isinstance(pair[0], str) or not isinstance(pair[1], str)
               for pair in pairs):
            _reject()
        assignments = dict(pairs)
        if (len(assignments) != len(pairs)
                or set(assignments) != affected or any(target not in children for target in assignments.values())):
            _reject()
        # One assignment selects one replacement *endpoint*.  A person-person
        # claim incident to two separately split identities would need two
        # endpoint assignments, so accepting a single claim key here would
        # silently overwrite one of them.  Require a future explicit endpoint
        # schema rather than guessing.
        if assigned_claims.intersection(assignments):
            _reject()
        assigned_claims.update(assignments)
        replacements.update(assignments)
        affected_count += len(affected)
    return replacements, affected_count


def adjudicate(*, nodes: tuple[GraphNode, ...], claims: tuple[GraphClaim, ...],
               decisions: tuple[ReviewDecision, ...] = (), merges: tuple[IdentityMerge, ...] = (),
               splits: tuple[IdentitySplit, ...] = ()) -> dict[str, object]:
    """Return a source-free summary of bounded, in-memory review actions."""
    try:
        node_kinds = _validate_nodes(nodes)
        claim_by_id = _validate_claims(claims, node_kinds)
        decision_by_claim = _validate_decisions(decisions, claim_by_id)
        aliases, merged_people = _identity_map(merges, node_kinds)
        split_targets, split_claims = _apply_splits(splits, claim_by_id, node_kinds, decision_by_claim, aliases, merged_people)
    except (TypeError, ValueError, KeyError):
        _reject()

    counts = Counter(decision_by_claim.values())
    by_type: dict[str, Counter[str]] = {relation: Counter() for relation in sorted(_RELATIONS)}
    accepted: list[tuple[str, str, str]] = []
    for identifier, claim in claim_by_id.items():
        status = decision_by_claim.get(identifier, "PENDING")
        by_type[claim.relation][status] += 1
        if status != "ACCEPT":
            continue
        source = split_targets.get(identifier, aliases[claim.source_id]) if node_kinds[claim.source_id] == "person" else claim.source_id
        target = split_targets.get(identifier, aliases[claim.target_id]) if node_kinds[claim.target_id] == "person" else claim.target_id
        # A valid pre-review person-to-person claim can collapse to a self-link
        # when its endpoints are merged.  It is no longer a valid typed edge;
        # abstain instead of counting it as accepted.
        if _ENDPOINTS[claim.relation] == ("person", "person") and source == target:
            _reject()
        accepted.append((claim.relation, source, target))

    conflicts: list[dict[str, object]] = []
    for relation, subject_index in (("works_at", 1), ("assigned_to", 1)):
        grouped: dict[str, set[str]] = defaultdict(set)
        for candidate_relation, source, target in accepted:
            if candidate_relation == relation:
                grouped[source if subject_index == 1 else target].add(target if subject_index == 1 else source)
        affected = [objects for objects in grouped.values() if len(objects) > 1]
        if affected:
            conflicts.append({"kind": "POTENTIAL_MULTIPLE_WORKS_AT" if relation == "works_at" else "POTENTIAL_MULTIPLE_ASSIGNED_TO",
                              "status": "UNRESOLVED_REVIEW_REQUIRED", "affected_subjects": len(affected),
                              "accepted_claims": sum(len(objects) for objects in affected)})

    return {
        "schema_version": "ephemeral-graph-adjudication-v1", "state": "EPHEMERAL_STATELESS",
        "release_authorized": False,
        "decisions": {"accepted": counts["ACCEPT"], "rejected": counts["REJECT"], "pending": len(claim_by_id) - len(decision_by_claim)},
        "identity_actions": {"merges": len(merges), "splits": len(splits), "claims_reassigned_by_split": split_claims},
        "relationships": {relation: {"accepted": by_type[relation]["ACCEPT"], "rejected": by_type[relation]["REJECT"], "pending": by_type[relation]["PENDING"]}
                          for relation in sorted(_RELATIONS) if sum(by_type[relation].values())},
        "conflicts": conflicts,
        "limitations": ["Review actions are in-memory only and are discarded after this call.",
                        "This summary contains no source text, document identifiers, node identifiers, or durable correction keys.",
                        "Potential cardinality conflicts require a future durable reviewer decision; they are not resolved automatically.",
                        "This module does not authorize release, delivery, or identity resolution."],
    }
