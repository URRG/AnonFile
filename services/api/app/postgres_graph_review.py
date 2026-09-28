"""Shared PostgreSQL journal for trusted-server, source-free D06 graph review.

This adapter is intentionally not mounted on an HTTP route. It has no external
audit anchor, release authority, or permission to ingest original documents.
Every write locks its immutable snapshot row, verifies and replays the complete
bounded event chain, then appends one event in the same transaction.
"""
from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
import hashlib
import json
from typing import Any

from app.durable_graph_review import _apply, _events, _load, _public, _snapshot_dict
from app.revisioned_graph_review import (GraphConflictResolution, GraphIdentityMerge,
    GraphIdentitySplit, GraphReviewConflict, GraphReviewError, GraphSnapshot, RevisionedGraphReviewStore)


class PostgresGraphReviewError(RuntimeError):
    def __init__(self) -> None:
        super().__init__("PostgreSQL graph review unavailable")


def _fail() -> None:
    raise PostgresGraphReviewError() from None


def _canonical(value: object, maximum: int) -> bytes:
    try:
        data = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (TypeError, ValueError, UnicodeError, OverflowError, RecursionError):
        _fail()
    if len(data) > maximum:
        _fail()
    return data


def _digest(domain: bytes, value: object, maximum: int) -> str:
    return "sha256:" + hashlib.sha256(domain + _canonical(value, maximum)).hexdigest()


def _event_digest(tenant: str, snapshot: str, previous: str, action: dict[str, Any]) -> str:
    return _digest(b"anonflow-graph-review-event-v1:\x00",
                   [tenant, snapshot, previous, action], 8192)


def _row(cursor: Any) -> tuple[Any, ...] | None:
    result = cursor.fetchone()
    if result is not None and type(result) is not tuple:
        _fail()
    return result


def _json_object(value: object, maximum: int) -> dict[str, Any]:
    if type(value) is str:
        try:
            value = json.loads(value)
        except (ValueError, UnicodeError):
            _fail()
    if type(value) is not dict:
        _fail()
    _canonical(value, maximum)
    return value


class PostgresGraphReviewAdapter:
    """Standalone shared-state primitive; callers must authenticate reviewers."""

    def __init__(self, connection_factory: Callable[[], Any]) -> None:
        if not callable(connection_factory):
            _fail()
        self._connection_factory = connection_factory

    def _connect(self) -> Any:
        connection = self._connection_factory()
        if connection is None or getattr(connection, "autocommit", None) is not True:
            _fail()
        return connection

    @staticmethod
    def _close(connection: Any) -> None:
        try:
            connection.close()
        except Exception:
            pass

    @staticmethod
    def _rollback(connection: Any) -> None:
        try:
            connection.rollback()
        except Exception:
            pass

    @staticmethod
    def _isolation(cursor: Any) -> None:
        cursor.execute("SHOW transaction_isolation")
        if _row(cursor) != ("read committed",):
            _fail()

    @staticmethod
    def _state(cursor: Any, tenant: str, snapshot: str, *, lock: bool) -> tuple[RevisionedGraphReviewStore, str]:
        suffix = " FOR UPDATE" if lock else ""
        cursor.execute("SELECT snapshot,snapshot_digest,expires_at FROM anonflow_graph_review_snapshots "
                       "WHERE tenant_ref=%s AND snapshot_ref=%s" + suffix, (tenant, snapshot))
        parent = _row(cursor)
        if parent is None or len(parent) != 3:
            _fail()
        document, stored_digest, expiry = parent
        document = _json_object(document, 131072)
        if (set(document) != {"tenant", "snapshot", "nodes", "claims"}
                or document.get("tenant") != tenant or document.get("snapshot") != snapshot
                or type(stored_digest) is not str
                or _digest(b"anonflow-graph-review-snapshot-v1:\x00", document, 131072) != stored_digest
                or type(expiry) is not datetime or expiry.tzinfo is None):
            _fail()
        cursor.execute("SELECT clock_timestamp()")
        now = _row(cursor)
        if now is None or len(now) != 1 or type(now[0]) is not datetime or expiry <= now[0]:
            _fail()
        cursor.execute("SELECT revision,action,previous_digest,event_digest FROM anonflow_graph_review_events "
                       "WHERE tenant_ref=%s AND snapshot_ref=%s ORDER BY revision", (tenant, snapshot))
        rows = cursor.fetchall()
        if type(rows) is not list or len(rows) > 200:
            _fail()
        events: list[dict[str, Any]] = []
        head = stored_digest
        for number, row in enumerate(rows, 1):
            if type(row) is not tuple or len(row) != 4:
                _fail()
            revision, action, previous, digest = row
            action = _json_object(action, 8192)
            if (type(revision) is not int or revision != number or action.get("revision") != number
                    or previous != head or digest != _event_digest(tenant, snapshot, head, action)):
                _fail()
            head = digest
            events.append(action)
        try:
            engine = _load({"payload": {"snapshot": document, "events": events}})
        except Exception:
            _fail()
        return engine, head

    def create_snapshot(self, snapshot: GraphSnapshot) -> None:
        if type(snapshot) is not GraphSnapshot:
            _fail()
        try:
            state = RevisionedGraphReviewStore()
            state.create_snapshot(snapshot)
            document = _snapshot_dict(snapshot)
            digest = _digest(b"anonflow-graph-review-snapshot-v1:\x00", document, 131072)
        except GraphReviewError:
            _fail()
        connection = None
        try:
            connection = self._connect()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            self._isolation(cursor)
            cursor.execute("INSERT INTO anonflow_graph_review_snapshots "
                           "(tenant_ref,snapshot_ref,snapshot,snapshot_digest,expires_at) "
                           "VALUES (%s,%s,%s::jsonb,%s,clock_timestamp() + interval '1 hour')",
                           (snapshot.tenant_ref, snapshot.snapshot_ref, _canonical(document, 131072).decode(), digest))
            connection.commit()
        except PostgresGraphReviewError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)

    def read(self, *, tenant_ref: str, snapshot_ref: str) -> dict[str, Any]:
        connection = None
        try:
            connection = self._connect()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            self._isolation(cursor)
            state, _ = self._state(cursor, tenant_ref, snapshot_ref, lock=False)
            result = _public(state)
            connection.commit()
            return result
        except PostgresGraphReviewError:
            if connection is not None:
                self._rollback(connection)
            raise
        except Exception:
            if connection is not None:
                self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)

    def _append(self, *, tenant_ref: str, snapshot_ref: str, expected_revision: int,
                reviewer_ref: str, event: dict[str, Any]) -> dict[str, Any]:
        connection = None
        try:
            connection = self._connect()
            cursor = connection.cursor()
            cursor.execute("BEGIN")
            self._isolation(cursor)
            state, head = self._state(cursor, tenant_ref, snapshot_ref, lock=True)
            _apply(state, event, tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                   expected_revision=expected_revision, reviewer_ref=reviewer_ref)
            actions = _events(state)
            if len(actions) != expected_revision + 1:
                _fail()
            action = actions[-1]
            digest = _event_digest(tenant_ref, snapshot_ref, head, action)
            cursor.execute("INSERT INTO anonflow_graph_review_events "
                           "(tenant_ref,snapshot_ref,revision,action,previous_digest,event_digest) "
                           "VALUES (%s,%s,%s,%s::jsonb,%s,%s)",
                           (tenant_ref, snapshot_ref, action["revision"],
                            _canonical(action, 8192).decode(), head, digest))
            result = _public(state)
            connection.commit()
            return result
        except GraphReviewConflict:
            if connection is not None:
                self._rollback(connection)
            raise
        except (GraphReviewError, PostgresGraphReviewError):
            if connection is not None:
                self._rollback(connection)
            _fail()
        except Exception:
            if connection is not None:
                self._rollback(connection)
            _fail()
        finally:
            if connection is not None:
                self._close(connection)

    def decide(self, *, tenant_ref: str, snapshot_ref: str, claim_ref: str,
               expected_revision: int, decision: str, reviewer_ref: str) -> dict[str, Any]:
        return self._append(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                            expected_revision=expected_revision, reviewer_ref=reviewer_ref,
                            event={"type": "decision", "claim": claim_ref, "decision": decision})

    def merge_identities(self, *, tenant_ref: str, snapshot_ref: str, merge: GraphIdentityMerge,
                         expected_revision: int, reviewer_ref: str) -> dict[str, Any]:
        return self._append(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                            expected_revision=expected_revision, reviewer_ref=reviewer_ref,
                            event={"type": "merge", "canonical": merge.canonical_person_ref,
                                   "members": list(merge.member_person_refs)})

    def split_identity(self, *, tenant_ref: str, snapshot_ref: str, split: GraphIdentitySplit,
                       expected_revision: int, reviewer_ref: str) -> dict[str, Any]:
        return self._append(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                            expected_revision=expected_revision, reviewer_ref=reviewer_ref,
                            event={"type": "split", "source": split.source_person_ref,
                                   "replacements": list(split.replacement_person_refs),
                                   "assignments": [{"claim": item.claim_ref, "endpoint": item.endpoint,
                                                    "replacement": item.replacement_person_ref}
                                                   for item in split.endpoint_assignments]})

    def resolve_conflict(self, *, tenant_ref: str, snapshot_ref: str, resolution: GraphConflictResolution,
                         expected_revision: int, reviewer_ref: str) -> dict[str, Any]:
        return self._append(tenant_ref=tenant_ref, snapshot_ref=snapshot_ref,
                            expected_revision=expected_revision, reviewer_ref=reviewer_ref,
                            event={"type": "conflict_resolution", "kind": resolution.kind,
                                   "subject": resolution.subject_ref, "claims": list(resolution.claim_refs),
                                   "disposition": resolution.disposition})
