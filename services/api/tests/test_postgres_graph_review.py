"""D06 shared journal tests; real PostgreSQL runs with ANONFLOW_POSTGRES_TEST_DSN."""
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
import uuid
from threading import Barrier

import pytest

from app.postgres_graph_review import (PostgresGraphReviewAdapter, PostgresGraphReviewError,
                                       _canonical, _digest, _event_digest)
from app.durable_graph_review import _snapshot_dict
from app.revisioned_graph_review import (GraphClaimSnapshot, GraphIdentityMerge, GraphNodeSnapshot,
                                         GraphReviewConflict, GraphSnapshot)


def ref(kind: str, seed: str) -> str:
    return f"{kind}:v1:" + base64.urlsafe_b64encode(hashlib.sha256(seed.encode()).digest()).decode().rstrip("=")


def snapshot(seed: str) -> GraphSnapshot:
    tenant = ref("tenantref", seed)
    first, second, org = (ref("graphnode", seed + part) for part in ("first", "second", "org"))
    claim = ref("graphclaim", seed + "claim")
    return GraphSnapshot(tenant, ref("graphsnap", seed),
        (GraphNodeSnapshot(first, "person"), GraphNodeSnapshot(second, "person"),
         GraphNodeSnapshot(org, "organization")),
        (GraphClaimSnapshot(claim, "works_at", first, org, ref("graphevidence", seed + "evidence")),))


def test_canonical_is_bounded_and_digest_is_scope_sensitive():
    with pytest.raises(PostgresGraphReviewError):
        _canonical({"source": "x" * 100}, 10)
    action = {"type": "decision", "claim": "opaque", "decision": "ACCEPT", "revision": 1, "reviewer": "opaque"}
    assert _event_digest("tenant-a", "snapshot-a", "sha256:" + "0" * 64, action) != _event_digest(
        "tenant-b", "snapshot-a", "sha256:" + "0" * 64, action)
    assert _digest(b"domain-a", action, 8192) != _digest(b"domain-b", action, 8192)


def test_connection_must_be_autocommit():
    class Connection:
        autocommit = False
    with pytest.raises(PostgresGraphReviewError):
        PostgresGraphReviewAdapter(lambda: Connection()).read(tenant_ref="x", snapshot_ref="y")


def test_source_free_replay_verifies_scope_revision_and_chain_without_database():
    item = snapshot("replay")
    document = _snapshot_dict(item)
    parent_digest = _digest(b"anonflow-graph-review-snapshot-v1:\x00", document, 131072)
    action = {"type": "decision", "claim": item.claims[0].identifier,
              "decision": "ACCEPT", "revision": 1, "reviewer": ref("reviewerref", "reviewer")}
    event_digest = _event_digest(item.tenant_ref, item.snapshot_ref, parent_digest, action)

    class Cursor:
        def __init__(self, rows):
            self.rows = rows
            self.query = ""

        def execute(self, query, parameters=None):
            self.query = query

        def fetchone(self):
            if self.query.startswith("SELECT snapshot,"):
                return document, parent_digest, datetime.now(UTC) + timedelta(hours=1)
            if self.query == "SELECT clock_timestamp()":
                return (datetime.now(UTC),)
            raise AssertionError(self.query)

        def fetchall(self):
            assert self.query.startswith("SELECT revision,action,")
            return self.rows

    valid = [(1, action, parent_digest, event_digest)]
    state, head = PostgresGraphReviewAdapter._state(Cursor(valid), item.tenant_ref,
                                                     item.snapshot_ref, lock=True)
    assert head == event_digest and state.read(tenant_ref=item.tenant_ref,
                                                snapshot_ref=item.snapshot_ref).revision == 1
    for corrupt in ([(2, action, parent_digest, event_digest)],
                    [(1, action, "sha256:" + "0" * 64, event_digest)],
                    [(1, {**action, "decision": "REJECT"}, parent_digest, event_digest)]):
        with pytest.raises(PostgresGraphReviewError):
            PostgresGraphReviewAdapter._state(Cursor(corrupt), item.tenant_ref,
                                              item.snapshot_ref, lock=True)


@pytest.fixture
def postgres_graph_review():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN for live PostgreSQL graph journal test")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "020_d06_graph_review.sql"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(migration.read_text())
        connection.execute(migration.read_text())
    return dsn, psycopg


def test_postgres_cross_instance_cas_replay_isolation_and_immutability(postgres_graph_review):
    dsn, psycopg = postgres_graph_review
    item = snapshot(uuid.uuid4().hex)
    connect = lambda: psycopg.connect(dsn, autocommit=True)
    one, two = PostgresGraphReviewAdapter(connect), PostgresGraphReviewAdapter(connect)
    one.create_snapshot(item)
    first = one.read(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref)
    assert first["revision"] == 0 and "graphevidence" not in json.dumps(first)
    with pytest.raises(PostgresGraphReviewError):
        two.read(tenant_ref=ref("tenantref", "other"), snapshot_ref=item.snapshot_ref)
    updated = one.decide(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref,
                         claim_ref=item.claims[0].identifier, expected_revision=0,
                         decision="ACCEPT", reviewer_ref=ref("reviewerref", "reviewer"))
    assert updated["revision"] == 1
    assert two.read(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref) == updated
    with pytest.raises(GraphReviewConflict):
        two.merge_identities(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref,
                             merge=GraphIdentityMerge(item.nodes[0].identifier,
                                                       (item.nodes[0].identifier, item.nodes[1].identifier)),
                             expected_revision=0, reviewer_ref=ref("reviewerref", "reviewer"))
    assert one.read(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref)["revision"] == 1
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("DELETE FROM anonflow_graph_review_events WHERE tenant_ref=%s AND snapshot_ref=%s",
                               (item.tenant_ref, item.snapshot_ref))
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute("UPDATE anonflow_graph_review_snapshots SET expires_at=%s "
                               "WHERE tenant_ref=%s AND snapshot_ref=%s",
                               (datetime.now(UTC) + timedelta(hours=2), item.tenant_ref, item.snapshot_ref))


def test_postgres_two_host_simultaneous_decisions_have_one_winner(postgres_graph_review):
    dsn, psycopg = postgres_graph_review
    item = snapshot(uuid.uuid4().hex)
    connect = lambda: psycopg.connect(dsn, autocommit=True)
    PostgresGraphReviewAdapter(connect).create_snapshot(item)
    start = Barrier(2)

    def decide(decision: str) -> str:
        service = PostgresGraphReviewAdapter(connect)
        start.wait(timeout=5)
        try:
            service.decide(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref,
                           claim_ref=item.claims[0].identifier, expected_revision=0,
                           decision=decision, reviewer_ref=ref("reviewerref", decision))
            return "committed"
        except GraphReviewConflict:
            return "stale"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(decide, ("ACCEPT", "REJECT")))
    assert sorted(results) == ["committed", "stale"]
    assert PostgresGraphReviewAdapter(connect).read(tenant_ref=item.tenant_ref,
                                                     snapshot_ref=item.snapshot_ref)["revision"] == 1


def test_postgres_rejects_corrupt_chain_and_rolls_back(postgres_graph_review):
    dsn, psycopg = postgres_graph_review
    item = snapshot(uuid.uuid4().hex)
    service = PostgresGraphReviewAdapter(lambda: psycopg.connect(dsn, autocommit=True))
    service.create_snapshot(item)
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.errors.RaiseException):
            connection.execute(
                "INSERT INTO anonflow_graph_review_events "
                "(tenant_ref,snapshot_ref,revision,action,previous_digest,event_digest) "
                "VALUES (%s,%s,2,%s::jsonb,%s,%s)",
                (item.tenant_ref, item.snapshot_ref, '{}', 'sha256:' + '0' * 64, 'sha256:' + '1' * 64))
    assert service.read(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref)["revision"] == 0
    with psycopg.connect(dsn, autocommit=True) as connection:
        parent_digest = connection.execute(
            "SELECT snapshot_digest FROM anonflow_graph_review_snapshots WHERE tenant_ref=%s AND snapshot_ref=%s",
            (item.tenant_ref, item.snapshot_ref)).fetchone()[0]
        action = {"type": "decision", "claim": item.claims[0].identifier,
                  "decision": "ACCEPT", "revision": 1, "reviewer": ref("reviewerref", "reviewer")}
        connection.execute(
            "INSERT INTO anonflow_graph_review_events "
            "(tenant_ref,snapshot_ref,revision,action,previous_digest,event_digest) "
            "VALUES (%s,%s,1,%s::jsonb,%s,%s)",
            (item.tenant_ref, item.snapshot_ref, json.dumps(action), parent_digest, 'sha256:' + '0' * 64))
    with pytest.raises(PostgresGraphReviewError):
        service.read(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref)
    with pytest.raises(PostgresGraphReviewError):
        service.decide(tenant_ref=item.tenant_ref, snapshot_ref=item.snapshot_ref,
                       claim_ref=item.claims[0].identifier, expected_revision=0,
                       decision="ACCEPT", reviewer_ref=ref("reviewerref", "reviewer"))
