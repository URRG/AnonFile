"""Tests for the M26 PostgreSQL metadata-only adapter.

The fake exercises transaction boundaries without a service.  The optional
integration test runs automatically in CI (where its DSN is supplied) and is
skipped for ordinary local development.
"""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
from threading import Barrier

import pytest

from app.postgres_metadata import PostgresControlPlaneMetadata, PostgresMetadataError
from app.production_substrate import ControlPlaneMetadata, TenantMetadataTransaction


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


TENANT = opaque("tenantref:v1:")
RECORD = opaque("metarecord:v1:")
OTHER_TENANT = opaque("tenantref:v1:")


def metadata(*, tenant=TENANT, record_id=RECORD, version=1, state="PENDING"):
    return ControlPlaneMetadata(tenant, record_id, "processing_run", version,
                                {"state": state, "sequence": version})


def transaction(*, transaction_id=None, write=None, expected=None):
    write = metadata() if write is None else write
    return TenantMetadataTransaction(write.tenant_ref, transaction_id or opaque("metatx:v1:"),
                                     {write.record_id: write.version - 1} if expected is None else expected,
                                     (write,))


class FakeDatabase:
    def __init__(self):
        self.records = {}
        self.transactions = {}


class FakeConnection:
    def __init__(self, database):
        self.database = database
        self.autocommit = True
        self.records = copy.deepcopy(database.records)
        self.transactions = copy.deepcopy(database.transactions)
        self.committed = self.rolled_back = self.closed = False

    def cursor(self):
        return FakeCursor(self)

    def commit(self):
        self.database.records = self.records
        self.database.transactions = self.transactions
        self.committed = True

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


class FakeCursor:
    def __init__(self, connection):
        self.connection = connection
        self._row = None
        self.rowcount = -1

    def fetchone(self):
        return self._row

    def execute(self, sql, params=()):
        normalized = " ".join(sql.split())
        self._row, self.rowcount = None, -1
        if normalized in {"BEGIN", "BEGIN READ ONLY"}:
            return
        if normalized == "COMMIT":
            self.connection.commit()
            return
        if normalized == "ROLLBACK":
            self.connection.rollback()
            return
        if normalized.startswith("INSERT INTO anonflow_metadata_transactions"):
            tenant, txid, digest = params
            key = (tenant, txid)
            if key in self.connection.transactions:
                self.rowcount = 0
            else:
                self.connection.transactions[key] = (digest, None)
                self._row, self.rowcount = (txid,), 1
        elif normalized.startswith("SELECT request_digest, CASE WHEN octet_length(result_document::text)"):
            current = self.connection.transactions.get((params[1], params[2]))
            self._row = None if current is None else (*current, current[1] is not None)
        elif normalized.startswith("SELECT version FROM anonflow_metadata_records"):
            record = self.connection.records.get((params[0], params[1]))
            self._row = None if record is None else (record[0],)
        elif normalized.startswith("INSERT INTO anonflow_metadata_records"):
            tenant, record_id, version, document = params
            key = (tenant, record_id)
            if key not in self.connection.records:
                self.connection.records[key] = (version, json.loads(document))
                self.rowcount = 1
            else:
                self.rowcount = 0
        elif normalized.startswith("UPDATE anonflow_metadata_records"):
            version, document, tenant, record_id, expected = params
            key = (tenant, record_id)
            current = self.connection.records.get(key)
            if current is not None and current[0] == expected:
                self.connection.records[key] = (version, json.loads(document))
                self.rowcount = 1
            else:
                self.rowcount = 0
        elif normalized.startswith("UPDATE anonflow_metadata_transactions"):
            document, tenant, txid, digest = params
            key = (tenant, txid)
            current = self.connection.transactions.get(key)
            if current is not None and current == (digest, None):
                self.connection.transactions[key] = (digest, json.loads(document))
                self.rowcount = 1
            else:
                self.rowcount = 0
        elif normalized.startswith("SELECT version, CASE WHEN octet_length(document::text)"):
            current = self.connection.records.get((params[1], params[2]))
            self._row = None if current is None else (*current, True)
        else:
            raise AssertionError(normalized)


def fake_adapter(database):
    connections = []

    def connect():
        connection = FakeConnection(database)
        connections.append(connection)
        return connection
    return PostgresControlPlaneMetadata(connect), connections


def test_commit_is_atomic_exact_cas_and_idempotent_with_a_fake_connection():
    database = FakeDatabase()
    adapter, connections = fake_adapter(database)
    first = transaction()

    committed = adapter.commit(first)
    assert committed == first.writes
    assert adapter.read(TENANT, RECORD) == first.writes[0]
    assert adapter.commit(first) == first.writes
    assert len(database.records) == 1
    assert all(connection.committed and connection.closed for connection in connections)

    second_write = metadata(version=2, state="SUCCEEDED")
    assert adapter.commit(transaction(write=second_write)) == (second_write,)
    assert adapter.read(TENANT, RECORD) == second_write


def test_conflicts_and_reused_ids_with_different_requests_fail_closed_and_rollback():
    database = FakeDatabase()
    adapter, connections = fake_adapter(database)
    original = transaction()
    adapter.commit(original)

    with pytest.raises(PostgresMetadataError):
        adapter.commit(transaction(transaction_id=original.transaction_id,
                                   write=metadata(version=2, state="FAILED"), expected={RECORD: 1}))
    with pytest.raises(PostgresMetadataError):
        adapter.commit(transaction(write=metadata(version=2), expected={RECORD: 0}))
    assert database.records[(TENANT, RECORD)][0] == 1
    assert connections[-1].rolled_back and connections[-1].closed


def test_reads_are_tenant_scoped_immutable_and_malformed_rows_fail_closed():
    database = FakeDatabase()
    adapter, _connections = fake_adapter(database)
    adapter.commit(transaction())
    assert adapter.read(OTHER_TENANT, RECORD) is None
    loaded = adapter.read(TENANT, RECORD)
    with pytest.raises(TypeError):
        loaded.attributes["state"] = "FAILED"

    database.records[(TENANT, RECORD)] = (1, {"raw": "candidate bytes"})
    with pytest.raises(PostgresMetadataError):
        adapter.read(TENANT, RECORD)


def test_idempotent_replay_rejects_a_valid_but_tampered_result_document():
    database = FakeDatabase()
    adapter, _connections = fake_adapter(database)
    request = transaction()
    adapter.commit(request)
    digest, result = database.transactions[(TENANT, request.transaction_id)]
    result[0]["attributes"]["state"] = "FAILED"
    database.transactions[(TENANT, request.transaction_id)] = (digest, result)
    with pytest.raises(PostgresMetadataError):
        adapter.commit(request)


def test_late_cas_conflict_rolls_back_every_earlier_write_and_transaction_claim():
    database = FakeDatabase()
    adapter, _connections = fake_adapter(database)
    adapter.commit(transaction())
    new_record = opaque("metarecord:v1:")
    late_conflict = TenantMetadataTransaction(
        TENANT, opaque("metatx:v1:"), {new_record: 0, RECORD: 0},
        (metadata(record_id=new_record), metadata(record_id=RECORD)))

    with pytest.raises(PostgresMetadataError):
        adapter.commit(late_conflict)
    assert (TENANT, new_record) not in database.records
    assert (TENANT, late_conflict.transaction_id) not in database.transactions


def test_adapter_requires_a_fresh_autocommit_connection_to_own_transactions():
    database = FakeDatabase()
    connection = FakeConnection(database)
    connection.autocommit = False
    adapter = PostgresControlPlaneMetadata(lambda: connection)
    with pytest.raises(PostgresMetadataError):
        adapter.commit(transaction())
    assert connection.rolled_back and connection.closed


def test_postgresql_service_commit_cas_and_idempotency_when_configured():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "001_m26_postgres_metadata.sql"
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute(migration.read_text(encoding="utf-8"))

    tenant, record_id, txid = opaque("tenantref:v1:"), opaque("metarecord:v1:"), opaque("metatx:v1:")
    first = metadata(tenant=tenant, record_id=record_id)
    adapter = PostgresControlPlaneMetadata(lambda: psycopg.connect(dsn, autocommit=True))
    request = transaction(transaction_id=txid, write=first)
    assert adapter.commit(request) == (first,)
    assert adapter.commit(request) == (first,)
    with pytest.raises(PostgresMetadataError):
        adapter.commit(transaction(transaction_id=opaque("metatx:v1:"), write=first, expected={record_id: 0}))
    assert adapter.read(tenant, record_id) == first

    concurrent_record, concurrent_tx = opaque("metarecord:v1:"), opaque("metatx:v1:")
    concurrent_write = metadata(tenant=tenant, record_id=concurrent_record)
    concurrent_request = transaction(transaction_id=concurrent_tx, write=concurrent_write)
    # Separate connections race on the same unique transaction ID. PostgreSQL
    # must serialize them as one commit plus an exact idempotent replay.
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _unused: adapter.commit(concurrent_request), range(2)))
    assert results == [(concurrent_write,), (concurrent_write,)]
    assert adapter.read(tenant, concurrent_record) == concurrent_write

    # Unlike same-ID replay, independently named requests racing the same
    # version are a real compare-and-swap conflict: exactly one may commit.
    cas_tx_a, cas_tx_b = opaque("metatx:v1:"), opaque("metatx:v1:")
    cas_a = transaction(transaction_id=cas_tx_a,
                        write=metadata(tenant=tenant, record_id=record_id, version=2, state="RUNNING"),
                        expected={record_id: 1})
    cas_b = transaction(transaction_id=cas_tx_b,
                        write=metadata(tenant=tenant, record_id=record_id, version=2, state="FAILED"),
                        expected={record_id: 1})
    barrier = Barrier(2)

    def race(request):
        barrier.wait()
        try:
            return adapter.commit(request)
        except PostgresMetadataError:
            return None

    with ThreadPoolExecutor(max_workers=2) as executor:
        cas_results = list(executor.map(race, (cas_a, cas_b)))
    winners = [result for result in cas_results if result is not None]
    assert len(winners) == 1
    assert adapter.read(tenant, record_id) == winners[0][0]

    new_record, rollback_tx = opaque("metarecord:v1:"), opaque("metatx:v1:")
    late_conflict = TenantMetadataTransaction(
        tenant, rollback_tx, {new_record: 0, record_id: 0},
        (metadata(tenant=tenant, record_id=new_record), metadata(tenant=tenant, record_id=record_id)))
    with pytest.raises(PostgresMetadataError):
        adapter.commit(late_conflict)
    assert adapter.read(tenant, new_record) is None
    with psycopg.connect(dsn, autocommit=True) as connection:
        count = connection.execute("SELECT COUNT(*) FROM anonflow_metadata_transactions "
                                   "WHERE tenant_ref=%s AND transaction_id=%s",
                                   (tenant, rollback_tx)).fetchone()[0]
    assert count == 0

    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("UPDATE anonflow_metadata_records SET document=%s::jsonb "
                           "WHERE tenant_ref=%s AND record_id=%s",
                           ('{"valid_but_wrong":"metadata"}', tenant, record_id))
    with pytest.raises(PostgresMetadataError):
        adapter.read(tenant, record_id)
