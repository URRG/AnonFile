"""M39a fake and optional PostgreSQL integration tests for publication intents."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
from threading import Barrier

import pytest

from app.postgres_publication_intents import (PostgresPublicationIntentError,
                                              PostgresPublicationIntents,
                                              PublicationIntent)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def digest() -> str:
    return "sha256:" + secrets.token_hex(32)


TENANT = opaque("tenantref:v1:")
OTHER_TENANT = opaque("tenantref:v1:")
PUBLICATION = opaque("publicationref:v1:")
OBJECT = opaque("objectref:v1:")
WORK = opaque("workref:v1:")
TARGET = opaque("metarecord:v1:")
KEY = "keyref:v1:publication-key"


def intent(*, tenant=TENANT, publication=PUBLICATION, transaction_id=None,
           request_digest=None, attributes=None, object_ref=OBJECT) -> PublicationIntent:
    return PublicationIntent(
        tenant_ref=tenant, publication_ref=publication,
        transaction_id=transaction_id or opaque("metatx:v1:"), object_ref=object_ref,
        key_ref=KEY, work_ref=WORK, target_ref=TARGET, metadata_kind="release_artifact",
        request_digest=request_digest or digest(), policy_digest=digest(), expected_version=1,
        attributes={} if attributes is None else attributes)


class FakeDatabase:
    def __init__(self):
        self.intents = {}


class FakeConnection:
    def __init__(self, database):
        self.database = database
        self.intents = copy.deepcopy(database.intents)
        self.autocommit = True
        self.committed = self.rolled_back = self.closed = False

    def cursor(self): return FakeCursor(self)
    def close(self): self.closed = True
    def commit(self): self.database.intents = self.intents; self.committed = True
    def rollback(self): self.rolled_back = True


class FakeCursor:
    def __init__(self, connection):
        self.connection, self._row, self._rows, self.rowcount = connection, None, [], -1
    def fetchone(self): return self._row
    def fetchall(self): return self._rows
    def execute(self, sql, params=()):
        normalized = " ".join(sql.split()); self._row, self._rows, self.rowcount = None, [], -1
        if normalized in {"BEGIN", "BEGIN READ ONLY"}: return
        if normalized == "COMMIT": self.connection.commit(); return
        if normalized == "ROLLBACK": self.connection.rollback(); return
        if normalized.startswith("INSERT INTO anonflow_publication_intents"):
            publication, tenant, transaction, object_ref, plan_digest, document = params
            conflicts = [value for value in self.connection.intents.values()
                         if value["publication_ref"] == publication
                         or (value["tenant_ref"], value["transaction_id"]) == (tenant, transaction)
                         or (value["tenant_ref"], value["object_ref"]) == (tenant, object_ref)]
            if not conflicts:
                value = {"publication_ref": publication, "tenant_ref": tenant,
                         "transaction_id": transaction, "object_ref": object_ref, "plan_digest": plan_digest,
                         "document": json.loads(document)}
                self.connection.intents[publication] = value
                self._row, self.rowcount = (publication, tenant, transaction, plan_digest, value["document"]), 1
            else: self.rowcount = 0
            return
        if normalized.startswith("SELECT publication_ref, tenant_ref, transaction_id, plan_digest"):
            _limit, publication, tenant, transaction = params
            self._rows = [(value["publication_ref"], value["tenant_ref"], value["transaction_id"],
                           value["plan_digest"], value["document"])
                          for value in self.connection.intents.values()
                          if value["publication_ref"] == publication
                          or (value["tenant_ref"], value["transaction_id"]) == (tenant, transaction)]
            return
        if normalized.startswith("SELECT transaction_id, plan_digest"):
            _limit, tenant, publication = params
            value = self.connection.intents.get(publication)
            self._row = None if value is None or value["tenant_ref"] != tenant else (
                value["transaction_id"], value["plan_digest"], value["document"])
            return
        raise AssertionError(normalized)


def fake_adapter(database):
    connections = []
    def connect():
        connection = FakeConnection(database); connections.append(connection); return connection
    return PostgresPublicationIntents(connect), connections


def test_begin_is_exact_idempotent_and_read_is_tenant_scoped():
    database = FakeDatabase(); ledger, connections = fake_adapter(database); first = intent()
    assert ledger.begin(first) == first
    assert ledger.begin(first) == first
    assert ledger.read(TENANT, PUBLICATION) == first
    assert ledger.read(OTHER_TENANT, PUBLICATION) is None
    loaded = ledger.read(TENANT, PUBLICATION)
    with pytest.raises(TypeError): loaded.attributes["sequence"] = 2
    assert all(connection.committed and connection.closed for connection in connections)


def test_same_publication_or_transaction_with_an_altered_plan_fails_closed():
    database = FakeDatabase(); ledger, connections = fake_adapter(database); first = intent()
    ledger.begin(first)
    with pytest.raises(PostgresPublicationIntentError):
        ledger.begin(intent(publication=first.publication_ref, request_digest=digest()))
    with pytest.raises(PostgresPublicationIntentError):
        ledger.begin(intent(transaction_id=first.transaction_id, publication=opaque("publicationref:v1:")))
    with pytest.raises(PostgresPublicationIntentError):
        ledger.begin(intent(publication=opaque("publicationref:v1:")))
    assert len(database.intents) == 1
    assert connections[-1].rolled_back and connections[-1].closed


def test_safe_vocabulary_and_exact_publication_grammar_reject_bytes_urls_and_payload_text():
    with pytest.raises(PostgresPublicationIntentError): intent(publication="publicationref:v1:short")
    with pytest.raises(PostgresPublicationIntentError): intent(attributes={"url": "https://example.invalid"})
    with pytest.raises(PostgresPublicationIntentError): intent(attributes={"authorization_ref": "candidate bytes"})
    with pytest.raises(PostgresPublicationIntentError): intent(attributes={"sequence": True})
    created = PublicationIntent(tenant_ref=TENANT, publication_ref=opaque("publicationref:v1:"),
        transaction_id=opaque("metatx:v1:"), object_ref=opaque("objectref:v1:"), key_ref=KEY,
        work_ref=WORK, target_ref=TARGET, metadata_kind="release_artifact", request_digest=digest(),
        policy_digest=digest(), expected_version=0, attributes={})
    assert created.expected_version == 0


def test_fake_rejects_tampered_document_and_ambiguous_identity_collision():
    database = FakeDatabase(); ledger, _connections = fake_adapter(database); first = intent()
    ledger.begin(first)
    database.intents[first.publication_ref]["document"]["state"] = "SUCCEEDED"
    with pytest.raises(PostgresPublicationIntentError): ledger.read(TENANT, first.publication_ref)

    # An attacker-created second conflicting immutable identity must not be
    # resolved by cursor ordering.
    other = intent(publication=opaque("publicationref:v1:"), transaction_id=first.transaction_id)
    database.intents[other.publication_ref] = {"publication_ref": other.publication_ref,
        "tenant_ref": other.tenant_ref, "transaction_id": other.transaction_id,
        "plan_digest": "sha256:" + "0" * 64, "document": {}}
    with pytest.raises(PostgresPublicationIntentError): ledger.begin(first)


def test_postgresql_service_atomic_idempotency_constraints_and_concurrency_when_configured():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migration = Path(__file__).parents[1] / "migrations" / "003_m39_publication_intents.sql"
    with psycopg.connect(dsn, autocommit=True) as connection: connection.execute(migration.read_text(encoding="utf-8"))
    ledger = PostgresPublicationIntents(lambda: psycopg.connect(dsn, autocommit=True))
    first = intent(tenant=opaque("tenantref:v1:"), publication=opaque("publicationref:v1:"))
    assert ledger.begin(first) == first
    assert ledger.begin(first) == first
    assert ledger.read(OTHER_TENANT, first.publication_ref) is None
    with pytest.raises(PostgresPublicationIntentError):
        ledger.begin(intent(tenant=first.tenant_ref, publication=first.publication_ref, request_digest=digest()))

    concurrent = intent(tenant=opaque("tenantref:v1:"), publication=opaque("publicationref:v1:"),
                        object_ref=opaque("objectref:v1:"))
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _unused: ledger.begin(concurrent), range(2)))
    assert results == [concurrent, concurrent]

    # Verify database checks also reject a malformed direct insert, rather
    # than relying solely on the Python boundary.
    with psycopg.connect(dsn, autocommit=True) as connection:
        with pytest.raises(psycopg.Error):
            connection.execute("INSERT INTO anonflow_publication_intents "
                               "(publication_ref, tenant_ref, transaction_id, object_ref, plan_digest, document) "
                               "VALUES (%s,%s,%s,%s,%s,%s::jsonb)",
                               (opaque("publicationref:v1:"), first.tenant_ref, opaque("metatx:v1:"),
                                opaque("objectref:v1:"), digest(), '{"state":"PENDING"}'))
