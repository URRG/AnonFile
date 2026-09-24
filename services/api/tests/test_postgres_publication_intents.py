"""M39a fake and optional PostgreSQL integration tests for publication intents."""
from __future__ import annotations

import copy
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import secrets
from threading import Barrier
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.postgres_publication_intents import (PostgresPublicationIntentError,
                                              PostgresPublicationIntents,
                                              PublicationIntent, _plan_digest)
from app.publication_payload_binding import (PublicationPayloadBinding,
                                              PublicationPayloadBindingError,
                                              payload_digest)
from app.publication_authorization import (PinnedPublicationAuthorizationVerifier,
                                           PublicationAuthorizationAttestation)


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
NOW = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)
ISSUER = Ed25519PrivateKey.generate()


def authorization_for(plan: PublicationIntent, binding: PublicationPayloadBinding, *, at=NOW):
    values = dict(tenant_ref=plan.tenant_ref, publication_ref=plan.publication_ref,
        plan_digest=_plan_digest(plan), target_ref=plan.target_ref, metadata_kind=plan.metadata_kind,
        binding_digest=binding.binding_digest, release_case_id=opaque("release-case:v1:"),
        release_case_digest=digest(), privacy_decision_id=opaque("privacy-decision:v1:"),
        privacy_decision_digest=digest(), approval_digests=(digest(), digest()), rights_digest=secrets.token_hex(32),
        contract_digest=digest(), recipient_commitment=opaque("recipient-commitment:v1:"),
        purpose_code="model_training", issuer_key_id="m43-test", issued_at=at,
        expires_at=at + timedelta(minutes=5))
    blank = "publication-authorization-sig:v1:" + "A" * 86
    unsigned = PublicationAuthorizationAttestation(signature=blank, **values)
    import base64, json
    signature = "publication-authorization-sig:v1:" + base64.urlsafe_b64encode(ISSUER.sign(
        b"anonflow-publication-authorization-attestation:v1:\x00" + json.dumps(
            unsigned.canonical(), ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":")).encode("ascii"))).decode("ascii").rstrip("=")
    return PublicationAuthorizationAttestation(signature=signature, **values)


def verifier(*tenants):
    public = ISSUER.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return PinnedPublicationAuthorizationVerifier({(tenant, "m43-test"): public for tenant in tenants or (TENANT,)})


def intent(*, tenant=TENANT, publication=PUBLICATION, transaction_id=None,
           request_digest=None, attributes=None, object_ref=OBJECT) -> PublicationIntent:
    return PublicationIntent(
        tenant_ref=tenant, publication_ref=publication,
        transaction_id=transaction_id or opaque("metatx:v1:"), object_ref=object_ref,
        key_ref=KEY, work_ref=WORK, target_ref=TARGET, metadata_kind="release_artifact",
        request_digest=request_digest or digest(), policy_digest=digest(), expected_version=1,
        attributes={} if attributes is None else attributes)


def binding_for(plan: PublicationIntent, payload: bytes = b"sample\n",
                serialization_id: str = "jsonl-utf8-v1") -> PublicationPayloadBinding:
    return PublicationPayloadBinding.create(
        tenant_ref=plan.tenant_ref, publication_ref=plan.publication_ref,
        object_ref=plan.object_ref, key_ref=plan.key_ref, plan_digest=_plan_digest(plan),
        payload_digest=payload_digest(payload), payload_size_bytes=len(payload),
        serialization_id=serialization_id)


class FakeDatabase:
    def __init__(self):
        self.intents, self.bindings, self.authorizations = {}, {}, {}
        self.now, self.advance_after_authorization_insert = NOW, False


class FakeConnection:
    def __init__(self, database):
        self.database = database
        self.intents, self.bindings = copy.deepcopy(database.intents), copy.deepcopy(database.bindings)
        self.authorizations = copy.deepcopy(database.authorizations)
        self.autocommit = True
        self.committed = self.rolled_back = self.closed = False

    def cursor(self): return FakeCursor(self)
    def close(self): self.closed = True
    def commit(self):
        self.database.intents, self.database.bindings = self.intents, self.bindings
        self.database.authorizations = self.authorizations; self.committed = True
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
        if normalized == "SELECT date_trunc('second', clock_timestamp())":
            self._row = (self.connection.database.now,); return
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
        if normalized.startswith("INSERT INTO anonflow_publication_payload_bindings"):
            tenant, publication, object_ref, key, plan, payload, size, serialization, binding = params
            identity = (tenant, publication)
            if identity not in self.connection.bindings:
                value = (object_ref, key, plan, payload, size, serialization, binding)
                self.connection.bindings[identity] = value
                self._row, self.rowcount = value, 1
            else: self.rowcount = 0
            return
        if normalized.startswith("SELECT object_ref, key_ref, plan_digest, payload_digest"):
            tenant, publication = params
            self._row = self.connection.bindings.get((tenant, publication))
            return
        if normalized.startswith("INSERT INTO anonflow_publication_authorizations"):
            tenant, publication, digest_value, expires_at, document, issued_at, checked_expiry = params
            if issued_at > NOW or checked_expiry <= NOW or (tenant, publication) in self.connection.authorizations:
                self.rowcount = 0; return
            value = (digest_value, expires_at, json.loads(document))
            self.connection.authorizations[(tenant, publication)] = value
            self._row, self.rowcount = value, 1
            if self.connection.database.advance_after_authorization_insert:
                self.connection.database.now = expires_at
            return
        if normalized.startswith("SELECT attestation_digest, expires_at"):
            if len(params) == 3:
                _limit, tenant, publication = params
            else:
                tenant, publication = params
            self._row = self.connection.authorizations.get((tenant, publication))
            return
        raise AssertionError(normalized)


def fake_adapter(database):
    connections = []
    def connect():
        connection = FakeConnection(database); connections.append(connection); return connection
    return PostgresPublicationIntents(connect, verifier()), connections


def test_begin_is_exact_idempotent_and_read_is_tenant_scoped():
    database = FakeDatabase(); ledger, connections = fake_adapter(database); first = intent()
    binding = binding_for(first)
    authorization = authorization_for(first, binding)
    assert ledger.begin(first, binding, authorization) == first
    assert ledger.begin(first, binding, authorization) == first
    assert ledger.read(TENANT, PUBLICATION) == first
    assert ledger.read_binding(TENANT, PUBLICATION) == binding
    assert ledger.read_authorization(TENANT, PUBLICATION) == authorization
    assert ledger.read(OTHER_TENANT, PUBLICATION) is None
    loaded = ledger.read(TENANT, PUBLICATION)
    with pytest.raises(TypeError): loaded.attributes["sequence"] = 2
    assert all(connection.committed and connection.closed for connection in connections)


def test_same_publication_or_transaction_with_an_altered_plan_fails_closed():
    database = FakeDatabase(); ledger, connections = fake_adapter(database); first = intent()
    first_binding = binding_for(first); first_authorization = authorization_for(first, first_binding)
    ledger.begin(first, first_binding, first_authorization)
    with pytest.raises(PostgresPublicationIntentError):
        changed_binding = binding_for(first, b"changed\n")
        ledger.begin(first, changed_binding, authorization_for(first, changed_binding))
    with pytest.raises(PostgresPublicationIntentError):
        changed = intent(publication=first.publication_ref, request_digest=digest())
        changed_binding = binding_for(changed); ledger.begin(changed, changed_binding, authorization_for(changed, changed_binding))
    with pytest.raises(PostgresPublicationIntentError):
        changed = intent(transaction_id=first.transaction_id, publication=opaque("publicationref:v1:"))
        changed_binding = binding_for(changed); ledger.begin(changed, changed_binding, authorization_for(changed, changed_binding))
    with pytest.raises(PostgresPublicationIntentError):
        changed = intent(publication=opaque("publicationref:v1:"))
        changed_binding = binding_for(changed); ledger.begin(changed, changed_binding, authorization_for(changed, changed_binding))
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
    first_binding = binding_for(first); ledger.begin(first, first_binding, authorization_for(first, first_binding))
    database.intents[first.publication_ref]["document"]["state"] = "SUCCEEDED"
    with pytest.raises(PostgresPublicationIntentError): ledger.read(TENANT, first.publication_ref)

    # An attacker-created second conflicting immutable identity must not be
    # resolved by cursor ordering.
    other = intent(publication=opaque("publicationref:v1:"), transaction_id=first.transaction_id)
    database.intents[other.publication_ref] = {"publication_ref": other.publication_ref,
        "tenant_ref": other.tenant_ref, "transaction_id": other.transaction_id,
        "plan_digest": "sha256:" + "0" * 64, "document": {}}
    first_binding = binding_for(first)
    with pytest.raises(PostgresPublicationIntentError): ledger.begin(first, first_binding, authorization_for(first, first_binding))


def test_legacy_intent_without_a_binding_fails_closed_and_cannot_be_retrospectively_bound():
    database = FakeDatabase(); ledger, _connections = fake_adapter(database); first = intent()
    database.intents[first.publication_ref] = {
        "publication_ref": first.publication_ref, "tenant_ref": first.tenant_ref,
        "transaction_id": first.transaction_id, "object_ref": first.object_ref,
        "plan_digest": _plan_digest(first), "document": {
            "attributes": {}, "expected_version": first.expected_version, "key_ref": first.key_ref,
            "metadata_kind": first.metadata_kind, "policy_digest": first.policy_digest,
            "object_ref": first.object_ref, "publication_ref": first.publication_ref,
            "request_digest": first.request_digest, "state": "PENDING", "target_ref": first.target_ref,
            "tenant_ref": first.tenant_ref, "transaction_id": first.transaction_id, "work_ref": first.work_ref}}
    with pytest.raises(PostgresPublicationIntentError): ledger.read(TENANT, PUBLICATION)
    first_binding = binding_for(first)
    with pytest.raises(PostgresPublicationIntentError): ledger.begin(first, first_binding, authorization_for(first, first_binding))
    assert database.bindings == {}


def test_missing_corrupt_or_expired_authorization_fails_closed_on_every_read():
    database = FakeDatabase(); ledger, _connections = fake_adapter(database); first = intent()
    first_binding = binding_for(first); authorization = authorization_for(first, first_binding)
    ledger.begin(first, first_binding, authorization)
    del database.authorizations[(TENANT, PUBLICATION)]
    with pytest.raises(PostgresPublicationIntentError): ledger.read(TENANT, PUBLICATION)

    database = FakeDatabase(); ledger, _connections = fake_adapter(database)
    ledger.begin(first, first_binding, authorization)
    digest_value, expires_at, document = database.authorizations[(TENANT, PUBLICATION)]
    document["binding_digest"] = digest()
    database.authorizations[(TENANT, PUBLICATION)] = (digest_value, expires_at, document)
    with pytest.raises(PostgresPublicationIntentError): ledger.read_binding(TENANT, PUBLICATION)

    database = FakeDatabase(); ledger, _connections = fake_adapter(database)
    expired = authorization_for(first, first_binding, at=NOW - timedelta(minutes=5))
    database.intents[first.publication_ref] = {
        "publication_ref": first.publication_ref, "tenant_ref": first.tenant_ref,
        "transaction_id": first.transaction_id, "object_ref": first.object_ref,
        "plan_digest": _plan_digest(first), "document": {
            "attributes": {}, "expected_version": first.expected_version, "key_ref": first.key_ref,
            "metadata_kind": first.metadata_kind, "policy_digest": first.policy_digest,
            "object_ref": first.object_ref, "publication_ref": first.publication_ref,
            "request_digest": first.request_digest, "state": "PENDING", "target_ref": first.target_ref,
            "tenant_ref": first.tenant_ref, "transaction_id": first.transaction_id, "work_ref": first.work_ref}}
    database.bindings[(TENANT, PUBLICATION)] = (first_binding.object_ref, first_binding.key_ref,
        first_binding.plan_digest, first_binding.payload_digest, first_binding.payload_size_bytes,
        first_binding.serialization_id, first_binding.binding_digest)
    database.authorizations[(TENANT, PUBLICATION)] = (expired.digest, expired.expires_at, expired.to_record())
    with pytest.raises(PostgresPublicationIntentError): ledger.read_authorization(TENANT, PUBLICATION)


def test_begin_rechecks_database_clock_immediately_before_commit():
    database = FakeDatabase(); database.advance_after_authorization_insert = True
    ledger, connections = fake_adapter(database); first = intent(); first_binding = binding_for(first)
    with pytest.raises(PostgresPublicationIntentError):
        ledger.begin(first, first_binding, authorization_for(first, first_binding))
    assert database.intents == {} and database.bindings == {} and database.authorizations == {}
    assert connections[-1].rolled_back and connections[-1].closed


def test_payload_digest_and_binding_are_exact_domain_separated_bounded_commitments():
    assert payload_digest(b"") != payload_digest(b"\x00")
    plan = intent(); binding = binding_for(plan, b'{"x":1}\n')
    assert binding.payload_size_bytes == 8
    with pytest.raises(PublicationPayloadBindingError): payload_digest(bytearray(b"x"))
    with pytest.raises(PublicationPayloadBindingError): payload_digest(b"x" * (32 * 1024 * 1024 + 1))
    with pytest.raises(PublicationPayloadBindingError): PublicationPayloadBinding.create(
        tenant_ref=plan.tenant_ref, publication_ref=plan.publication_ref, object_ref=plan.object_ref,
        key_ref=plan.key_ref, plan_digest=_plan_digest(plan), payload_digest=payload_digest(b"x"),
        payload_size_bytes=1, serialization_id="csv-v1")


def test_postgresql_service_atomic_idempotency_constraints_and_concurrency_when_configured():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn: pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migrations = [Path(__file__).parents[1] / "migrations" / name for name in
                  ["003_m39_publication_intents.sql", "006_m42_publication_payload_bindings.sql",
                   "007_m43_publication_authorizations.sql"]]
    with psycopg.connect(dsn, autocommit=True) as connection:
        for migration in migrations: connection.execute(migration.read_text(encoding="utf-8"))
    first = intent(tenant=opaque("tenantref:v1:"), publication=opaque("publicationref:v1:"))
    concurrent = intent(tenant=opaque("tenantref:v1:"), publication=opaque("publicationref:v1:"),
                        object_ref=opaque("objectref:v1:"))
    ledger = PostgresPublicationIntents(lambda: psycopg.connect(dsn, autocommit=True),
                                        verifier(first.tenant_ref, concurrent.tenant_ref))
    first_binding = binding_for(first)
    service_now = datetime.now(UTC).replace(microsecond=0)
    first_authorization = authorization_for(first, first_binding, at=service_now)
    assert ledger.begin(first, first_binding, first_authorization) == first
    assert ledger.begin(first, first_binding, first_authorization) == first
    assert ledger.read_binding(first.tenant_ref, first.publication_ref) == first_binding
    assert ledger.read(OTHER_TENANT, first.publication_ref) is None
    with pytest.raises(PostgresPublicationIntentError):
        changed = intent(tenant=first.tenant_ref, publication=first.publication_ref, request_digest=digest())
        changed_binding = binding_for(changed)
        ledger.begin(changed, changed_binding, authorization_for(changed, changed_binding, at=service_now))

    with ThreadPoolExecutor(max_workers=2) as executor:
        concurrent_binding = binding_for(concurrent)
        concurrent_authorization = authorization_for(concurrent, concurrent_binding, at=service_now)
        results = list(executor.map(lambda _unused: ledger.begin(concurrent, concurrent_binding, concurrent_authorization), range(2)))
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
        with pytest.raises(psycopg.Error):
            connection.execute("UPDATE anonflow_publication_payload_bindings SET payload_size_bytes=0 "
                               "WHERE tenant_ref=%s AND publication_ref=%s",
                               (first.tenant_ref, first.publication_ref))
        with pytest.raises(psycopg.Error):
            connection.execute("DELETE FROM anonflow_publication_payload_bindings "
                               "WHERE tenant_ref=%s AND publication_ref=%s",
                               (first.tenant_ref, first.publication_ref))
