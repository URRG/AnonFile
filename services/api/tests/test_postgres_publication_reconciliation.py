"""M41a validation and real PostgreSQL reconciliation tests."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
from pathlib import Path
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.postgres_publication_intents import (PostgresPublicationIntents, PublicationIntent,
                                              _plan_digest)
from app.publication_payload_binding import (PublicationPayloadBinding,
                                             payload_digest)
from app.postgres_publication_reconciliation import (PostgresPublicationReconciliationError,
                                                      PostgresPublicationReconciler)
from app.postgres_worker_jobs import PostgresLeasedWorkerJobs
from app.publication_authorization import (PinnedPublicationAuthorizationVerifier,
                                           PublicationAuthorizationAttestation)


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def digest() -> str:
    return "sha256:" + secrets.token_hex(32)


ISSUER = Ed25519PrivateKey.generate()


def verifier(*tenants: str) -> PinnedPublicationAuthorizationVerifier:
    raw = ISSUER.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    return PinnedPublicationAuthorizationVerifier({(tenant, "m43-reconciliation-test"): raw
                                                   for tenant in tenants})


def authorization(intent: PublicationIntent, payload: PublicationPayloadBinding) -> PublicationAuthorizationAttestation:
    now = datetime.now(UTC).replace(microsecond=0)
    values = dict(
        tenant_ref=intent.tenant_ref, publication_ref=intent.publication_ref,
        plan_digest=_plan_digest(intent), target_ref=intent.target_ref,
        metadata_kind=intent.metadata_kind, binding_digest=payload.binding_digest,
        release_case_id=opaque("release-case:v1:"), release_case_digest=digest(),
        privacy_decision_id=opaque("privacy-decision:v1:"), privacy_decision_digest=digest(),
        approval_digests=(digest(), digest()), rights_digest=secrets.token_hex(32),
        contract_digest=digest(), recipient_commitment=opaque("recipient-commitment:v1:"),
        purpose_code="model_training", issuer_key_id="m43-reconciliation-test",
        issued_at=now, expires_at=now + timedelta(minutes=5))
    unsigned = PublicationAuthorizationAttestation(
        signature="publication-authorization-sig:v1:" + "A" * 86, **values)
    import base64, json
    signature = "publication-authorization-sig:v1:" + base64.urlsafe_b64encode(ISSUER.sign(
        b"anonflow-publication-authorization-attestation:v1:\x00" + json.dumps(
            unsigned.canonical(), ensure_ascii=True, allow_nan=False, sort_keys=True,
            separators=(",", ":")).encode("ascii"))).decode("ascii").rstrip("=")
    return PublicationAuthorizationAttestation(signature=signature, **values)


def plan(tenant: str, *, publication: str | None = None, work: str | None = None) -> PublicationIntent:
    return PublicationIntent(tenant, publication or opaque("publicationref:v1:"), opaque("metatx:v1:"),
        opaque("objectref:v1:"), "keyref:v1:reconcile", work or opaque("workref:v1:"),
        opaque("metarecord:v1:"), "release_artifact", digest(), digest(), 0, {})


def binding(intent: PublicationIntent) -> PublicationPayloadBinding:
    payload = b"reconciliation commitment"
    return PublicationPayloadBinding.create(
        tenant_ref=intent.tenant_ref, publication_ref=intent.publication_ref,
        object_ref=intent.object_ref, key_ref=intent.key_ref,
        plan_digest=_plan_digest(intent), payload_digest=payload_digest(payload),
        payload_size_bytes=len(payload), serialization_id="binary-v1")


def test_reconciler_validates_bounded_metadata_only_inputs_without_connecting():
    opened: list[bool] = []
    reconciler = PostgresPublicationReconciler(lambda: opened.append(True))
    tenant = opaque("tenantref:v1:")
    with pytest.raises(PostgresPublicationReconciliationError):
        reconciler.scan(tenant, older_than_seconds=0)
    with pytest.raises(PostgresPublicationReconciliationError):
        reconciler.scan(tenant, older_than_seconds=1, limit=101)
    with pytest.raises(PostgresPublicationReconciliationError):
        reconciler.quarantine(tenant, opaque("publicationref:v1:"), opaque("observation:v1:"), reason="guessed")
    with pytest.raises(PostgresPublicationReconciliationError):
        reconciler.quarantine(tenant, opaque("publicationref:v1:"), opaque("observation:v1:"),
                              reason="OPERATOR_CONFIRMED_UNRECOVERABLE")
    with pytest.raises(PostgresPublicationReconciliationError):
        PostgresPublicationReconciler(lambda: opened.append(True), quarantine_authorizer=lambda *_args: False).quarantine(
            tenant, opaque("publicationref:v1:"), opaque("observation:v1:"),
            reason="OPERATOR_CONFIRMED_UNRECOVERABLE")
    assert opened == []


@pytest.fixture
def pg_reconciliation():
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migrations = [Path(__file__).parents[1] / "migrations" / name for name in (
        "001_m26_postgres_metadata.sql", "002_m28_postgres_worker_jobs.sql",
        "003_m39_publication_intents.sql", "004_m40_publication_finalizations.sql",
        "005_m41_publication_reconciliation.sql", "006_m42_publication_payload_bindings.sql",
        "007_m43_publication_authorizations.sql")]
    with psycopg.connect(dsn, autocommit=True) as connection:
        for migration in migrations:
            connection.execute(migration.read_text(encoding="utf-8"))
    connect = lambda: psycopg.connect(dsn, autocommit=True)
    tenant = opaque("tenantref:v1:")
    intent = plan(tenant)
    authority = verifier(tenant)
    intents = PostgresPublicationIntents(connect, authority)
    payload = binding(intent)
    assert intents.begin(intent, payload, authorization(intent, payload)) == intent
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("UPDATE anonflow_publication_intents SET created_at=clock_timestamp()-interval '2 minutes' "
                           "WHERE tenant_ref=%s AND publication_ref=%s", (tenant, intent.publication_ref))
    return {"psycopg": psycopg, "dsn": dsn, "connect": connect, "tenant": tenant,
            "intent": intent, "verifier": authority}


def _scan(state, **kwargs):
    return PostgresPublicationReconciler(state["connect"]).scan(state["tenant"], older_than_seconds=60, **kwargs)


def _event_count(state) -> int:
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        return connection.execute("SELECT count(*) FROM anonflow_publication_observation_events "
                                  "WHERE tenant_ref=%s AND publication_ref=%s",
                                  (state["tenant"], state["intent"].publication_ref)).fetchone()[0]


def test_postgresql_scan_is_tenant_scoped_bounded_and_single_scanner(pg_reconciliation):
    state = pg_reconciliation
    other = plan(opaque("tenantref:v1:"))
    payload = binding(other)
    assert PostgresPublicationIntents(state["connect"], verifier(other.tenant_ref)).begin(
        other, payload, authorization(other, payload)) == other
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        connection.execute("UPDATE anonflow_publication_intents SET created_at=clock_timestamp()-interval '2 minutes' "
                           "WHERE tenant_ref=%s AND publication_ref=%s", (other.tenant_ref, other.publication_ref))
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _ignored: _scan(state), range(2)))
    observed = [row for result in results for row in result]
    assert len(observed) == 1 and observed[0].publication_ref == state["intent"].publication_ref
    assert observed[0].state == "OBSERVED" and observed[0].reason is None
    assert _event_count(state) == 1
    assert PostgresPublicationReconciler(state["connect"]).scan(other.tenant_ref, older_than_seconds=60) != ()


def test_postgresql_scan_filters_more_than_one_hundred_live_observations_before_limit(pg_reconciliation):
    state = pg_reconciliation
    intents = PostgresPublicationIntents(state["connect"], state["verifier"])
    active = [plan(state["tenant"]) for _unused in range(101)]
    for pending in active:
        payload = binding(pending)
        assert intents.begin(pending, payload, authorization(pending, payload)) == pending
    eligible = plan(state["tenant"])
    eligible_payload = binding(eligible)
    assert intents.begin(eligible, eligible_payload, authorization(eligible, eligible_payload)) == eligible
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        for pending in [state["intent"], *active, eligible]:
            connection.execute("UPDATE anonflow_publication_intents SET created_at=clock_timestamp()-interval '2 minutes' "
                               "WHERE tenant_ref=%s AND publication_ref=%s", (state["tenant"], pending.publication_ref))
        for pending in [state["intent"], *active]:
            connection.execute("INSERT INTO anonflow_publication_observations "
                               "(tenant_ref, publication_ref, observation_epoch, observation_token, state, lease_expires_at) "
                               "VALUES (%s,%s,1,%s,'OBSERVED',clock_timestamp()+interval '1 hour')",
                               (state["tenant"], pending.publication_ref, opaque("observation:v1:")))
    observed = _scan(state, limit=100)
    assert [item.publication_ref for item in observed] == [eligible.publication_ref]


def test_postgresql_scan_normalizes_non_utc_session_timestamps(pg_reconciliation):
    state = pg_reconciliation
    def offset_connect():
        connection = state["psycopg"].connect(state["dsn"], autocommit=True)
        connection.execute("SET TIME ZONE 'Asia/Kolkata'")
        return connection
    observed = PostgresPublicationReconciler(offset_connect).scan(state["tenant"], older_than_seconds=60)[0]
    assert observed.created_at.tzinfo is UTC and observed.lease_expires_at.tzinfo is UTC


def test_postgresql_scan_skips_live_claim_then_observes_expired_lease(pg_reconciliation):
    state = pg_reconciliation
    jobs = PostgresLeasedWorkerJobs(state["connect"])
    assert jobs.enqueue(state["tenant"], state["intent"].work_ref)
    assert jobs.claim(state["tenant"], opaque("workerref:v1:"), lease_seconds=60) is not None
    assert _scan(state) == ()
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        connection.execute("WITH database_clock AS (SELECT date_trunc('second', clock_timestamp()) AS now) "
                           "UPDATE anonflow_worker_jobs SET leased_at=database_clock.now-interval '3 seconds', "
                           "lease_expires_at=database_clock.now-interval '1 second' FROM database_clock "
                           "WHERE tenant_ref=%s AND work_ref=%s", (state["tenant"], state["intent"].work_ref))
    assert len(_scan(state)) == 1


def test_postgresql_quarantine_is_explicit_cas_and_events_are_append_only(pg_reconciliation):
    state = pg_reconciliation
    observation = _scan(state)[0]
    reconciler = PostgresPublicationReconciler(state["connect"], quarantine_authorizer=lambda *_args: True)
    assert reconciler.quarantine(state["tenant"], observation.publication_ref,
                                  opaque("observation:v1:"), reason="OPERATOR_CONFIRMED_UNRECOVERABLE") is False
    assert reconciler.quarantine(state["tenant"], observation.publication_ref, observation.observation_token,
                                  reason="OPERATOR_CONFIRMED_UNRECOVERABLE") is True
    assert _scan(state) == () and _event_count(state) == 2
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        with pytest.raises(state["psycopg"].Error):
            connection.execute("DELETE FROM anonflow_publication_observation_events WHERE tenant_ref=%s",
                               (state["tenant"],))


def test_postgresql_quarantine_declines_after_finalization(pg_reconciliation):
    state = pg_reconciliation
    observation = _scan(state)[0]
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        connection.execute(
            "INSERT INTO anonflow_publication_finalizations "
            "(tenant_ref, publication_ref, completion_digest, result_document) "
            "VALUES (%s,%s,%s,'{}'::jsonb)",
            (state["tenant"], state["intent"].publication_ref, secrets.token_hex(32)))
    reconciler = PostgresPublicationReconciler(state["connect"], quarantine_authorizer=lambda *_args: True)
    assert reconciler.quarantine(state["tenant"], observation.publication_ref, observation.observation_token,
                                 reason="OPERATOR_CONFIRMED_UNRECOVERABLE") is False
    assert _event_count(state) == 1


def test_postgresql_commit_lost_replay_never_creates_second_active_observation(pg_reconciliation):
    state = pg_reconciliation
    class CommitLostCursor:
        def __init__(self, cursor): self._cursor = cursor
        def execute(self, sql, params=None):
            result = self._cursor.execute(sql, params)
            if " ".join(sql.split()) == "COMMIT":
                raise RuntimeError("lost commit response")
            return result
        def __getattr__(self, name): return getattr(self._cursor, name)
    class CommitLostConnection:
        autocommit = True
        def __init__(self, connection): self._connection = connection
        def cursor(self): return CommitLostCursor(self._connection.cursor())
        def close(self): return self._connection.close()
    with pytest.raises(PostgresPublicationReconciliationError):
        PostgresPublicationReconciler(lambda: CommitLostConnection(state["connect"]())).scan(
            state["tenant"], older_than_seconds=60)
    assert _scan(state) == ()
    assert _event_count(state) == 1
