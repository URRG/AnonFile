"""M41c non-remediating object-verification tests."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
import base64
import json
import os
from pathlib import Path
import secrets

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.openbao_datakey import OpenBaoTransitDataKey
from app.postgres_publication_intents import (PostgresPublicationIntents, PublicationIntent,
                                              _plan_digest)
from app.postgres_publication_reconciliation import PostgresPublicationReconciler
from app.postgres_publication_verification import (PostgresPublicationObservationVerifier,
                                                    PostgresPublicationVerificationError)
from app.postgres_worker_jobs import PostgresLeasedWorkerJobs
from app.publication_authorization import (PinnedPublicationAuthorizationVerifier,
                                           PublicationAuthorizationAttestation)
from app.publication_payload_binding import (PublicationPayloadBinding, payload_digest)
from app.production_substrate import EncryptedObjectReference
from app.s3_ciphertext_transport import S3CiphertextTransport
from app.worker_encrypted_objects import WorkerEncryptedObjects


def opaque(prefix: str) -> str:
    return prefix + secrets.token_urlsafe(32)


def digest() -> str:
    return "sha256:" + secrets.token_hex(32)


ISSUER = Ed25519PrivateKey.generate()


def verifier(tenant: str) -> PinnedPublicationAuthorizationVerifier:
    raw = ISSUER.public_key().public_bytes(serialization.Encoding.Raw,
                                           serialization.PublicFormat.Raw)
    return PinnedPublicationAuthorizationVerifier({(tenant, "m41c-test"): raw})


def authorization(plan: PublicationIntent, binding: PublicationPayloadBinding) -> PublicationAuthorizationAttestation:
    now = datetime.now(UTC).replace(microsecond=0)
    values = dict(tenant_ref=plan.tenant_ref, publication_ref=plan.publication_ref,
        plan_digest=_plan_digest(plan), target_ref=plan.target_ref, metadata_kind=plan.metadata_kind,
        binding_digest=binding.binding_digest, release_case_id=opaque("release-case:v1:"),
        release_case_digest=digest(), privacy_decision_id=opaque("privacy-decision:v1:"),
        privacy_decision_digest=digest(), approval_digests=(digest(), digest()),
        rights_digest=secrets.token_hex(32), contract_digest=digest(),
        recipient_commitment=opaque("recipient-commitment:v1:"), purpose_code="model_training",
        issuer_key_id="m41c-test", issued_at=now, expires_at=now + timedelta(minutes=5))
    unsigned = PublicationAuthorizationAttestation(
        signature="publication-authorization-sig:v1:" + "A" * 86, **values)
    payload = b"anonflow-publication-authorization-attestation:v1:\x00" + json.dumps(
        unsigned.canonical(), ensure_ascii=True, allow_nan=False, sort_keys=True,
        separators=(",", ":")).encode("ascii")
    return PublicationAuthorizationAttestation(
        signature="publication-authorization-sig:v1:" + base64.urlsafe_b64encode(
            ISSUER.sign(payload)).decode("ascii").rstrip("="), **values)


def worker() -> WorkerEncryptedObjects:
    return WorkerEncryptedObjects(openbao=object.__new__(OpenBaoTransitDataKey),
                                  ciphertexts=object.__new__(S3CiphertextTransport))


@pytest.fixture
def pg_verification(monkeypatch):
    dsn = os.environ.get("ANONFLOW_POSTGRES_TEST_DSN")
    if not dsn:
        pytest.skip("set ANONFLOW_POSTGRES_TEST_DSN to run PostgreSQL integration")
    psycopg = pytest.importorskip("psycopg")
    migrations = [Path(__file__).parents[1] / "migrations" / name for name in (
        "001_m26_postgres_metadata.sql", "002_m28_postgres_worker_jobs.sql",
        "003_m39_publication_intents.sql", "004_m40_publication_finalizations.sql",
        "005_m41_publication_reconciliation.sql", "006_m42_publication_payload_bindings.sql",
        "007_m43_publication_authorizations.sql", "008_m41c_publication_observation_verifications.sql")]
    with psycopg.connect(dsn, autocommit=True) as connection:
        for migration in migrations:
            connection.execute(migration.read_text(encoding="utf-8"))
    connect = lambda: psycopg.connect(dsn, autocommit=True)
    tenant, publication, object_ref, work, target = (opaque("tenantref:v1:"),
        opaque("publicationref:v1:"), opaque("objectref:v1:"), opaque("workref:v1:"),
        opaque("metarecord:v1:"))
    plan = PublicationIntent(tenant, publication, opaque("metatx:v1:"), object_ref,
        "keyref:v1:m41c", work, target, "release_artifact", digest(), digest(), 0, {})
    binding = PublicationPayloadBinding.create(tenant_ref=tenant, publication_ref=publication,
        object_ref=object_ref, key_ref=plan.key_ref, plan_digest=_plan_digest(plan),
        payload_digest=payload_digest(b"bound M41c payload"), payload_size_bytes=len(b"bound M41c payload"),
        serialization_id="binary-v1")
    auth_verifier = verifier(tenant)
    intents, jobs = PostgresPublicationIntents(connect, auth_verifier), PostgresLeasedWorkerJobs(connect)
    assert intents.begin(plan, binding, authorization(plan, binding)) == plan
    assert jobs.enqueue(tenant, work)
    with psycopg.connect(dsn, autocommit=True) as connection:
        connection.execute("UPDATE anonflow_publication_intents SET created_at=clock_timestamp()-interval '2 minutes' "
                           "WHERE tenant_ref=%s AND publication_ref=%s", (tenant, publication))
    observation = PostgresPublicationReconciler(connect).scan(tenant, older_than_seconds=60)[0]
    reference = EncryptedObjectReference(tenant, object_ref, publication, plan.key_ref, digest(), 99,
                                         binding.binding_digest)
    calls: list[dict[str, object]] = []
    def recover(_self, **kwargs):
        calls.append(kwargs)
        return reference
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", recover)
    return {"psycopg": psycopg, "dsn": dsn, "connect": connect, "plan": plan,
        "binding": binding, "verifier": auth_verifier, "jobs": jobs, "observation": observation,
        "reference": reference, "objects": worker(), "calls": calls}


def _adapter(state, connect=None) -> PostgresPublicationObservationVerifier:
    return PostgresPublicationObservationVerifier(connect or state["connect"], state["objects"], state["verifier"])


def _verify(state):
    observation = state["observation"]
    return _adapter(state).verify(tenant_ref=observation.tenant_ref,
        publication_ref=observation.publication_ref, observation_epoch=observation.observation_epoch,
        observation_token=observation.observation_token, openbao_token="test-token")


def _count(state) -> int:
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        return connection.execute("SELECT count(*) FROM anonflow_publication_observation_verifications "
            "WHERE tenant_ref=%s AND publication_ref=%s", (state["plan"].tenant_ref,
            state["plan"].publication_ref)).fetchone()[0]


def test_verifier_rejects_invalid_observation_before_connecting():
    opened: list[bool] = []
    tenant, publication = opaque("tenantref:v1:"), opaque("publicationref:v1:")
    with pytest.raises(PostgresPublicationVerificationError):
        PostgresPublicationObservationVerifier(lambda: opened.append(True), worker(), verifier(tenant)).verify(
            tenant_ref=tenant, publication_ref=publication, observation_epoch=0,
            observation_token=opaque("observation:v1:"), openbao_token="test-token")
    assert opened == []


def test_postgresql_verification_records_only_bounded_verified_evidence(pg_verification):
    state = pg_verification
    result = _verify(state)
    assert (result is not None and result.outcome == "VERIFIED" and result.recorded is True
            and result.actionable is False)
    assert state["calls"] == [{"tenant_ref": state["plan"].tenant_ref,
        "object_ref": state["binding"].object_ref, "publication_ref": state["plan"].publication_ref,
        "key_ref": state["binding"].key_ref, "binding": state["binding"],
        "openbao_token": "test-token"}]
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        row = connection.execute("SELECT outcome, binding_digest, authorization_digest, ciphertext_digest, "
            "ciphertext_size_bytes FROM "
            "anonflow_publication_observation_verifications WHERE tenant_ref=%s AND publication_ref=%s",
            (state["plan"].tenant_ref, state["plan"].publication_ref)).fetchone()
        assert row[0] == "VERIFIED" and row[1] == state["binding"].binding_digest
        assert row[3:] == (state["reference"].ciphertext_digest, state["reference"].ciphertext_size_bytes)
        assert connection.execute("SELECT count(*) FROM anonflow_publication_finalizations WHERE tenant_ref=%s",
                                  (state["plan"].tenant_ref,)).fetchone()[0] == 0
        with pytest.raises(state["psycopg"].Error):
            connection.execute("DELETE FROM anonflow_publication_observation_verifications WHERE tenant_ref=%s",
                               (state["plan"].tenant_ref,))


def test_postgresql_provider_failure_collapses_to_not_verified(pg_verification, monkeypatch):
    state = pg_verification
    monkeypatch.setattr(WorkerEncryptedObjects, "recover",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("token=secret")))
    result = _verify(state)
    assert result is not None and result.outcome == "NOT_VERIFIED" and _count(state) == 1


def test_postgresql_replay_with_changed_recovery_outcome_fails_closed(pg_verification, monkeypatch):
    state = pg_verification
    assert _verify(state).outcome == "VERIFIED"
    monkeypatch.setattr(WorkerEncryptedObjects, "recover",
                        lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("unavailable")))
    with pytest.raises(PostgresPublicationVerificationError):
        _verify(state)
    assert _count(state) == 1


def test_postgresql_replay_with_changed_ciphertext_version_fails_closed(pg_verification, monkeypatch):
    state = pg_verification
    assert _verify(state).outcome == "VERIFIED"
    changed = EncryptedObjectReference(state["reference"].tenant_ref, state["reference"].object_ref,
        state["reference"].publication_ref, state["reference"].key_ref, digest(), 100,
        state["reference"].binding_digest)
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", lambda *_args, **_kwargs: changed)
    with pytest.raises(PostgresPublicationVerificationError):
        _verify(state)
    assert _count(state) == 1


def test_postgresql_live_claim_or_post_recovery_claim_is_non_actionable(pg_verification, monkeypatch):
    state = pg_verification
    claim = state["jobs"].claim(state["plan"].tenant_ref, opaque("workerref:v1:"), lease_seconds=60)
    assert claim is not None and _verify(state) is None and state["calls"] == [] and _count(state) == 0
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        connection.execute("UPDATE anonflow_worker_jobs SET lease_expires_at=clock_timestamp()-interval '1 second' "
                           "WHERE tenant_ref=%s AND work_ref=%s", (state["plan"].tenant_ref, state["plan"].work_ref))
    def recover(_self, **_kwargs):
        assert state["jobs"].claim(state["plan"].tenant_ref, opaque("workerref:v1:"), lease_seconds=60) is not None
        return state["reference"]
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", recover)
    assert _verify(state) is None and _count(state) == 0


def test_postgresql_missing_job_is_non_actionable_without_recovery(pg_verification):
    state = pg_verification
    with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
        connection.execute("DELETE FROM anonflow_worker_jobs WHERE tenant_ref=%s AND work_ref=%s",
                           (state["plan"].tenant_ref, state["plan"].work_ref))
    assert _verify(state) is None and state["calls"] == [] and _count(state) == 0


def test_postgresql_lease_replacement_or_completion_during_recovery_is_non_actionable(pg_verification, monkeypatch):
    state = pg_verification
    def replace_lease(_self, **_kwargs):
        with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
            connection.execute("UPDATE anonflow_publication_observations SET observation_epoch=2, "
                "observation_token=%s WHERE tenant_ref=%s AND publication_ref=%s",
                (opaque("observation:v1:"), state["plan"].tenant_ref, state["plan"].publication_ref))
        return state["reference"]
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", replace_lease)
    assert _verify(state) is None and _count(state) == 0


def test_postgresql_completion_during_recovery_is_non_actionable(pg_verification, monkeypatch):
    state = pg_verification
    def complete(_self, **_kwargs):
        with state["psycopg"].connect(state["dsn"], autocommit=True) as connection:
            connection.execute("INSERT INTO anonflow_publication_finalizations "
                "(tenant_ref, publication_ref, completion_digest, result_document) "
                "VALUES (%s,%s,%s,'{}'::jsonb)", (state["plan"].tenant_ref,
                state["plan"].publication_ref, secrets.token_hex(32)))
        return state["reference"]
    monkeypatch.setattr(WorkerEncryptedObjects, "recover", complete)
    assert _verify(state) is None and _count(state) == 0


def test_postgresql_lease_expiring_before_commit_rolls_back_evidence(pg_verification):
    state = pg_verification
    observation_reads = [0]
    class ClockCursor:
        def __init__(self, cursor):
            self._cursor, self._observation = cursor, False
        def execute(self, sql, params=None):
            self._observation = "SELECT observation_epoch, observation_token, state" in sql
            return self._cursor.execute(sql, params)
        def fetchone(self):
            row = self._cursor.fetchone()
            if self._observation:
                observation_reads[0] += 1
                if observation_reads[0] >= 3:
                    return (state["observation"].observation_epoch,
                            state["observation"].observation_token, "OBSERVED", False)
            return row
        def __getattr__(self, name): return getattr(self._cursor, name)
    class ClockConnection:
        autocommit = True
        def __init__(self, connection): self._connection = connection
        def cursor(self): return ClockCursor(self._connection.cursor())
        def close(self): return self._connection.close()
    observation = state["observation"]
    with pytest.raises(PostgresPublicationVerificationError):
        _adapter(state, lambda: ClockConnection(state["connect"]())).verify(
            tenant_ref=observation.tenant_ref, publication_ref=observation.publication_ref,
            observation_epoch=observation.observation_epoch,
            observation_token=observation.observation_token, openbao_token="test-token")
    assert observation_reads[0] >= 3 and _count(state) == 0
