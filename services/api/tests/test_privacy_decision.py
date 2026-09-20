"""M15 envelope regressions: parser and stable per-case id only."""
import base64
import json
import types
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from concurrent.futures import ThreadPoolExecutor

from app.privacy_decision import (PrivacyDecision, PrivacyDecisionControl,
                                  PrivacyDecisionAuthority, PrivacyDecisionError,
                                  load_privacy_decision_controls)
from app.privacy_evidence_authority import PrivacyEvidenceAttestationAuthority
from app.privacy_evidence_policy import PrivacyEvidenceBinding, PrivacyEvidenceKind, assess_privacy_evidence
from app.repository import DevelopmentStore
import app.main as main_module
import app.repository as repository_module
from app.main import create_app
from test_access import auth
from test_control_plane_api import controls, ingested_dataset, run_request, setup

D = "sha256:" + "a" * 64
R = "b" * 64
CASE = "release-case:v1:" + "A" * 43


def test_signed_envelope_round_trips_and_rejects_mutation():
    now = datetime.now(UTC).replace(microsecond=0)
    expiry = now + timedelta(days=10)
    key = lambda char: base64.b64encode(char.encode() * 32).decode()
    signer = PrivacyDecisionAuthority("tenant-a", "decision-a", expiry, key("a"))
    pairs = tuple((kind, PrivacyEvidenceAttestationAuthority("tenant-a", "issuer-" + kind.value.lower(), expiry, key(chr(98 + i))))
                  for i, kind in enumerate(PrivacyEvidenceKind))
    thresholds = ((PrivacyEvidenceKind.BENCHMARK, 1_000_000), (PrivacyEvidenceKind.DISCLOSURE_RISK, 1),
                  (PrivacyEvidenceKind.LINKAGE, 0), (PrivacyEvidenceKind.RESIDUAL_SCAN, 0), (PrivacyEvidenceKind.UTILITY, 1_000_000))
    control = PrivacyDecisionControl(signer, 60, thresholds, pairs)
    binding = PrivacyEvidenceBinding(D, D, R, D, "purpose-a", D, now + timedelta(hours=1))
    policy = control.policy(binding)
    outcome = assess_privacy_evidence(decision_id="policy-a", binding=binding, policy=policy, evidence=(),
                                      authorities=tuple(item.policy_verifier for _, item in pairs), at=now)
    item = signer.issue(decision_id=control.decision_identifier(case_id=CASE, idempotency_key="key-a"),
                        case_id=CASE, case_digest=D, decision=outcome, evidence_references=(),
                        expires_at=now + timedelta(minutes=30), at=now)
    rebuilt = PrivacyDecision.from_record(item.to_record())
    assert rebuilt == item and signer.verifies(rebuilt, at=now)
    altered = item.to_record(); altered["case_digest"] = "sha256:" + "c" * 64
    with pytest.raises(PrivacyDecisionError):
        PrivacyDecision.from_record(altered)
    assert control.decision_identifier(case_id=CASE, idempotency_key="key-a") == item.decision_id


def test_documented_m15_configuration_shape_loads_with_valid_disclosure_floor(monkeypatch):
    """Keep the copyable env contract aligned with M12's disclosure domain."""
    expiry = (datetime.now(UTC).replace(microsecond=0) + timedelta(days=10)).isoformat().replace("+00:00", "Z")
    encoded = lambda char: base64.b64encode(char.encode() * 32).decode()
    requirements = [
        {"kind": "RESIDUAL_SCAN", "threshold": 0, "issuer_key_id": "privacy-residual", "key": encoded("b")},
        {"kind": "DISCLOSURE_RISK", "threshold": 1, "issuer_key_id": "privacy-disclosure", "key": encoded("c")},
        {"kind": "UTILITY", "threshold": 1_000_000, "issuer_key_id": "privacy-utility", "key": encoded("d")},
        {"kind": "LINKAGE", "threshold": 0, "issuer_key_id": "privacy-linkage", "key": encoded("e")},
        {"kind": "BENCHMARK", "threshold": 1_000_000, "issuer_key_id": "privacy-benchmark", "key": encoded("f")},
    ]
    monkeypatch.setenv("ANONFLOW_PRIVACY_DECISION_AUTHORITIES", json.dumps([{
        "tenant": "tenant-a", "issuer_key_id": "privacy-decision-a", "expires_at": expiry,
        "private_key": encoded("a"), "max_evidence_age_seconds": 3600, "requirements": requirements,
    }]))
    loaded = load_privacy_decision_controls()
    assert len(loaded) == 1
    assert dict(loaded[0].thresholds)[PrivacyEvidenceKind.DISCLOSURE_RISK] == 1


def test_quarantined_signed_tombstone_is_retrievable_without_a_live_release_case():
    """A sticky hold retains its audit record but cannot revive a case handle."""
    now = datetime.now(UTC).replace(microsecond=0)
    expiry = now + timedelta(days=10)
    key = lambda char: base64.b64encode(char.encode() * 32).decode()
    signer = PrivacyDecisionAuthority("tenant-a", "decision-a", expiry, key("a"))
    pairs = tuple((kind, PrivacyEvidenceAttestationAuthority("tenant-a", "issuer-" + kind.value.lower(), expiry, key(chr(98 + i))))
                  for i, kind in enumerate(PrivacyEvidenceKind))
    thresholds = ((PrivacyEvidenceKind.BENCHMARK, 1_000_000), (PrivacyEvidenceKind.DISCLOSURE_RISK, 1),
                  (PrivacyEvidenceKind.LINKAGE, 0), (PrivacyEvidenceKind.RESIDUAL_SCAN, 0), (PrivacyEvidenceKind.UTILITY, 1_000_000))
    control = PrivacyDecisionControl(signer, 60, thresholds, pairs)
    binding = PrivacyEvidenceBinding(D, D, R, D, "purpose-a", D, now + timedelta(hours=1))
    policy = control.policy(binding)
    outcome = assess_privacy_evidence(decision_id="policy-a", binding=binding, policy=policy, evidence=(object(),),
                                      authorities=tuple(item.policy_verifier for _, item in pairs), at=now)
    item = signer.issue(decision_id=control.decision_identifier(case_id=CASE, idempotency_key="key-a"),
                        case_id=CASE, case_digest=D, decision=outcome, evidence_references=(),
                        expires_at=now + timedelta(minutes=30), at=now)
    assert item.decision.outcome.value == "QUARANTINED"
    store = DevelopmentStore()
    store.controls["privacy_decision"][item.decision_id] = {
        "id": item.decision_id, "kind": "privacy_decision", "tenant": "tenant-a", "created_at": now.isoformat(),
        "expires_at": item.expires_at.timestamp(), "size_bytes": 0,
        "payload": {"case_id": CASE, "run_id": "run-a", "idempotency_key": "key-a", "decision": item.to_record()},
    }
    assert store.get_privacy_decision(item.decision_id, "tenant-a", signer, None)["id"] == item.decision_id


def test_api_server_derives_a_case_bound_holding_and_reuses_same_key(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        dataset_id = ingested_dataset(client)
        policy, rights = controls(client)
        run = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m15-run-api"},
                          json=run_request(dataset_id, policy["id"], rights["id"])).json()
        assert client.post(f"/processing-runs/{run['id']}/execute", headers=auth()).status_code == 200
        case = client.post(f"/processing-runs/{run['id']}/release-cases", headers={**auth(), "Idempotency-Key": "m15-case-api"}).json()
        first = client.post(f"/release-cases/{case['id']}/privacy-decisions", headers={**auth(), "Idempotency-Key": "m15-decision-api"})
        assert first.status_code == 201, first.text
        item = first.json()
        assert item["outcome"] == "INSUFFICIENT_EVIDENCE" and item["posture"] == "NO_RELEASE_AUTHORIZATION"
        assert client.post(f"/release-cases/{case['id']}/privacy-decisions", headers={**auth(), "Idempotency-Key": "m15-decision-api"}).status_code == 200
        assert client.get(f"/privacy-decisions/{item['id']}", headers=auth("reviewer")).status_code == 200


def _case_with_native_utility(client, *, suffix):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    run = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m15-run-" + suffix},
                      json=run_request(dataset_id, policy["id"], rights["id"])).json()
    assert client.post(f"/processing-runs/{run['id']}/execute", headers=auth()).status_code == 200
    utility = client.post(f"/processing-runs/{run['id']}/utility-evidence", headers={**auth(), "Idempotency-Key": "m15-util-" + suffix})
    assert utility.status_code == 201, utility.text
    case = client.post(f"/processing-runs/{run['id']}/release-cases", headers={**auth(), "Idempotency-Key": "m15-case-" + suffix})
    assert case.status_code == 201
    return run, case.json(), utility.json()


def test_m15_same_key_replay_refuses_expired_native_evidence_and_policy_drift(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        run, case, utility = _case_with_native_utility(client, suffix="stale")
        headers = {**auth(), "Idempotency-Key": "m15-decision-stale"}
        assert client.post(f"/release-cases/{case['id']}/privacy-decisions", headers=headers).status_code == 201
        native = client.app.state.store.controls["utility_evidence"][utility["id"]]
        native["expires_at"] = 1
        assert client.post(f"/release-cases/{case['id']}/privacy-decisions", headers=headers).status_code != 200
    setup(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        _, case, _ = _case_with_native_utility(client, suffix="drift")
        headers = {**auth(), "Idempotency-Key": "m15-decision-drift"}
        assert client.post(f"/release-cases/{case['id']}/privacy-decisions", headers=headers).status_code == 201
        control = client.app.state.privacy_decision_controls[0]
        changed = list(control.thresholds); changed[0] = (changed[0][0], changed[0][1] - 1)
        client.app.state.privacy_decision_controls = (PrivacyDecisionControl(control.decision_authority, control.max_evidence_age_seconds,
            tuple(changed), control.evidence_authorities),)
        assert client.post(f"/release-cases/{case['id']}/privacy-decisions", headers=headers).status_code != 200


def test_m15_quarantine_is_sticky_tombstone_and_same_key_race_is_one_record(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        run, case, utility = _case_with_native_utility(client, suffix="quarantine")
        # Corrupt an otherwise originally attested native control; the M15
        # adapter must quarantine rather than silently omit it.
        client.app.state.store.controls["utility_evidence"][utility["id"]]["payload"]["attestation_signature"] = "utilsig:v1:" + "A" * 43
        response = client.post(f"/release-cases/{case['id']}/privacy-decisions", headers={**auth(), "Idempotency-Key": "m15-q"})
        assert response.status_code == 201, response.text
        item = response.json(); assert item["outcome"] == "QUARANTINED"
        assert client.get(f"/release-cases/{case['id']}", headers=auth()).status_code == 404
        assert client.get(f"/processing-runs/{run['id']}", headers=auth()).json()["state"] == "QUARANTINED"
        assert client.get(f"/privacy-decisions/{item['id']}", headers=auth("reviewer")).status_code == 200
        assert "body" not in client.get(f"/privacy-decisions/{item['id']}", headers=auth("reviewer")).text
    setup(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        _, case, _ = _case_with_native_utility(client, suffix="race")
        def post(): return client.post(f"/release-cases/{case['id']}/privacy-decisions", headers={**auth(), "Idempotency-Key": "m15-race"}).status_code
        with ThreadPoolExecutor(max_workers=4) as pool: codes = list(pool.map(lambda _: post(), range(4)))
        assert set(codes) <= {200, 201} and codes.count(201) == 1
        assert len(client.app.state.store.controls["privacy_decision"]) == 1


def test_m15_fresh_write_survives_a_cross_second_store_transaction(monkeypatch, tmp_path):
    """The API's signed timestamp may precede the atomic store clock by 1s."""
    setup(monkeypatch, tmp_path)
    with TestClient(create_app()) as client:
        _, case, _ = _case_with_native_utility(client, suffix="clock")
        instant = datetime.now(UTC).replace(microsecond=0)
        monkeypatch.setattr(main_module, "now", lambda: instant)
        monkeypatch.setattr(repository_module, "datetime", types.SimpleNamespace(
            now=lambda _tz: instant + timedelta(seconds=1), fromtimestamp=datetime.fromtimestamp))
        response = client.post(f"/release-cases/{case['id']}/privacy-decisions",
                               headers={**auth(), "Idempotency-Key": "m15-clock"})
        assert response.status_code == 201, response.text
