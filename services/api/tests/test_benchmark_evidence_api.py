"""M17 server-only adapter and M15 freshness regressions."""
from datetime import UTC, datetime, timedelta
import json

from fastapi.testclient import TestClient

from app.benchmark_evidence import CategoryMetrics
from app.benchmark_evidence_profile import BenchmarkEvidenceProfile
from app.evaluation_harness import ScoredEvaluation, ScoringBinding
from app.main import create_app
from app.policies import TAXONOMY_CATEGORIES
from app.processing import RULES_METHOD_CONFIG_DIGEST, RULES_METHOD_VERSION
from app.rules_policy_execution import RULES_TAXONOMY_MAPPING_DIGEST
from test_access import auth
from test_control_plane_api import controls, ingested_dataset, run_request, setup


def digest(letter: str) -> str:
    return "sha256:" + letter * 64


def configure_profile(monkeypatch, *, minimum=2):
    monkeypatch.setenv("ANONFLOW_BENCHMARK_EVIDENCE_PROFILES", json.dumps([{
        "tenant": "tenant-a", "evaluator_subject": "evaluator", "evaluator_id": "m8-harness",
        "evaluator_version": "v1", "evaluator_config_digest": digest("a"), "corpus_digest": digest("d"),
        "detector_id": "rules-v1", "detector_version": RULES_METHOD_VERSION,
        "detector_config_digest": RULES_METHOD_CONFIG_DIGEST,
        "taxonomy_mapping_digest": RULES_TAXONOMY_MAPPING_DIGEST,
        "required_categories": sorted(TAXONOMY_CATEGORIES), "minimum_category_reference_count": minimum,
    }]))


def full_report(*, evaluated_at):
    return ScoredEvaluation(
        binding=ScoringBinding("m8-harness", "v1", digest("a"), "rules-v1", RULES_METHOD_VERSION,
                               RULES_METHOD_CONFIG_DIGEST, RULES_TAXONOMY_MAPPING_DIGEST, digest("d"), digest("e")),
        metrics=tuple(CategoryMetrics(category, 8 if category != "PAYMENT" else 3, 0,
                                       2 if category == "PAYMENT" else 0)
                      for category in sorted(TAXONOMY_CATEGORIES)), evaluated_at=evaluated_at)


def run_and_m8(client, *, measured_at):
    dataset_id = ingested_dataset(client)
    policy, rights = controls(client)
    response = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m17-run-01"},
                           json=run_request(dataset_id, policy["id"], rights["id"]))
    assert response.status_code == 201, response.text
    run = response.json()
    report = full_report(evaluated_at=measured_at)
    signature = client.app.state.evaluator_authorities[0].sign_for_test_or_worker(
        run_id=run["id"], processing_request_digest=run["request_digest"], report=report)
    m8 = client.post(f"/processing-runs/{run['id']}/detector-evaluation-evidence",
                     headers={**auth("evaluator"), "Idempotency-Key": "m17-m8"},
                     json={"report": report.to_record(), "attestation_signature": signature})
    assert m8.status_code == 201, m8.text
    return run, m8.json()


def test_bodyless_fixed_profile_adapter_is_idempotent_source_safe_and_non_authorizing(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); configure_profile(monkeypatch)
    with TestClient(create_app()) as client:
        run, m8 = run_and_m8(client, measured_at=datetime.now(UTC).replace(microsecond=0))
        endpoint = f"/processing-runs/{run['id']}/benchmark-evidence"
        first = client.post(endpoint, headers={**auth(), "Idempotency-Key": "m17-adapter"})
        assert first.status_code == 201, first.text
        item = first.json()
        assert item["conservative_recall_ppm"] == 600_000
        assert item["report_digest"] == m8["report_digest"]
        assert item["posture"] == "OBSERVATIONAL_ONLY" and "NO_RELEASE_AUTHORIZATION" in item["limitations"]
        assert client.post(endpoint, headers={**auth(), "Idempotency-Key": "m17-adapter"}).status_code == 200
        assert client.post(endpoint, headers={**auth(), "Idempotency-Key": "m17-body"}, json={}).status_code == 422
        assert client.post(endpoint, headers={**auth("reviewer"), "Idempotency-Key": "m17-role"}).status_code == 403
        assert client.post(endpoint, headers={**auth("other"), "Idempotency-Key": "m17-other"}).status_code == 404
        assert "reference_digest" not in first.text and "case_id" not in first.text
        stored = client.app.state.store.get_control("benchmark_evidence", item["id"], "tenant-a")["payload"]
        assert set(stored) == {"run_id", "processing_request_digest", "policy_digest", "rights_digest", "method_id",
                               "method_version", "method_config_digest", "taxonomy_mapping_digest", "idempotency_key",
                               "source_evidence_id", "assessment"}
        assert client.get(f"/processing-runs/{run['id']}", headers=auth()).json() == run
        # M15 consumes M17, not naked M8: an adapter/case method mismatch is
        # a quarantining policy input rather than a score that can be reused.
        assert client.post(f"/processing-runs/{run['id']}/execute", headers=auth()).status_code == 200
        case = client.post(f"/processing-runs/{run['id']}/release-cases", headers={**auth(), "Idempotency-Key": "m17-case-method"}).json()
        client.app.state.store.controls["benchmark_evidence"][item["id"]]["payload"]["method_id"] = "rules-v999"
        held = client.post(f"/release-cases/{case['id']}/privacy-decisions",
                           headers={**auth(), "Idempotency-Key": "m17-method-hold"})
        assert held.status_code == 201 and held.json()["outcome"] == "QUARANTINED"


def test_requires_exactly_one_verified_m8_source_and_rejects_source_signature_drift(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); configure_profile(monkeypatch)
    with TestClient(create_app()) as client:
        dataset_id = ingested_dataset(client); policy, rights = controls(client)
        run = client.post("/processing-runs", headers={**auth(), "Idempotency-Key": "m17-no-source"},
                          json=run_request(dataset_id, policy["id"], rights["id"])).json()
        endpoint = f"/processing-runs/{run['id']}/benchmark-evidence"
        assert client.post(endpoint, headers={**auth(), "Idempotency-Key": "m17-none"}).status_code == 409
        report = full_report(evaluated_at=datetime.now(UTC).replace(microsecond=0))
        signer = client.app.state.evaluator_authorities[0]
        signature = signer.sign_for_test_or_worker(run_id=run["id"], processing_request_digest=run["request_digest"], report=report)
        for key in ("m17-source-a", "m17-source-b"):
            result = client.post(f"/processing-runs/{run['id']}/detector-evaluation-evidence",
                                 headers={**auth("evaluator"), "Idempotency-Key": key},
                                 json={"report": report.to_record(), "attestation_signature": signature})
            assert result.status_code == 201, result.text
        assert client.post(endpoint, headers={**auth(), "Idempotency-Key": "m17-many"}).status_code == 409
        # A fresh single-source run demonstrates that M17 read paths recheck
        # the M8 signature rather than trusting the stored adapter aggregate.
        fresh, _ = run_and_m8(client, measured_at=datetime.now(UTC).replace(microsecond=0))
        fresh_endpoint = f"/processing-runs/{fresh['id']}/benchmark-evidence"
        item = client.post(fresh_endpoint, headers={**auth(), "Idempotency-Key": "m17-signature"}).json()
        source = client.app.state.store.controls["detector_evaluation_evidence"][
            client.app.state.store.controls["benchmark_evidence"][item["id"]]["payload"]["source_evidence_id"]]
        source["payload"]["attestation_signature"] = "evalsig:v1:" + "A" * 43
        assert client.get(f"{fresh_endpoint}/{item['id']}", headers=auth()).status_code == 503


def test_profile_drift_and_old_native_measurement_fail_closed_for_m15(monkeypatch, tmp_path):
    setup(monkeypatch, tmp_path); configure_profile(monkeypatch)
    with TestClient(create_app()) as client:
        instant = datetime.now(UTC).replace(microsecond=0)
        run, _ = run_and_m8(client, measured_at=instant - timedelta(hours=2))
        endpoint = f"/processing-runs/{run['id']}/benchmark-evidence"
        item = client.post(endpoint, headers={**auth(), "Idempotency-Key": "m17-old"}).json()
        assert client.post(f"/processing-runs/{run['id']}/execute", headers=auth()).status_code == 200
        case = client.post(f"/processing-runs/{run['id']}/release-cases", headers={**auth(), "Idempotency-Key": "m17-case"}).json()
        decision = client.post(f"/release-cases/{case['id']}/privacy-decisions", headers={**auth(), "Idempotency-Key": "m17-decision"})
        assert decision.status_code == 201 and decision.json()["outcome"] == "INSUFFICIENT_EVIDENCE"
        assert "EVIDENCE_STALE" in decision.json()["reasons"]
        assert "BENCHMARK" in {entry["kind"] for entry in decision.json()["evidence"]}
        old = client.app.state.benchmark_evidence_profiles[0]
        client.app.state.benchmark_evidence_profiles = (BenchmarkEvidenceProfile(
            **{**old.canonical(), "required_categories": tuple(old.required_categories),
               "minimum_category_reference_count": 11}),)
        assert client.get(f"/processing-runs/{run['id']}/benchmark-evidence/{item['id']}", headers=auth()).status_code == 503
