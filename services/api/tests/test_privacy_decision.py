"""M15 envelope regressions: parser and stable per-case id only."""
import base64
import json
from datetime import UTC, datetime, timedelta

import pytest

from app.privacy_decision import (PrivacyDecision, PrivacyDecisionControl,
                                  PrivacyDecisionAuthority, PrivacyDecisionError,
                                  load_privacy_decision_controls)
from app.privacy_evidence_authority import PrivacyEvidenceAttestationAuthority
from app.privacy_evidence_policy import PrivacyEvidenceBinding, PrivacyEvidenceKind, assess_privacy_evidence

D = "sha256:" + "a" * 64
R = "b" * 64


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
    item = signer.issue(decision_id=control.decision_identifier(case_id="case-a", idempotency_key="key-a"),
                        case_id="case-a", case_digest=D, decision=outcome, evidence_references=(),
                        expires_at=now + timedelta(minutes=30), at=now)
    rebuilt = PrivacyDecision.from_record(item.to_record())
    assert rebuilt == item and signer.verifies(rebuilt, at=now)
    altered = item.to_record(); altered["case_digest"] = "sha256:" + "c" * 64
    with pytest.raises(PrivacyDecisionError):
        PrivacyDecision.from_record(altered)
    assert control.decision_identifier(case_id="case-a", idempotency_key="key-a") == item.decision_id


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
