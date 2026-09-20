"""M15 envelope regressions: parser and stable per-case id only."""
import base64
from datetime import UTC, datetime, timedelta

import pytest

from app.privacy_decision import (PrivacyDecision, PrivacyDecisionControl,
                                  PrivacyDecisionAuthority, PrivacyDecisionError)
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
