# Scoring, Release Cards, and decisions

## Principles

Scores summarize evidence; they do not decide legality, erase residual risk, or override hard policy gates. Every score reports its inputs, version, confidence, and missing evidence. A missing required measurement routes the release to review or block.

## Scores

| Score | Direction | Evidence |
| --- | --- | --- |
| Privacy risk | 0–100; lower is safer | residual findings, severity, detector disagreement, quasi-identifier uniqueness, linkability, attack success, recipient controls |
| Utility / legibility | 0–100; higher is better | structural validity, readability, semantic preservation, entity/relationship consistency, downstream task retention |
| Subjectivity | 0–100 | opinion/sentiment density, speculation, first-person judgement, citations/evidence signals, classifier disagreement |
| Sensitivity | `Public`, `Internal`, `Confidential`, `Restricted` | policy classification and sensitive-category tags |

Privacy risk uses fixed initial weights: residual severity 35%, attack-test result 25%, quasi-identifier/linkability 20%, detection uncertainty 10%, recipient/access context 10%. Utility uses: semantic preservation 25%, entity consistency 25%, relationship preservation 20%, structural validity 15%, task retention 15%.

Weights are versioned policy values, never hidden model behavior. They are calibrated against synthetic benchmarks and may be changed only through policy review with a recorded rationale.

### Legibility and subjectivity

Legibility measures whether transformed data remains understandable and usable, not whether it is factually correct. Subjectivity describes opinion/judgement content; it is a routing and fitness signal, not a privacy or truth score.

Task retention is evaluated inside the secure environment:

```text
task retention = anonymized task score / raw task score
```

The raw result is retained as protected evaluation evidence, not included in a release.

## Hard release gates

| Outcome | Trigger |
| --- | --- |
| `BLOCKED` | Credential found; critical residual direct identifier; failed attack threshold; missing provenance; failed mandatory control |
| `REVIEW_REQUIRED` | Low-confidence sensitive finding; incomplete benchmark coverage; high sensitivity; unresolved entity ambiguity; utility below policy target |
| `APPROVED_RESTRICTED` | Policy passes only with enclave/no-download, named recipient, expiry, watermark, or dual approval |
| `APPROVED_ANONYMIZED` | External-mode policy and all required contextual validation tests pass |

Humans may request a stricter rerun, reject a release, or approve a reviewable result under policy. They may not downgrade a critical `BLOCKED` finding; a new release run must provide new evidence.

## Release Card

A Release Card is a signed, immutable JSON document plus human-readable rendering. Its minimum fields are:

```json
{
  "release_id": "uuid",
  "content_digest": "sha256:...",
  "tenant_id": "opaque-id",
  "mode": "anonymized_external",
  "decision": "APPROVED_ANONYMIZED",
  "policy": {"id": "external-v1", "version": "1.0.0", "digest": "sha256:..."},
  "provenance": {"dataset_id": "opaque-id", "purpose": "model-evaluation", "recipient_class": "named-buyer"},
  "scores": {},
  "findings_summary": {},
  "validation": {"detectors": [], "attack_tests": [], "benchmark_coverage": []},
  "transformations": {},
  "restrictions": [],
  "created_at": "RFC3339 timestamp",
  "signature": {"algorithm": "ed25519", "key_id": "customer-kms-key"}
}
```

It includes no raw sensitive values, mapping keys, or plaintext detector spans. It binds output integrity, policy and model versions, destination context, validation evidence, reviewer identity references, retention/expiry, and signature.
