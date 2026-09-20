# M10: operational utility-evidence retention

M10 turns the M9 `utility_evidence` comparison primitive into a bounded,
aggregate-only trusted-worker control. It adds:

- `POST /processing-runs/{run_id}/utility-evidence`, which accepts no request
  body and requires the owning `processor` plus one idempotency key;
- `GET /processing-runs/{run_id}/utility-evidence/{evidence_id}`, available to
  the same tenant's processor or reviewer;
- tenant-scoped, server-owned authorities loaded from
  `ANONFLOW_UTILITY_EVIDENCE_AUTHORITIES`; and
- private-control retention bound to the run, private candidate, processing
  request, method/version/config/taxonomy mapping, policy, rights, tenant, and
  the earlier of the run/candidate expiries.

The create route obtains the stored private source and candidate only inside
the API's trusted worker boundary. A client cannot submit source data,
candidate data, a source commitment, a report, or authority/key material. The
worker creates its own HMAC source commitment and persists only the existing
M9 `DataUtilityReport`: opaque commitment, candidate/provenance digests and
aggregate byte/unit/node/scalar counts with two value-free structural checks.
No source digest, record, field name, path, value, snippet, schema descriptor,
candidate body, commitment secret, or raw key enters the retained record or
HTTP response.

## Local authority configuration

The development authority is explicit; absence means the route fails closed
without computing or retaining evidence. Each tenant has exactly one entry:

```json
[
  {
    "tenant": "tenant-a",
    "key_id": "utility-worker-key-2026-01",
    "key": "base64-encoded-32-to-64-byte-secret"
  }
]
```

Malformed, duplicate, or oversized configuration prevents app startup.
Missing tenant authority, corrupt stored source/candidate, failed commitment,
or non-assessed result returns a fixed failure and writes no utility record.
The configuration's secret is repr-hidden, not persisted, and is not exposed
by either route. Its public authority identity is only a SHA-256 identifier in
the protected control wrapper; it is not a key.

Idempotent replay returns the original verified aggregate record. A changed
record for the same run/key conflicts. Dataset/policy/rights invalidation also
tombstones utility evidence, the candidate, and the run; the evidence cannot
outlive either run or candidate source retention.

## Non-goals

This is still observational `NO_RELEASE_AUTHORIZATION` evidence. It does not
alter run state, cure policy quarantine, qualify a candidate, authorize a
release, export data, issue a delivery credential, or assess semantic utility,
downstream ML quality, fairness, privacy, linkage/re-identification risk, or
legal/contractual suitability. The local in-process authority and development
stores are not KMS/HSM secret custody, a durable production job boundary, or a
production release gate.
