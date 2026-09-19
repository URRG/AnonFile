# M2b control-plane contract

M2b extends M2a's synthetic/local development foundation. It builds the
durable control-plane prerequisites for later processing and evaluation. It
does **not** admit customer data, run a background worker, authorize a buyer,
or retain/return any transformed candidate output.

## State that must be explicit and immutable

- A **rights profile** declares the supplier scope, allowed processing
  purposes, allowed recipients, expiry and whether resale is permitted. An
  absent, expired, mismatched or denied profile blocks a run before it is
  registered. A profile never grants export by itself.
- A **policy snapshot** declares supported input formats/languages and the
  sensitivity families: `PII`, `HEALTH_SENSITIVE`, `PAYMENT`, `CREDENTIAL`,
  `BUSINESS_CONFIDENTIAL` and `QUASI_IDENTIFIER`. Unsupported values must
  quarantine/block rather than select a default.
- A **processing run** binds one tenant dataset, rights digest, policy digest,
  named recipient, requested purpose and idempotency key. It records only
  identifiers/digests and bounded operational metadata; it does not embed raw
  source, findings, candidate bytes or protected maps.

`REGISTERED -> RUNNING -> CANDIDATE` and `REGISTERED/RUNNING ->
QUARANTINED|FAILED` are the only initial lifecycle edges. M2b API admission
only creates `REGISTERED`; no endpoint marks a candidate sale-ready. Later
worker integration must use a compare-and-set transition, preserve the same
immutable plan and generate a separate artifact/evaluation record.

## Repository integration

The root integration adds a `controls` record kind to both M2a stores. Records
are JSON dictionaries with explicit `kind`, opaque `id`, `tenant`,
`created_at`, `expires_at` and `size_bytes`. The encrypted SQLite adapter
authenticates them with `tenant/kind/id` AAD and includes them in current-state
commitment verification. Memory and SQLite must have identical tenant,
detachment, expiry and atomic-update behavior.

M2b resource kinds are `rights_profile`, `policy_snapshot` and
`processing_run`. Policy/rights creation is processor-only for the local
development API. Rights and policy reads are same-tenant processor/reviewer;
run creation/list/read is processor/reviewer, and only a separate future
worker identity may advance the state. Reviewer decisions remain unable to
approve/export anything.

Every mutation appends a metadata-only audit event. Public event values never
contain purposes, recipient strings, source hashes, policy content or raw
input. Version/digest values are treated as internal linkage metadata and are
not returned from generic audit endpoints.

## Endpoint boundary for this increment

- `POST /rights-profiles`, `GET /rights-profiles/{id}`
- `POST /policy-snapshots`, `GET /policy-snapshots/{id}`
- `POST /processing-runs` with `Idempotency-Key`
- `GET /processing-runs/{id}`, `GET /processing-runs`

Responses contain state and opaque identifiers/digests suitable for internal
operators; no original/candidate output, approval or download URL is exposed.
Unknown IDs and cross-tenant IDs return the same 404. A reused idempotency key
with a different canonical request returns 409; the same request returns the
original registered run while its bound prerequisites remain live. Expiring or
deleting a prerequisite invalidates dependent registered runs rather than
letting a stale retry survive. Exact artifact delivery, evaluator execution,
protected exception review and any approval/export endpoint are out of scope.

## Completion gate

M2b is complete only with tests for rights/policy fail-closed behavior,
idempotency races, lifecycle transitions, memory/restart-persistent SQLite
behavior, tenant isolation, record/audit integrity and API safe-error/output
negative assertions. The next milestone starts final-output evaluation, not
buyer release.
