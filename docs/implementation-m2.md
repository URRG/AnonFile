# M2a: container-independent secure ingestion foundation

Scope: synthetic/local development only. Production startup remains refused and all
candidate output/approval/export remains disabled. SQLite is a durable local adapter,
not a claim of production PostgreSQL/KMS/worker readiness. Signed JWT verification is
an offline resource-server adapter, not a browser login flow or full OIDC deployment.

## Exclusive ownership

- Storage agent: app/repository.py, app/durable_repository.py, tests/test_repository.py.
- Identity agent: app/security.py, app/token_auth.py, tests/test_token_auth.py.
- Ingestion agent: app/ingestion.py, tests/test_ingestion.py.
- Orchestrator: main.py, other integration tests, frontend, configuration/dependencies,
  documentation and CI. Only orchestrator may stage, commit, push or merge.

All paths above are relative to services/api. No other owned-file edits, no customer
data, model downloads or source egress. Communicate before changing interfaces.

## Repository interface

Keep DevelopmentStore and its existing test-visible datasets/releases/lock/constants.
Add the following common methods to memory and durable adapters. API will not access
maps/locks directly after integration. Records are ordinary JSON-compatible dictionaries;
created_at/generated_at are ISO timestamps; cards/events are dictionaries, not Pydantic.

- add_dataset(record): atomic insert plus dataset.created audit.
- list_datasets(tenant): detached copies, expiry enforced.
- get_dataset(identifier, tenant): detached copy, 404 missing/foreign/expired.
- add_release(record): atomic insert, check parent still exists/unexpired in same tenant,
  release quotas under same transaction, record release.created audit.
- get_release(identifier, tenant): detached copy, same isolation.
- reject_release(identifier, tenant, reviewer, decided_at): atomic independent-review
  checks; only REVIEW_REQUIRED -> BLOCKED, new card revision/gate REVIEW_REJECTED;
  preserve prior card event; append review.rejected audit. Return detached record.
- delete_dataset(identifier, tenant, actor): delete source and dependent releases
  atomically, append dataset.deleted audit. Missing/foreign ->404.
- purge(): remove expired sources/releases, record system expiry event; return count.
- audit_events(tenant, limit=100): bounded metadata only (actor/action/object_id/time/seq),
  chronological newest tail; verify chain before returning; no raw data or hashes needed.
- verify_audit(tenant): true if local chain verifies; integrity corruption -> safe503.
- close(): release resources (memory no-op).

Use HTTPException404/409/429/503 fixed messages. Retain existing quotas and one-hour
maximum development retention; use wall-clock time for persisted expiry. No secure
erasure/backup deletion guarantee. Audit metadata is retained and separately bounded.

DurableStore(path: str, key: bytes) uses a32-byte caller-supplied key, AES-GCM encrypted
record blobs with tenant/type/id AAD, fresh random nonces, parameterized SQLite queries,
schema version, key-verification sentinel, atomic writes and cross-instance concurrency
checks. Derive separate audit/encryption subkeys with HKDF. Chain audit events with HMAC;
document that whole-DB rollback and terminal truncation require external anchoring.
Unencrypted indexes: opaque IDs, tenant, byte counters and expiry only; never raw source.
Existing key mismatch/corruption fails closed without modifying/reinitializing the DB.

## Identity interface

Keep Principal(subject,tenant,roles), load_principals and require_roles compatibility.
Add configure_auth(app) called at startup instead of directly calling load_principals.
ANONFLOW_ENV development-only remains mandatory. ANONFLOW_AUTH_MODE dev-token(default)
or jwt; no fallback between modes. JWT config: ANONFLOW_JWT_ISSUER, ANONFLOW_JWT_AUDIENCE,
ANONFLOW_JWKS_PATH (local public key bundle), ANONFLOW_JWT_BINDINGS JSON array of
{subject,tenant,roles}; issuer and audience exact server-configured values. Tenant and
roles come only from bindings, never token claims. Allowed algorithm RS256 only; require
explicit kid, RSA>=2048, iss/aud/sub/exp/iat/nbf, bounded input, strict numeric time claims,
no token-supplied URLs/algorithm switching, no network. Rejection401 fixed; configured
subject without binding403. Malformed configuration startup refusal with safe errors.
Require token header typ=at+jwt to avoid accepting ID tokens as access tokens. Offline
JWKS rotation/revocation requires operator config update+restart; no refresh flow yet.

## Ingestion interface

parse_source(*, content: str, format: str) -> ParsedSource dataclass with content:
str|None, records:list[dict]|None, manifest:dict, provenance:tuple[dict,...].
Exactly one normalized content/records populated. Formats text/json/jsonl/csv.
Fixed safe IngestionError(ValueError), no partial batch acceptance.
Limits2MB UTF8,10k records,depth32,nodes100k,CSV256columns, perfield bounded.
JSON duplicate members/nonfinite/lone surrogate/unsupported structures rejected;
JSON root array of objects only. JSONL each nonblank line object; blank lines counted.
CSV preserve strings, never infer types; strict headers/column counts, blank rows fail
closed rather than disappear; multiline records retain physical source line intervals.
No formula execution, no URL/file I/O; no new parsers/dependencies beyond stdlib.
Manifest fields: format, source_sha256, source_bytes, record_count, parser_id,
blank_lines (where relevant), limitations:list[str]. Provenance per record has
record_index and line_start/line_end when applicable (JSON array uses record_index).
No raw field values/headers/filenames in manifest/errors/provenance.

## Integration and release gate

Orchestrator selects ANONFLOW_STORAGE_MODE memory(default) or sqlite, explicit
ANONFLOW_DB_PATH plus base64 ANONFLOW_STORAGE_KEY; no key/default path generation.
Add POST/ingestions with explicit format/content+dataset metadata and return metadata
only; retain original serialized source privately along with parsed source/provenance.
Add authenticated DELETE/datasets/{id} and reviewer GET/audit, preserve all old routes.
All evaluation/approval/output safety gates remain unchanged. Cross-review AFTER
checkpoint commits, fix regressions, verify fresh suites; no unreviewed remote merge.
