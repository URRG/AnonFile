# M2a: secure local ingestion foundation

Synthetic data only. This increment does not authorize customer intake or buyer delivery. `ANONFLOW_ENV=development` remains mandatory. All candidates are withheld and approval returns409. Detection/evaluation coverage is unchanged from M1; parser, persistence and authentication improvements do not prove anonymity.

## Run without Docker

Use Python 3.12/Node 22, install `services/api/requirements-dev.txt` in your virtual environment and `npm ci` in `apps/web`. Export variables explicitly (the API does not automatically load `.env`). Configure unique random development tokens as in `.env.example` and the M1 guide. From `services/api`, run `python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --no-access-log`. From `apps/web`, run `npm run dev -- --host 127.0.0.1`. Bind loopback only. The supplied Compose stack remains the memory/dev-token baseline; it does not mount or configure SQLite/JWKS.

Run backend tests using `python -m pytest -q` from `services/api`; frontend `npm test`, `npm run test:deployment`, `npm run build`, `npm run test:integration` from `apps/web`. For the real-HTTP test, `ANONFLOW_TEST_PYTHON` may specify the absolute venv Python executable. Tests use generated keys/tokens and synthetic fixtures; no model downloads or source egress.

## Optional encrypted SQLite

Set `ANONFLOW_STORAGE_MODE=sqlite`, `ANONFLOW_DB_PATH` to an explicit local database file in an existing private directory, and `ANONFLOW_STORAGE_KEY` to standard base64 encoding of32 cryptographically random bytes. Generate the key once locally, retain it outside the repository/database, and load it securely into the process environment. Example key-generation command: `python -c "import base64,secrets; print(base64.b64encode(secrets.token_bytes(32)).decode())"`. Do not log/share the result. Restart with the same key/path to retain state. Missing/invalid keys, wrong keys and corrupted existing databases fail closed without reinitialization. Loss of key means loss of access.

### Offline local-key rotation

Rotation is a trusted maintenance primitive, deliberately not an HTTP endpoint or
an automatic startup action. Stop every process using the database, retain a
tested encrypted backup and both keys in operator-controlled secret custody,
then invoke `DurableStore.rotate_key(db_path, old_key, new_key,
new_key_id="opaque-operator-label")` from a tightly controlled maintenance
process. The label is ASCII `A-Z`/`a-z`/`0-9`/`.`/`_`/`-`, has no API exposure,
and is sealed in the key-check sentinel only to help an operator identify the
current rotation generation; it is not proof of key custody.

The operation authenticates all current records and audit history using the old
key, re-chains audit MACs under the new derived audit subkey, re-encrypts every
logical record/audit/sentinel row inside one SQLite transaction, and reloads the
entire store under the new key before committing. A wrong old key, malformed or
tampered database, invalid rotation input, write failure, or process exception
before commit leaves the old logical database usable; no plaintext migration
artifact is written. After a successful commit, restart the service with the
new storage key. Do not run concurrent service writers during this local
maintenance operation.

This remains a development adapter, not managed KMS key rotation. SQLite pages,
WAL/journal remnants, backups, filesystem snapshots, RAM and crash dumps may
retain ciphertext encrypted with the old key; physical secure erasure and key
custody/revocation need platform controls. The adapter cannot detect a
whole-database rollback without an external trusted anchor.

Source, normalized records, original serialization, provenance, cards and audit metadata are encrypted with AES-GCM. Separate record/audit keys are derived with HKDF; random nonces and tenant/type/object-bound associated data protect context. Plain indexes expose opaque IDs, tenant labels, byte counts, expiry and audit sequence. Tenant labels must not contain personal information. Decrypted records exist in process memory while handled. OS permissions, disk/process security, backups, key custody and crash-dump controls remain operator responsibilities; this is not managed key infrastructure.

Operations use SQLite transactions and cross-instance quota/parent checks. Each operation authenticates a bounded snapshot, so this intentionally favors simplicity over throughput: it is not a multi-host scalable service. Memory mode remains process-local/single-worker. No production performance claim has been measured.

`DELETE /datasets/{id}` requires a processor in the source tenant and atomically removes the source and dependent releases from active storage while retaining a metadata audit event. Expiry is wall-clock persisted and capped at one hour regardless of a larger requested retention. Cleanup is triggered by access or repository `purge()` calls; no background cleanup SLA exists. Deletion does not guarantee erasure of SQLite free pages, backups, RAM or historical copies. No automated operator job is installed.

Audit is append-only and bounded (10,000 global/2,000 per tenant); new datasets/releases stop at80% to reserve lifecycle space. Exhausting the absolute cap fails mutations closed rather than pruning history. Expired resources remain inaccessible, but physical cleanup can be blocked until an operator handles capacity. There is no archival/migration tool in this increment; do not use this store for real data. HMAC chains and current-record commitments detect authenticated-history inconsistency and isolated record replay; they cannot establish freshness against whole-database rollback or consistent terminal truncation without an external trusted anchor.

## Optional offline access-token verification

Set `ANONFLOW_AUTH_MODE=jwt` and all of:

- `ANONFLOW_JWT_ISSUER`: exact trusted issuer string.
- `ANONFLOW_JWT_AUDIENCE`: exact single-string audience.
- `ANONFLOW_JWKS_PATH`: ordinary local public-only RSA JWKS file, not a URL.
- `ANONFLOW_JWT_BINDINGS`: JSON array of `{"subject":"...","tenant":"...","roles":["processor"]}`. Role values are processor/reviewer/buyer/evaluator; configure distinct review, processing and evaluator subjects.

Accepted tokens require RS256, explicit known `kid`, `typ=at+jwt`, and `iss/aud/sub/exp/iat/nbf`; numeric dates must be finite numbers, not coerced strings/bools. RSA keys must be2048–8192bits. Only the narrow documented JOSE/JWK fields are accepted; token-controlled URLs and unsupported critical headers are rejected. Token tenant/role claims cannot grant access: bindings are authoritative. Invalid tokens return fixed401; unbound subjects/unauthorized roles return403. JWT errors never fall back to development tokens. Do not use ID tokens or paste third-party customer credentials into the workbench.

This is a resource-server verifier, **not** OIDC discovery, browser login, refresh, introspection or automatic key rotation. Revocation/key/binding updates require operator file/config changes and process restart; already issued valid tokens are not checked with an issuer online. Production needs identity-provider integration, lifecycle policies, transport protection and verified rotation/revocation procedures.

## Intake and metadata endpoints

`POST /ingestions` accepts dataset metadata plus explicit `format` (`text`, `json`, `jsonl`, `csv`) and UTF-8-encodable `content` string. No file paths, remote URLs, binary documents or archives are read. The older `/datasets` typed endpoint remains compatible but does not create a serialized-source manifest. The web workbench uses `/ingestions` for all formats.

- Text is nonblank and preserved verbatim. JSON is a nonempty array of objects. JSONL requires nonblank object records; blank physical lines are counted. CSV is comma-delimited, exact unique/nonblank headers, strings only, fixed width, strict quoting; blank physical rows fail the batch. Multiline fields retain physical line intervals.
- Input max2MB UTF-8, max10,000records, depth32/nodes100,000, CSV max256columns, structured keys/strings max100,000characters. Normalized compact JSON is separately bounded to2MB. API wire body max2.1MB includes JSON escaping/metadata, so some nominally2MB sources need smaller requests. No silent chunking or truncation.
- Duplicate JSON keys, nonfinite/overflow/underflow or non-roundtrippable numeric values, malformed quoting, BOM, lone surrogates, sensitive object keys and unsupported shapes fail with fixed errors and no partial intake commit. Numeric values requiring exact high precision should arrive as strings. CSV formulas remain inert strings; future spreadsheet export must implement separate formula-injection protection.
- Source SHA-256/UTF-8 bytes, parser identifier, count, limitations and record/physical-line provenance are retained with the original source. This is record-level provenance, **not** complete field/character span provenance. Parsing success is not privacy qualification.

Responses are metadata only. `GET /datasets/{id}/manifest` permits same-tenant processors/reviewers and excludes source/header values; source hashes are sensitive linkage metadata and never public. `GET /audit` is reviewer-only, returns the newest bounded100events after integrity verification and excludes source/content hashes. Existing release/review routes retain tenant isolation, independent review and no output/approval.

## Outstanding commercial gates

Production database/object store/KMS; OIDC lifecycle; durable jobs/idempotency/backpressure; rights/purpose/recipient policy; scheduled retention and backup erasure; anchored audit; hardened document parsers; field-level provenance; multilingual/contextual detectors; independent residual/linkage attacks; measured privacy/utility thresholds; output-manifest attestation; approved recipient-bound delivery; external security testing and design-partner acceptance. Docker images/Compose must still be exercised once the host engine is available. Native test results are only evidence for this bounded development increment.
