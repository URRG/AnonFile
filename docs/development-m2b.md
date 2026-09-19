# M2b control-plane development guide

M2b remains synthetic/local development software. It registers immutable,
tenant-scoped control records before later processing work; it does not start a
worker, create a candidate data artifact, approve a buyer, or expose a
download. Do not submit customer data.

## Control records

An operator first creates a policy snapshot and supplier rights profile. A
processing-run request then names an ingested dataset, one rights-profile
record, one policy-snapshot record, a recipient, a purpose, a release mode and
an `Idempotency-Key` header. The server verifies all of these before persisting
only a `REGISTERED` run.

Rights profiles are exact, lower-case identifier lists: no wildcards or partial
matching. They include a UTC expiry and explicit resale permission. An unknown,
expired, recipient-mismatched, purpose-mismatched or non-resale profile blocks
the request. The profile is **not** a contract interpreter and does not grant
release authority.

Policy snapshots list supported input format/language/release modes and rules
for PII, health-sensitive data, payment data, credentials, business-confidential
data and quasi-identifiers. Unknown categories and unsupported settings fail
closed. A policy is a processing instruction, not a measurement that its
detectors work or that a dataset is anonymous.

M2b requires a source accepted through `/ingestions`: legacy `/datasets`
requests lack a serialized-source manifest and are rejected from a processing
run. The named source must stay within the same tenant as the controls.

## API lifecycle

`POST /rights-profiles` and `POST /policy-snapshots` are processor-only.
Same-tenant processors/reviewers may read them. `POST /processing-runs` is
processor-only and requires exactly one `Idempotency-Key` header; replaying the
same canonical request returns the prior run while its dataset, rights profile
and policy snapshot remain live. Expiry/deletion invalidates dependent
registered runs rather than retaining a stale request. Using that key with a
different request returns 409. Read endpoints are tenant-scoped.

Only `REGISTERED` is reachable through this API. The domain model defines the
future state graph `REGISTERED -> RUNNING -> CANDIDATE`, with quarantine/failure
edges and bounded retries, but M2b deliberately ships no worker role or
transition endpoint. A `CANDIDATE`, when later implemented, will still require
independent evaluation and buyer/use authorization. Neither reviewers nor
processors can approve/export through M2b.

The controls are encrypted at rest in optional local SQLite alongside M2a
records and protected by the same tenant/type/object binding, audit chain and
current-record commitment checks. Memory mode loses them on restart. SQLite
records retain them only until their persisted local development expiry, capped
at one hour, and logical deletion is not secure erasure or backup cleanup.

## Explicit non-goals

No rights document ingestion, legal interpretation, policy editing after
sealing, identity-provider workflow, job queue, output storage, transformation
execution, residual evaluation, review approval, buyer grant, signed artifact
or export exists yet. The system emits no claim that an acquired dataset may be
resold. M2b control digests are internal linkage metadata and public audit
events deliberately omit them.

Run `python -m pytest -q` from `services/api` for backend tests. Existing
M2a setup guidance remains in [development-m2.md](development-m2.md). Docker
runtime validation is still pending on this host.
