# M11: operational disclosure-risk evidence

`POST /processing-runs/{run_id}/disclosure-risk-evidence` accepts no body. An
owning processor may trigger only a server-side worker that reads the existing
private candidate and its tenant's configured QID selection. Clients cannot
supply source/candidate records, QID fields, commitments, reports, or keys.

`ANONFLOW_DISCLOSURE_RISK_AUTHORITIES` is a server-only JSON list with one
tenant entry: `tenant`, `key_id`, `expires_at`, base64 32–64 byte `key`, and
private `quasi_identifier_fields`. QID fields are repr-hidden and never enter
the authority identity, API response, control report, or audit metadata. The
worker exposes only M8 aggregate equivalence-class evidence and an opaque HMAC
QID commitment. It HMAC-attests the full report plus tenant, run/request,
candidate, method, policy, rights and idempotency bindings; admission and
retrieval re-verify that signature against the active configured authority.

Evidence expires no later than both candidate and run, is tenant-scoped,
idempotent, and is invalidated with its run dependencies. It is strictly
`OBSERVATIONAL_ONLY`: it never changes run state or authorizes qualification,
release, export, delivery, privacy sufficiency, linkage safety, or legal use.
The local in-process authority is not KMS/HSM custody or a production worker
boundary.
