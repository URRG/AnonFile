# M16 independent residual evidence

`POST /processing-runs/{run_id}/independent-residual-evidence` has no request
body and only uses the private candidate plus a tenant-owned local Ed25519 V2
issuer.  It returns and persists aggregate category/unit counts and an opaque
candidate digest only.  It never accepts a client-provided report, raw match,
source, field path, candidate payload, release approval, artifact URL, or
delivery instruction.

The control scans only `PII`, `PAYMENT`, and `CREDENTIAL`.  An attested value
is present for M15 only when every candidate unit was scanned without
abstention; its `maximum_residual_ppm` is the maximum per-family observed unit
rate, so lower is safer and threshold zero requires no observed residual unit.
Unsupported categories, a partial scan, config/tamper/lifecycle drift, expired
issuer, ambiguous evidence selection, or invalid native report are not clean
evidence and retain M15's hold/quarantine semantics.  This remains an
observational control with `NO_RELEASE_AUTHORIZATION`.
