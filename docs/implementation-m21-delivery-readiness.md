# M21 delivery readiness

M21 adds a short-lived, Ed25519-signed, tenant-bound control-plane record. It is issued only after the repository revalidates a live M14 release case, the clean M15 holding decision, the M18 request, and exactly two distinct active M18 approvals (privacy reviewer and release authorizer). The record commits to the case's candidate, rights, server-owned recipient commitment, purpose, and contract digest.

The record is **not** delivery authorization. It never contains artifact bytes, an artifact locator, signed URL, credential, recipient value, contract body, export operation, or transport instruction. A caller that wants an external handoff must operate a separate delivery system and independently revalidate all dependencies.

`POST /release-authorization-requests/{request_id}/delivery-readiness` accepts no body and requires an `Idempotency-Key`. `GET /delivery-readiness/{id}` repeats the complete live dependency verification. Missing configuration, expired signer/case/decision/request/approval, invalid signature, revoked/deleted dependency, tenant mismatch, scope drift, or a missing/duplicate approval fails closed. Case invalidation recursively tombstones readiness records; all other dependency drift is denied on every read even if physical cleanup is delayed.
