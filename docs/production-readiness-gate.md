# Production readiness gate: media and evaluation

**Status: BLOCKED / NOT PRODUCTION-READY.** The `/health` route deliberately
returns `production_ready: false`; in production mode the API permits health
and authenticated identity only. Every data, processing, release, and demo
workflow route returns `503`. This is an intentional safety boundary, not an
implementation bug. The synthetic PDF/image preview introduced by the batch
workbench must never be described as a production-safe redaction service.

| Gate | Current evidence | Required exit test |
| --- | --- | --- |
| Untrusted parser isolation | PDFium, Pillow and OCR run in-process in the opt-in development API. Files and pixels are bounded, but a malicious parser input can still affect the API process. | Dedicated non-root worker/container, no network egress, read-only filesystem, cgroup/OS CPU and memory budgets, wall-clock timeout, patched parsers, and malformed-file/fuzz regression. API must not decode untrusted media. |
| Artifact rewriting | Raster pages are newly encoded; PDF candidates are built image-only in memory without copied source objects. The synthetic workbench can save an unqualified local review copy after explicit acknowledgement; PDF/PNG bytes are digest-checked before download. | Deliver a separately reviewed, immutable artifact only after source/candidate provenance binding, hidden-layer/metadata checks, visual QA and reviewer approval. Test real mixed PDF/image cases and failure paths. |
| Detection coverage | Rule matching plus OCR can miss prose names, oblique text, handwriting, low contrast, language variants, images, and sensitive context. Same-engine OCR residual count is not independent. | Independently annotated, rights-cleared, blinded holdout by format/language/entity type; report exact false negatives and uncertainty. Independently inspect final pixels/objects; abstain on unreadable content. See [holdout protocol](holdout-evaluation.md). |
| Privacy and utility | Span agreement does not measure re-identification, linkability, or task utility. | Threat-model buyer and auxiliary data, run linkage/re-identification exercises, quantify task utility, set and validate policy thresholds and escalation decisions for each release profile. |
| Durable data plane | PostgreSQL metadata, encrypted object, key, and worker contracts exist, but are not wired into a deployable end-to-end lifecycle. | Operate the full path with tenant-bound OIDC, encrypted object custody, KMS, fenced queue workers, transactional metadata, immutable audit, controlled delivery, and failure/recovery tests. |
| Operations and assurance | No production deployment, independent security test, backup/deletion proof, incident drill, or production load test has been completed. CI audits resolved dependencies and builds the digest-pinned development API/web images; the local Docker engine was unavailable for this audit. | Reproducible production deployment, periodic base-image digest refresh and vulnerability review, key rotation, observability without source leakage, backup/restore, retention/deletion across replicas, incident response, threat-model review, dependency/SBOM and penetration tests, and measured capacity under adversarial media. |

## Decision rule

The production guard must remain active until **all** gates have signed
evidence and an explicit release decision. A clean demo scorecard, a passing
unit suite, or an opt-in `ANONFLOW_DEMO_MODE=enabled` must not change
`production_ready` or register the media batch route in production. The
regression suite tests that posture. If the safe worker or independent media
holdout is absent, the system must refuse real customer media rather than
degrade to an unverified path.

## Immediate engineering sequence

1. Package a minimal isolated media worker with resource ceilings and no
   network access; move PDF/image decoding and OCR out of the API process.
2. Add media-coordinate findings, reviewer correction, and whole-artifact
   quarantine when OCR confidence/coverage is insufficient.
3. Add an independent final-artifact validator that checks pixels and PDF
   structure with different tools, then a human QA sampling workflow.
4. Run the frozen benchmark on an externally annotated corpus, including
   scanned and mixed PDFs, image formats, and context-sensitive identifiers.
5. Integrate the durable data plane and execute a security/operational pilot
   before changing the production guard.

The actively maintained checkbox tracker is [pending-product-gaps.md](pending-product-gaps.md).
