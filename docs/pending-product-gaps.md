# Product gap tracker

This is the living checklist after PR #86. Check a box only when its exit test
has passed and the evidence is linked here. A passing synthetic demo is not a
privacy qualification, release authorization, or permission to process real
supplier data. `Blocked externally` is not the same as done.

## Demo quality and review workflow

- [x] **D01 — Correct demo documentation.** Remove stale statements that PDFs
  cannot be downloaded or that relationships are only mail rows; keep the
  synthetic-only and review-required warnings. Exit: docs match the current API
  and UI, and the documentation test/lint path passes. Evidence: PR #86 demo
  guide plus updated roadmap/production gate on this branch; `git diff --check`
  and linked-file existence checks pass. No dedicated Markdown linter exists.
- [ ] **D02 — Contextual sensitive-value coverage.** Detect explicitly labelled
  employee IDs, internal URLs and postal addresses in TXT, structured files,
  and OCR text without promoting arbitrary prose or public links into PII.
  Exit: positive, negative, cross-file and OCR-regression tests; findings and
  residuals are visible in the review register and candidate.
- [ ] **D03 — Safe, useful replacements for D02.** Preserve relationship and
  document utility while avoiding live internal hosts, contact points and
  fake claims of non-issuable employee IDs or addresses. Exit: deterministic
  batch-local surrogates, collision tests, format/safety labels, and explicit
  abstention when no safe profile exists.
- [ ] **D04 — Media coordinate review.** Let a reviewer add or correct a missed
  region on a PDF/image, not only a phrase already found by OCR. Exit: bounded
  page boxes, visual diff, source/candidate provenance and rejection of
  out-of-page or overlapping unsafe edits.
- [ ] **D05 — Reading-order and layout fidelity.** Test text, tables, forms,
  scanned PDFs, screenshots and images at supported limits; preserve readable
  output or abstain. Exit: visual regression corpus with explicit overlap,
  blur and unprocessed-region failure cases.
- [ ] **D06 — Graph provenance and adjudication.** Link an edge to exact
  page/line/span evidence, support reviewer accept/reject and identity
  merge/split, and flag conflicts. Exit: evidence navigation and graph
  correction tests across at least three documents.
- [ ] **D07 — Independent demo scorecard.** Evaluate untouched final pixels and
  text with a different engine/annotated ground truth; separate automatic
  detector scores from reviewer corrections and measure graph/link quality.
  Exit: reproducible per-format/per-type false-negative report and abstention.
- [ ] **D08 — Accessible, scalable review UI.** Test keyboard, screen-reader,
  zoom, responsive layout and a larger batch; keep a navigable table fallback
  when a graph is too dense. Exit: automated checks plus a human walkthrough.

## Detection and transformation research

- [ ] **R01 — Evidence-based recognizer plug-ins.** Add versioned,
  country/industry-aware recognizers for free-text people, addresses,
  organizations, indirect identifiers, health and business-sensitive context.
  Exit: frozen, rights-cleared holdout results by type/language/source format;
  do not claim completeness from synthetic examples.
- [ ] **R02 — Jurisdiction-specific surrogate registry.** Record issuer,
  validation basis, format-preserving status, collision risk and abstention for
  each identifier family. Passport/licence numbers stay opaque until a
  documented non-issuable namespace exists. Exit: issuer-specific tests and
  negative collision cases, not just plausible-looking strings.
- [ ] **R03 — Cross-document identity resolution.** Resolve aliases using
  explicit evidence with ambiguity/conflict tracking rather than exact-name
  equality alone. Exit: homonym, alias, shared mailbox and changed-name tests.
- [ ] **R04 — Independent privacy and utility qualification.** Run final
  artifact leakage checks, linkage/re-identification exercises and task-utility
  benchmarks on representative, legally usable data. Exit: policy-bound
  thresholds, uncertainty, human review, and a signed qualification decision.
  **Blocked externally:** representative rights-cleared corpora and buyer task
  criteria are not yet supplied.

## Production and commercial release gates

- [ ] **P01 — Isolate untrusted media.** Move PDF/image decoding and OCR out of
  the API into non-root, no-egress, resource-limited workers. Exit: malformed
  media, timeout, memory and crash isolation tests.
- [ ] **P02 — Operable durable lifecycle.** Compose PostgreSQL metadata,
  encrypted object custody, OpenBao/key rotation, worker fencing, audit and
  recovery into one deployed path. Exit: live end-to-end failure/recovery tests.
- [ ] **P03 — Tenant, secrets and retention assurance.** Verify OIDC, tenant
  isolation, least privilege, observability without source leakage, backups,
  deletion across replicas and incident response. Exit: operational drills,
  load/security testing and documented evidence.
- [ ] **P04 — Supplier rights and buyer scope.** Bind authentic supplier
  authority, permission, purpose, recipient and revocation to each artifact.
  Exit: legal-approved supplier process and negative tests. **Blocked
  externally:** a supplier/legal attestation policy is needed; signatures
  alone are not proof of sale rights.
- [ ] **P05 — Controlled final delivery.** Require an immutable qualified
  artifact, independent approval, recipient-bound publication, audit and
  revocation. Exit: end-to-end authorization and denial tests against the
  exact final bytes. Production routes stay closed until P01–P04 pass.
- [ ] **P06 — External pilot and market acceptance.** Validate security,
  performance, reviewer time, measured false negatives and useful output with
  design partners before accepting real customer data. **Blocked externally:**
  a partner, permitted dataset and acceptance criteria are required.

## Completed baseline (not a production qualification)

- [x] **B01 — Three-file synthetic PDF/PDF/TXT demo, readable aliases,
  larger comparison and local review-copy download.** PR #86; 63 web tests,
  55 focused API/media tests, local Edge walkthrough and five green CI jobs.
- [x] **B02 — Explicit, typed relationship map with evidence and source-free
  labels.** PR #86; no inferred employment/client ties from mail domains or
  co-mentions.

Related detail: [demo roadmap](demo-to-product-roadmap.md), [production gate](production-readiness-gate.md),
[format-aware policy](format-aware-pseudonyms.md), and [graph contract](entity-relationship-graph.md).
