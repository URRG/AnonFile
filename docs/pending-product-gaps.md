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
- [x] **D02 — Contextual sensitive-value coverage.** Detect explicitly labelled
  employee IDs, internal URLs, bounded US-style prose postal addresses, and
  explicitly named structured address fields in TXT or structured files,
  and OCR text without promoting arbitrary prose or public links into PII.
  Exit: positive, negative, cross-file and OCR-regression tests; findings and
  residuals are visible in the review register and candidate. Evidence:
  contextual unit tests, JSON/CSV cross-file and rich PDF/PDF/TXT API tests,
  native-PDF/OCR disagreement test and local Edge walkthrough on this branch.
  Scope remains deliberately narrow; R01 covers broader recall.
- [x] **D03 — Safe, useful replacements for D02.** Preserve relationship and
  document utility while avoiding live internal hosts, contact points and
  fake claims of non-issuable employee IDs or addresses. Exit: deterministic
  batch-local surrogates, collision tests, format/safety labels, and explicit
  abstention when no safe profile exists. Evidence: source-free review
  references, `.invalid` URL host/path, bounded fallback to opaque marker,
  client response validation and browser candidate-download check on this
  branch. These are review labels, not issuer-valid replacements.
- [x] **D04 — Media coordinate review.** Let a reviewer add or correct a missed
  region on a PDF/image, not only a phrase already found by OCR. Exit: bounded
  page boxes, visual diff, source/candidate provenance and rejection of
  out-of-page or overlapping unsafe edits. Evidence: PDF/image OCR-free boxes
  with strict page/area/overlap limits, source and candidate SHA-256 bindings,
  independent browser pixel checks, a locally rebuilt lossless raster PDF
  download, removable applied boxes and failed-rescan recovery. The three-file
  Edge walkthrough applied two boxes, verified black candidate pixels,
  downloaded and decoded the raster-only PDF, then removed one box while the
  other remained. Full API suite: 1279 passed/57 skipped; web: 66 passed and
  production build green. Independent review found and verified fixes for two
  initial issues. This is a visual reviewer tool, not detection completeness.
- [ ] **D05 — Reading-order and layout fidelity.** Test text, tables, forms,
  scanned PDFs, screenshots and images at supported limits; preserve readable
  output or abstain. Exit: visual regression corpus with explicit overlap,
  blur and unprocessed-region failure cases.
  - [x] Fictional reproducible layout corpus and pixel mutation-mask tests;
    focused tests exercise a single-column control, actual OCR on columns,
    table, static form and screenshot, plus AcroForm abstention, simulated
    low-confidence scan and EXIF rotation. This is not a layout benchmark.
  - [x] Conservative actual-repaint-box versus neighboring OCR ink check,
    material OCR-ink overlap, same-baseline multi-cell and repeated
    staggered-column ambiguity abstention; whole-line unreadable fallback now
    abstains. No repaint box is cropped.
  - [x] The rich PDF/PDF/TXT batch remains usable with a single-column Slack
    transcript and labelled signature; a real-OCR screenshot replacement has
    an outside-mask pixel oracle. The focused D05 suite passed 102 tests.
  - [x] An OCR-reported source line must contain a measurable local raster edge
    in its own reported ink box; a catastrophically blurred/flat line abstains
    before preview construction. This is a geometry sanity check only: a dark
    rule or JPEG artifact can also satisfy it, so it is not text support,
    readability, completeness, or a visual-coverage score.
  - [ ] General multi-column/table/form reading-order mapping, real OCR blur and
    coverage qualification, and visual utility thresholds remain open. These
    synthetic controls do not prove completeness or production fidelity.
  - [x] An opt-in, bounded Tesseract CLI final-artifact checker is isolated from
    RapidOCR. It receives exact returned candidate PNG bytes (or rerasterizes
    exact returned PDF bytes), has fixed source-free unavailable/timeout/failure
    outcomes, and never changes `REVIEW_REQUIRED`. It is not installed in this
    demo environment and does not establish OCR completeness, layout fidelity,
    privacy qualification, or release approval.
    It is held unavailable by default until a provisioned, immutable executable
    allowlist, executable SHA-256 and Tesseract-version/config identity are
    installed and its behavior is calibrated; no current demo route enables it.
  - [ ] **Known P1 remains:** an overbroad same-engine OCR line can still hide
    adjacent source content. The optional second-engine final-byte check does
    not establish source geometry or coverage, does not run by default, and
    must not be represented as verified/safe media output.
- [ ] **D06 — Graph provenance and adjudication.** Link an edge to exact
  page/line/span evidence, support reviewer accept/reject and identity
  merge/split, and flag conflicts. Exit: evidence navigation and graph
  correction tests across at least three documents.
  - [x] Exact, bounded text-source spans for explicit statements, mail headers
    and unambiguous CSV records. The graph UI navigates to a highlighted text
    span. Repeated mail messages retain distinct evidence spans.
  - [x] A media relationship with an exact parser span mapping to one source
    page and at most four validated OCR lines navigates to approximate
    OCR-line boxes, bound to source bytes and page dimensions. Ambiguous,
    cross-page or stale maps abstain. These boxes are not glyph-precise proof.
  - [x] The graph UI offers batch-local, alias-only pending/accepted/rejected
    edge markers and narrowly typed multiple-affiliation/assignment cues. They
    reset on reload or graph change and are not stored adjudications, release
    decisions, or identity corrections.
  - [x] A graph-local two-person merge *proposal* rejects direct self-link
    collapse and resets on graph change. It does not apply a merge, split an
    identity, alter evidence, or persist a reviewer decision.
  - [x] A bounded server-side domain state machine owns immutable opaque graph
    snapshots, one-shot accept/reject decisions, optimistic revision checks,
    tenant/snapshot tuple lookup, and append-only source-free audit events.
    It rejects stale and fabricated claim references. The in-process primitive
    also supports revisioned merge and exhaustive endpoint-level split overlays,
    without changing original evidence or authorizing release.
  - [x] In development mode with encrypted SQLite storage, reviewer-only GET
    and accept/reject POST routes bind opaque graph snapshots to the authenticated
    tenant, retain CAS revision and audit atomically, reject expired snapshots,
    and omit evidence bindings from views. Memory mode exposes no graph-review
    route; production mode still blocks the workflow. Snapshot registration is
    trusted-server-only and has no user-facing ingest path.
  - [ ] User-facing recorded graph review is still unavailable in the synthetic
    demo. Identity merge/split actions and conflict resolution are not routed or
    durably applied; the UI's node/edge IDs remain response-local rather than
    durable correction keys. External audit anchoring and multi-host persistence
    are also not established.
- [ ] **D07 — Independent demo scorecard.** Evaluate untouched final pixels and
  text with a different engine/annotated ground truth; separate automatic
  detector scores from reviewer corrections and measure graph/link quality.
  Exit: reproducible per-format/per-type false-negative report and abstention.
  - [x] Every generated TXT/CSV/JSON/JSONL candidate is scanned in-process by
    separate bounded rules, even without reference labels. The guard checks
    the current candidate string only; it is not a durable byte attestation.
    Its aggregate result is text-only—not OCR, pixel validation, or
    anonymization certification—and media validation remains abstained.
  - [x] Aggregate-only synthetic evaluator separates automatic and
    reviewer-corrected exact-span errors by format and entity type. When
    complete synthetic labels are supplied, the demo displays bounded totals
    and explicitly abstains from independent final-artifact and graph claims.
  - [x] A separate, non-authorizing final-pixel holdout evaluator has a bounded,
    source-byte-pinned synthetic manifest, accepts only caller-supplied final
    rasters and an independent OCR adapter, and reports aggregate-only outcomes.
    It is not wired into the demo or release path; no actual independent OCR,
    renderer qualification, or media recall claim follows from this scaffold.
  - [ ] Freeze an independently annotated holdout, validate untouched final
    pixels/text with a different executable checker, and measure reviewed
    graph links and identity adjudication. No production qualification exists.
- [ ] **D08 — Accessible, scalable review UI.** Test keyboard, screen-reader,
  zoom, responsive layout and a larger batch; keep a navigable table fallback
  when a graph is too dense. Exit: automated checks plus a human walkthrough.
  - [x] Keyboard focus movement, live announcements, visible focus states,
    reduced-motion handling, responsive/zoom-oriented layout rules and the
    dense-batch table threshold have automated coverage. Evidence:
    [D08 review UI notes](d08-accessible-review-ui.md) and
    `apps/web/tests/review-ui.test.mjs`.
  - [ ] A human keyboard, screen-reader, 200–400% zoom and dense synthetic
    batch walkthrough is still required. The prescribed evidence is in the
    D08 review UI notes; no walkthrough is claimed yet.

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
