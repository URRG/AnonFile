# Synthetic demo and product-readiness plan

## Immediate demo acceptance criteria

The local development workbench must accept a synthetic UTF-8 `.txt`, `.csv`,
`.json`, or `.jsonl` file (or pasted text), identify bounded rules-based
findings, and display a transformed *demo preview*. It must disclose detector
coverage and limitations beside the preview. No preview may be called anonymous,
qualified, approved, exportable, or sellable. The preview endpoint is disabled
by default, requires an explicit development-only opt-in and processor token,
does not persist data, and remains unavailable in production mode. Existing
release, approval, candidate-custody, and buyer-delivery boundaries stay
unchanged. A local HTTP/UI integration test and full API/web suites are the
exit gate; a rendered-browser walkthrough is desirable when a browser is
available.

The newer batch workbench extends this to two or three synthetic files,
including bounded raster OCR for PDFs and PNG/JPEG images. It shows consistent
aliases, an explicit-evidence person/organization/project graph, and a
side-by-side candidate. The reviewer can save an unqualified local synthetic
review copy after acknowledging the limitation; production release remains
closed. A complete synthetic reference-label manifest can now produce
exact-span agreement counts; the built-in example has fixed labels. The
scorecard now breaks counts down by file, lists unmatched reference spans,
and links each file to its before/after comparison. Reviewers can add exact
non-name sensitive phrases across the batch, including from a missed reference
span. The scorecard separates automatic baseline counts from post-review
counts so corrections cannot be mistaken for detector performance. Both
measurements describe only the labelled case. They
are not an independent holdout, privacy qualification, or a general model
quality claim. A reviewer can mark a supported noncritical signal as a false
positive for this synthetic batch; the retained source remains visibly
review-required and cannot be exported. That narrow correction path does not
replace a production annotation workflow or two-person review.

PDF and image candidates now have visual source/candidate page comparisons.
The candidate PDF is rebuilt from new raster pages in memory, without copying
source PDF objects. This demonstrates actual pixel rewriting, but not safe
redaction: content missed by OCR can remain visible, the same OCR recheck is
not independent, and untrusted media parsing is not isolated in a hardened
production worker. A digest-checked local synthetic copy can be downloaded,
but no production release path is enabled.
The workbench now uses documented non-issuable examples for a narrow set of
PAN, explicit US SSN, and `+1` NANP phone shapes, retaining opaque markers
otherwise. Born-digital PDF text-layer signals are cross-checked against OCR,
but this cannot establish visual coverage. See
[format-aware replacement policy](format-aware-pseudonyms.md).

## Gaps after the synthetic demo

1. **Detector quality and coverage.** Collect representative, legally usable
   and independently annotated holdout corpora by source format, language,
   country, industry, and identifier family. Measure exact-span precision,
   recall and false negatives. Add configurable domain recognizers and
   validated models for free-text names, addresses, organizations, healthcare,
   business-sensitive context and indirect identifiers. Support documents,
   images, audio and other purchased-data formats only after their parsers and
   provenance are tested. Never infer completeness from a finite ruleset.
2. **Independent privacy and utility qualification.** Scan the *final*
   transformed artifact with independent methods, run linkage and
   re-identification attacks against realistic auxiliary data, test schema and
   task utility, and set source-specific thresholds and abstention rules.
   Evaluate every processor/model revision against a frozen holdout. A clean
   residual scan alone is not an anonymity proof.
   The offline evaluator now offers [checksum-pinned holdout selection](holdout-evaluation.md),
   but there is no independent corpus or annotation attestation yet.
3. **Supplier rights and governance.** Verify supplier organization and signer
   authority, preserve revocable and exact-scope rights evidence, settle when
   the supplier signs relative to processing and transfer, and bind rights,
   purpose, recipient, policy and output artifact at every admission/release
   gate. Legal sufficiency requires external review; a signature alone is not
   proof of permission to sell.
4. **Production data plane.** Wire the already tested PostgreSQL, encrypted
   object, key-service and worker components into one deployable lifecycle.
   Add OIDC, tenant isolation, hardened secrets and network controls,
   retention/deletion across replicas and backups, observability, incident
   recovery, migrations and operational runbooks. Keep production routes
   closed until the complete path is verified end to end.
5. **Controlled delivery and commercial validation.** Require independent
   approval of an immutable qualified artifact, recipient-bound publication,
   audit and revocation. Validate security and performance with design
   partners, external testing and documented acceptance criteria before
   handling customer data.

The synthetic preview is a presentation aid, not a shortcut through any of
these gates or authorization to upload actual company data.

The current fail-closed status and concrete exit tests are tracked in the
[production readiness gate](production-readiness-gate.md). The maintained,
checkable [product gap tracker](pending-product-gaps.md) lists the remaining
demo, research, operational and external acceptance work.
