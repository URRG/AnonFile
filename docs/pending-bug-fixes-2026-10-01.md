# Pending bug fixes and validation

This follow-up fixes reproduced document-review, final-OCR comparison, and
dependency-audit failures while retaining the original React workbench.

## Fixes

- Word extraction retains deleted field instructions, simple-field instruction
  attributes, and hyperlink tooltips in document, header, and comment parts.
  The additional fields enter the review transcript; detected identifiers are
  replaced in the text candidate. Nested text-box paragraphs are extracted once
  and separated from surrounding text.
  The additional hidden sources still obey the extraction byte limit.
- The optional final-OCR verifier rejects known source values when transcripts
  change whitespace, Unicode compatibility glyphs, composed/decomposed accents,
  or casefold-equivalent spelling. The original boundary-aware matcher remains
  active. Normalization adds conservative rejection; OCR transcripts are not
  rewritten and error messages remain source-free. Whitespace-only source values
  are rejected before candidate OCR.
- PyJWT is pinned to 2.15.1, addressing CVE-2026-101918 in 2.14.0. The hosted
  failure log confirmed that advisory. The API image and dependency-audit job
  bootstrap pip 26.2.1; the older base-image installer had separate findings in
  the local audit. Package installation keeps the optional build-only CA mount
  and certificate verification.

## Validation

| Check | Result |
| --- | --- |
| Original 8 supplied documents, fresh workers | 8 review-required results; 43/43 selected markers extracted; zero selected occurrences retained |
| Expanded 66-entry corpus | 55 reviews, 11 expected rejections; 50/50 selected checks passed; no unexpected results or negative-control findings |
| Independent document/OCR selection | 238 tests passed |
| Full native API suite with pinned PostgreSQL 16.15 container | 1,908 passed, 6 skipped; 180.36 s |
| Final-PDF comparison cases added after that collection | 3 passed separately |
| Full API suite against rebuilt image application | 1,856 passed, 61 skipped; 167.71 s |
| Fresh requirements audit | No known vulnerabilities |
| Audit of actual API image's frozen installed versions | No known vulnerabilities, including pip and PyJWT |
| Non-root API/web smoke | Auth, roles, CORS, redaction, release gates, web assets, real PNG OCR, runtime CA absence, and cleanup passed |

The image suite asserts application imports resolve to `/app/app`. Repository
test inputs are copied separately under `/validation`; the image application is
not replaced. Its 61 skips cover 55 PostgreSQL cases, five separate TLS service
cases, and the separately approved D07 runtime. The native PostgreSQL invocation
has the latter six skips. The three additional final-PDF cases are included in
the complete image suite. All disposable containers and volumes were removed.

The rebuilt API image ID is
`sha256:bc587883ec38e358a960a92e1d841447dfc699a5e9042df46dc737c5c7917d96`.
Its installed-version inventory was audited outside the image using a writable
audit cache. No audit tooling or proxy CA was added to the runtime image.

## Hosted gate and remaining scope

The billing block cleared. Rerun attempt 2 of
[main run 36750364707](https://github.com/URRG/AnonFile/actions/runs/36750364707)
executed all seven jobs: six passed and Python dependency audit failed on the
PyJWT advisory above. The corrected branch must pass all seven workflow jobs
before merge; its actual results are recorded in the consolidated pull request
and linked [workflow runs](https://github.com/URRG/AnonFile/actions/workflows/ci.yml).
No workflow, audit, protection, or verification gate is disabled.

Selected document annotations do not establish exhaustive recall, original-format
sanitization, or pixel privacy. OCR comparison regressions use injected transcripts;
the real container PNG probe exercises OpenCV/RapidOCR independently of those
tests. The original checked-in D07 executable/model/runtime pins remain intact,
and that separately approved runtime is not provisioned in this Linux environment.
Its opt-in test remains skipped. This work does not close the independent holdout,
source-geometry, production-persistence, or release-qualification gates in the
[product gap tracker](pending-product-gaps.md).
