# Supplied-document audit follow-up — 30 September 2026

The eight supplied originals now complete the authenticated development document-review workflow. Before this change, all eight were rejected by the synthetic batch reader. **These results concern extraction and unverified text candidates; no sanitized original-format document was produced.** The existing synthetic raster/export restrictions remain in place.

The final browser run submitted every supplied document from the actual upload screen to the API. All eight returned HTTP 200 with `Cache-Control: no-store` and `release_eligible: false`. Chromium reported no page errors; document selection and desktop/mobile layout checks passed. Original hashes were rechecked against the baseline inventory and were unchanged.

| Supplied document | PDF pages | Extracted text surfaces | OCR pages | Additional inspected content |
| --- | ---: | ---: | ---: | --- |
| Academic CV | 6 | 18 | 6 | Author/properties, identifying link, native text and OCR |
| Ofgem minutes | — | 31 | — | Body, headers/footers, comments/auxiliary parts, author/editor/custom properties |
| GSA presentation | — | 92 | — | 12 slides, one hidden slide, notes, object descriptions, properties and relationships |
| Supreme Court judgment | 29 | 50 | 8 | Annotation text and signature signer metadata; validity unmeasured |
| UCSF scanned business letter | 1 | 6 | 1 | Native/OCR disagreement and optional-content structure recorded |
| Welsh meetings workbook | — | 46 | — | 16 sheets including two hidden sheets, unused strings, custom XML and properties |
| UCSF deposition | 284 | 295 | 8 | Every native page processed; consistent repeated-name replacements and explicit remaining OCR gaps |
| IRS tax scenario | 3 | 12 | 3 | Native and OCR text kept separate, form-context SSNs, names, address and properties |

There are 323 PDF pages and 550 text surfaces, of which some auxiliary surfaces are empty. Native/OCR duplicates and shared-string/worksheet duplicates are deliberately retained as separate source witnesses. These counts are not numbers of independent people or sensitive values.

## Audit regressions

- All **43 selected value checks** from the earlier exploratory audit occur in the new extraction and have zero remaining exact occurrences in the corresponding text candidates. This includes the reviewed attendee names, repeated deposition names and editor identities. This is a source-aware regression check, not an exhaustive recall benchmark.
- The **17 previously expected email/phone matches** are still detected by the core rules on the original independently extracted text.
- None of the **20 previously irrelevant or misclassified matches** overlaps a new core finding on those same original surfaces. This covers the PDF dates, ordinary “basic” prose, transcript references/line numbers and the two prose quasi-identifier examples. This does not measure the precision of newly proposed names or other new findings.
- All **four OCR-visible IRS test-SSN occurrences** receive government-ID replacements, including `PrimarySSN`, table punctuation and whitespace-separated digits. Reviewed name/address occurrences are also absent from the OCR text candidate. The filled original PDF pixels are unchanged.
- Native long-document processing covers every deposition page. The reviewed repeated surname and witness-name variants no longer remain in text candidates. Only eight deposition pages receive OCR, with the remaining OCR coverage explicitly incomplete.
- The workbook's hidden sheets are inventoried accurately: one is empty and one contains an event taxonomy. Hidden state alone is not classified as personal information. Its editor identity also occurs in custom XML; that auxiliary text is now removed wholesale from the text candidate.

## Remaining limits

General name recognition is not solved. Capitalization proposals have false positives (including organizations, titles and OCR fragments); unfamiliar, single-token and non-Latin names can be missed. Addresses and form associations remain bounded heuristics. Repeated-known-value checks cannot discover an identifier absent from extraction or the known-value list.

The independent residual scanner still reports findings on some Office and OCR surfaces. Those include unqualified number/context patterns and require inspection; they are not silently cleared to obtain a zero score. Even zero counts leave semantic coverage `UNQUALIFIED`.

Handwritten signatures, image/QR content, Office rendering, embedded binaries, complete native/OCR agreement and signed/layered PDF fidelity remain unmeasured. OCR is capped at eight eligible pages per file. Review output always says `REVIEW_REQUIRED`; there is no cleaned PDF/Office export or qualified anonymity claim.

## Reproduction and evidence

Run the CLI described in [document-coverage-review.md](document-coverage-review.md), or use `?mode=documents`. The committed synthetic regressions exercise these behaviors without embedding the public originals or extracted identifiers in the repository.

The cloud task retains the originals, baseline inventory/diagnostics, final per-document review JSON, 43-value comparison, 37-match comparison, API/browser logs and screenshots outside the repository under `/workspace/anonfile-document-audit`. Reports contain source text and remain private diagnostic artifacts.

Validation: the full API suite passed 1,683 tests with 61 optional integration skips. The final document/media regression run also passed after the last rejection-message fix. All 110 web tests, six deployment checks and three real HTTP integration tests passed, as did the production web build, dependency consistency check, CLI execution and eight-document Chromium run. Final CSS was visually inspected and its desktop/mobile contrast and layout were rechecked. Optional PostgreSQL/OpenBao/S3/pinned final-OCR integration tests require their separately provisioned services; they are not represented as passing local integrations. Docker image builds could not run in this cloud environment because registry access was blocked during onboarding.
