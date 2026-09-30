# Document coverage review

The local workbench now accepts PDF, DOCX, PPTX and XLSX documents at `?mode=documents`. It produces **unverified text candidates and a coverage inventory**, with no cleaned original-format download or release approval. Source text and candidate text can both contain identifiers.

Enable `ANONFLOW_ENV=development`, `ANONFLOW_DEMO_MODE=enabled`, and the normal processor authentication configuration. Open **Document coverage review** from the synthetic batch sidebar. Select up to eight rights-cleared documents, enter a processor token, and acknowledge the review-only use. Documents are submitted sequentially; previous results remain visible if a later file fails. Credentials and results stay in browser memory. The endpoint does not persist uploaded documents.

`POST /development/documents/review` accepts `name`, `content_base64`, `review_only: true`, optional `ocr` (default true), and optional `reviewed_values` (`value` and `kind`). A correction must occur in the extracted source. Supported correction kinds are `PERSON_NAME`, `ADDRESS`, `GOVERNMENT_ID`, and `OTHER_SENSITIVE`. The route requires the processor role and is absent in production and when the demo is disabled. This route's 11 MB request allowance does not widen the existing processing/demo routes.

For a local directory, use the same bounded parser from the CLI:

```sh
python -m pip install -r services/api/requirements-dev.txt
python scripts/review-documents.py /path/to/documents --output /private/review-results
```

JSON reports contain extracted source text. Keep that output directory private and outside the repository. Original files are read only, and each report records the original SHA-256. `--no-ocr` explicitly records incomplete OCR coverage.

## Extraction and bounds

| Surface | Review behavior |
| --- | --- |
| PDF | Enumerates every page; reads native text, document properties, XMP, form values, signature metadata and annotation text. Records guarded root structures separately. |
| Word | Reads body, headers/footers, comments, tracked deletion text, field instruction text, descriptions and document/custom properties. |
| PowerPoint | Reads slides including hidden slides, speaker notes, object names/descriptions and properties. |
| Excel | Reads visible, hidden and very-hidden sheets, shared/inline strings, cached values, formulas, hidden row/column counts and properties. Also reads unused shared strings. |
| Package members | Inventories every member, including empty parts, relationships, thumbnails, image/embedded binaries and XML auxiliary parts. External relationships are not fetched. Macros and embedded code do not execute. |

Limits are 8 MB per original, 400 PDF pages, 2,000 ZIP members, 32 MB expanded ZIP data, 2 MB extracted UTF-8 text, 6,000 text surfaces and 20,000 proposed replacements. Limit violations fail the review rather than silently truncating it. DTDs/entities, encrypted inputs, duplicate/unsafe ZIP paths and invalid package references are rejected.

Linux parser processes have a 2 GB address-space limit, 120-second CPU limit and 180-second wall-clock limit. One review worker runs per API process. Parser credentials are not inherited; temporary working directories are removed. This is resource isolation for local development, not a hardened production document sandbox.

PDF review OCR requires Tesseract with English language data, PDFium and Pillow. The API Docker image installs Tesseract; native users must install `tesseract-ocr` and `tesseract-ocr-eng` through their OS package manager. Without those tools, native extraction continues and the missing OCR is reported. This transcript OCR is separate from the existing pinned independent final-artifact verifier.

OCR processes at most eight eligible pages per document, prioritizing empty/failed native pages, at no more than four million rendered pixels per page. Word offsets, confidence and pixel boxes are retained. Native and OCR transcripts remain separate. Low-confidence OCR is flagged; it is never promoted to verified pixel removal. The remaining pages are explicitly `UNMEASURED` for OCR. Every PDF page remains `UNMEASURED` for visual content even after OCR.

## Findings and coverage

Explicit-context rules now cover titles, labelled names, rosters, court parties/judges and common street addresses. Author identities and explicit person findings propagate across the document using consistent markers. Additional capitalization-based name proposals and nearby-form SSN proposals are labelled separately for human review; neither is qualified semantic recognition. Spreadsheet tabs are cell boundaries, not name separators. Metadata, custom XML and package relationship text are removed wholesale from the **text candidate**, without claiming the original package properties were edited.

The core processor distinguishes ordinary “basic” prose from Basic authorization credentials, avoids PDF timestamp/card confusion and transcript reference/line-number combinations, and recognizes labelled SSNs with common OCR separators. The independent residual scanner owns separate name/address/SSN patterns. Repeated-known-value checks are reported separately from its residual family counts.

An empty residual count does not establish name/address coverage. `coverage.names_addresses` remains `UNQUALIFIED`, pixels remain `UNMEASURED`, original-format output is `NOT_PRODUCED`, and `release_eligible` is always false. Arbitrary names, OCR errors, handwriting, QR content, embedded objects, links, signature validity, layout and indirect identifiers still need review. Original-format sanitization and complete rendered-output verification are not provided by this path.

## Validation

Synthetic regressions exercise long documents, repeated names, compound surnames, Indian honorifics, form SSNs, metadata, signature fields, hidden slides/sheets, notes, unused strings, formulas, external relationships, XML/ZIP abuse, authorization, scoped body limits and parser errors. Browser tests validate cancellation, malformed responses, bounded uploads and source-free failure messages.

The separate supplied-document follow-up is recorded in [document-audit-follow-up.md](document-audit-follow-up.md). Uploaded originals and extracted transcripts are not committed as test fixtures.
