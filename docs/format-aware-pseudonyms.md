# Format-aware replacements: demo policy and product decision

The batch workbench is **synthetic-only** and produces a review candidate, not
anonymous or saleable data. Its replacement strategy is shown per entity.
The goal is to preserve enough document meaning and visual fit for a reviewer
without inventing a live contact point or an issuable identity number.

| Signal with evidence | Demo replacement | Why | Unsupported case |
| --- | --- | --- | --- |
| Person name from a structured name field, mail header, or reviewer correction | Unique same-character-length name | Limits text-line overflow; maintains batch consistency | Arbitrary prose names can be missed; same-name collisions require identity review |
| Email | Owner-linked local part and reserved `.test` domain | Preserves email syntax and explicitly evidenced owner/domain equivalence; avoids real delivery | Ambiguous owner association rejects the request |
| Indian PAN-shaped value | `TSTZA0001A`, with a unique ordinal | 10-character shape; fourth-position `Z` is outside the [Income Tax Department's published holder-status set](https://traces61contents.tdscpc.gov.in/en/faq-general-pan.html) | Not a validator-compatible PAN; do not use when downstream needs a valid PAN |
| Explicitly labelled US SSN or `ssn`/`social_security_number` field | `000-01-0001`, preserving the source separator style | Area `000` is [never assigned by SSA](https://www.ssa.gov/employer/randomizationfaqs.html) | Unlabelled nine-digit values remain opaque; no jurisdiction guess |
| Explicit `+1` 11-digit NANP phone | `+1 202 555 0100`, preserving separators; unique through `0199` | [NANPA reserves 555-0100–0199 as fictitious non-working numbers](https://nanpa.com/numbering/555-line-numbers) | Other countries, ambiguous local numbers, and capacity overflow remain opaque |
| Passport, driving licence, Aadhaar, payment identifier, credential, or unidentified number | Typed opaque marker | No safe global fictitious range is established for these fields | A future country/jurisdiction adapter needs authoritative test ranges and independent validation |

These are **syntactic surrogates, not real format-valid substitutes**. In
particular, an intentionally invalid PAN or SSN may fail downstream business
validation. Minting a plausible live identifier would solve that utility
problem at unacceptable collision/misuse risk. The product should support a
separately governed compatibility profile only after a jurisdiction-specific
synthetic registry or other demonstrably non-issuable range is available.
Never silently switch to a plausible number.

The batch-local mapping is deterministic for a given batch and maintains
cross-document consistency. It is not a cryptographic token vault and is not
stable across separate runs or authorized for re-identification. Source-value
collision checks and finite surrogate pools fall back to opaque replacement.
The UI and scorecard continue to mark every candidate review-required.

## PDF/OCR boundary

The current PDF path rasterizes pages and paints recognized OCR lines into a
new image-only candidate. For a born-digital PDF, a second text-layer read now
compares recognizable email, PAN, phone, IP, Aadhaar, and card signals with
the OCR transcript. A missing native-text signal rejects the candidate. This
is a **partial disagreement check**, not independent proof: scanned pages lack
a text layer, OCR can miss visible text, and a text layer need not faithfully
represent the pixels. The [pypdfium2 documentation](https://pypdfium2.readthedocs.io/en/stable/python_api.html)
also states PDFium is not thread-safe, so the bounded PDF calls are serialized.

## Competitive architecture to evaluate next

1. Benchmark the current OCR/layout path against labelled born-digital,
   scanned, photographed, skewed, multilingual, and table-heavy documents.
   Measure pixel-level missed sensitive regions and reading-order/field-link
   errors, not only text span recall. [PaddleOCR PP-StructureV3](https://github.com/PaddlePaddle/PaddleOCR/blob/main/docs/version3.x/pipeline_usage/PP-StructureV3.en.md)
   is a candidate layout/table pipeline, but should be admitted only if a
   frozen holdout shows a gain under resource and privacy constraints.
2. Add a recognizer plug-in boundary for jurisdiction, context, checksums,
   confidence, and abstention. [Presidio's analyzer](https://microsoft.github.io/presidio/analyzer/)
   is an architectural benchmark; its own documentation warns that automated
   detection cannot guarantee complete PII discovery. The interface should
   retain source spans, provenance, confidence, and evidence, not just labels.
3. Keep transformation policies distinct: non-issuable synthetic values for
   review/training utility; opaque redaction when no safe surrogate exists;
   reversible keyed tokens only in a separately controlled workflow.
   [Google Sensitive Data Protection](https://docs.cloud.google.com/sensitive-data-protection/docs/pseudonymization)
   documents deterministic encryption and format-preserving encryption for
   compatibility, but their output may be real-looking and requires key,
   scope, and re-identification controls. Neither creates anonymity by itself.
4. Before accepting real purchased datasets: isolated parsers/workers,
   independent holdout and residual visual evaluation, tenant and key
   boundaries, provenance, human adjudication, retention/deletion, and a
   release gate that tests the final artifact. The current workbench stays
   synthetic-only until those gates are built and evaluated.
