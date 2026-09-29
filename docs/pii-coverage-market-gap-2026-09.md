# PII coverage gap ledger — updated 30 September 2026

This is a comparison of **implemented detection paths**, not the names in the
evaluation taxonomy. No finite list can cover every personal-information
vector: a project code, booking reference, face, or ordinary date can identify
someone when linked with another dataset. A syntactic candidate is not proof
of a real issued identifier, and a clean scan is not proof of anonymity.

Sources reviewed: [Amazon Comprehend PII types](https://docs.aws.amazon.com/comprehend/latest/dg/how-pii.html),
[Azure Language PII categories](https://learn.microsoft.com/en-us/azure/ai-services/language-service/personally-identifiable-information/concepts/entity-categories),
[Presidio supported entities](https://data-privacy-stack.github.io/presidio/supported_entities/),
[Google Sensitive Data Protection detector concepts](https://docs.cloud.google.com/sensitive-data-protection/docs/concepts-infotypes),
and [Azure document PII workflow](https://learn.microsoft.com/en-us/azure/ai-services/language-service/personally-identifiable-information/quickstart?pivots=programming-language-python&tabs=linux).
Vendor lists establish that a *category is offered*, not that it performs
well on our files, languages, or releases. This ledger is a prioritized gap
inventory, not a claim to have exhaustively enumerated those catalogs.

| Family / vector | Current AnonFlow implementation | Market comparison and next gate |
| --- | --- | --- |
| Free-text person names, aliases, roles, and indirect cross-file identity | Demo-specific name inference and exact aliases; core rules lack general multilingual NER | AWS, Azure, and Presidio offer person-name detection. Add a pluggable local NER candidate source, then blind span and cross-file identity evaluation; never auto-merge ambiguous people. |
| Full postal addresses, places, geocoordinates, movement traces | Structured `address` and bounded synthetic US-style address; precise decimal GPS pairs with explicit labels and structured latitude/longitude fields; other quasi fields and labelled context | AWS/Azure/Presidio cover addresses and/or locations; Azure lists GPS coordinates. Need regional address parsing and linked-location risk scoring, not a blanket city-name redaction. |
| National IDs and regional tax IDs | PAN and Aadhaar shapes; passport/licence fields and narrow labelled prose. Labelled US SSN/ITIN shapes, UK NINO, Indian voter ID, and now Canadian SIN are `GOVERNMENT_ID` candidates | AWS, Azure, and Presidio list many country-specific types. Next: per-country recognizer registry, test vectors, checksum/context policy and explicit unsupported-country status. Do not imply issuance validity. |
| Health IDs and clinical content | Named structured fields, labelled UK NHS numbers, and short contextual clauses; no calibrated clinical NER | Presidio offers optional medical NER; AWS/Azure list health identifiers. Need independent PHI annotations, local clinical model review and no diagnosis-only identity assumptions. |
| Payment and banking | Card-length candidates, PAN shape, labelled US account/routing, GB/DE IBAN; structured CVV/PIN/crypto fields | AWS/Presidio list broader IBAN, SWIFT, crypto and expiry recognizers. Next: checksum-aware, jurisdiction-specific candidates with controlled false positives and non-working surrogates. |
| Device, account and online identity | IP/MAC, handles, structured IMEI/device/cookie/advertising IDs, labelled UUID-shaped IDFA/GAID/AAID, employee/staff IDs and explicit HTTP(S) or rooted/dot-relative query keys (session, patient, customer and similar IDs). Public URL hosts/paths remain untouched | AWS/Azure list URL, username, VIN/MAC. Continue source-safe handling of personal data in URL paths, bare/other relative URLs, unlabelled mobile ad IDs and organization-specific identifiers. Public URLs alone are not always PII. |
| Travel/customer references | Demo-specific booking references and passenger context; generic core lacks a dedicated travel-record class | Vendor custom recognizer mechanisms can cover domain-specific IDs. Define a separate travel/customer-record taxonomy and supplier-specific dictionaries before deploying beyond the airline demo. |
| Credentials and cloud tokens | Generic labelled passwords/keys and authorization tokens, plus unlabelled AKIA/ASIA-shaped AWS access-key IDs; many provider-specific tokens and connection strings are not recognized | AWS lists access keys and Azure lists cloud secrets. Add provider-specific secret recognizers with strict tests; treat as security-sensitive even when not personal. |
| PDF/image/Office/audio and non-text identifiers | Bounded PDF/image OCR and review/redaction preview. The PDF demo rejects selected hidden/interactive containers and cross-checks rules-detected native text. Input image pixels are EXIF-oriented, alpha-flattened and rebuilt without source metadata; encoded PNG chunks are checked. A positively detected QR region causes media abstention, but there is no QR/barcode absence guarantee. No DOCX/XLSX, audio, face/signature/biometric or metadata-wide guarantee | Presidio has image/structured examples and Azure document PII supports PDF/DOCX/TXT. These need separate parsers, media provenance, final-byte inspection and abstention; text rules alone cannot close them. |
| Quasi-identifiers and linkage | Labelled/field-bound age, birth year, postal code, demographics; no robust k-anonymity/linkage-risk qualification | Vendors expose age/date/location classes. Product requirement goes further: evaluate combinations and buyer auxiliary data, with holdout evidence and human release review. |

## First implementation tranche

- Bounded, explicit-label free-text detection for US SSN/ITIN-shaped values,
  UK National Insurance number, Indian voter ID, 15-digit IMEI, and employee ID.
- Structured `employee_id` and `staff_id` map to the existing `USER_ID` category.
- A labelled IMEI no longer becomes a payment-card finding solely because it
  has 15 digits. Generic unlabelled 15-digit numbers remain card-length
  candidates under the existing conservative rule.
- Tests include source offsets, negative lookalikes, and whole-value redaction.

These are rules-only improvements, **not** validation against an independently
annotated corpus. Do not advertise full SSN, voter-ID, IMEI or regional ID
coverage from these narrow examples. See the independent holdout protocol for
the qualification gate.

## Second implementation tranche: labelled Canadian SIN and UK NHS number

- Canadian SIN recognizer requires `SIN` (uppercase) or an adjacent social
  insurance number label and a nine-digit shape. Its Mod-10/Luhn result is
  recorded in internal, source-free span provenance (not yet a demo scorecard
  field). [Canada Revenue Agency](https://www.canada.ca/en/revenue-agency/services/tax/businesses/topics/payroll/set-up-new-employee/social-insurance-number.html)
  describes the nine-digit number; [CRA's processing guidance](https://www.canada.ca/en/revenue-agency/services/tax/registered-plans-administrators/consultation-sessions/questions-answers-resp-rrsp-rrif-consultation-session-october-25-2004.html)
  describes a Mod-10 check and not rejecting invalid submissions.
- UK NHS recognizer requires `NHS number` or `NHS no.` and a ten-digit shape.
  Its Mod-11 result is likewise recorded without a registry lookup. The
  [NHS number guidance](https://digital.nhs.uk/services/personal-demographics-service/nhs-number)
  specifies 3-3-4 formatting and a tenth check digit; the
  [NHS service manual](https://service-manual.nhs.uk/design-system/patterns/ask-for-nhs-numbers)
  calls for Mod-11 validation and says 9-prefixed examples are test numbers.
- A failed check digit **does not suppress detection**. Mistyped, OCR-damaged,
  or fictional labelled values remain sensitive. A passing check digit does
  not prove issuance or authorize a format-valid surrogate. Generic unlabelled
  numbers are not promoted to these regional classes. Malformed labelled values
  outside the bounded shape are not comprehensively covered; a human review
  and independent holdout remain necessary.
- Synthetic tests cover checksum pass/mismatch, strict boundaries, source
  offsets, whole-value suppression, and structured field names. No blind
  sensitivity/precision claim is available without the annotated holdout.

## Third implementation tranche: PDF hidden-container abstention

- The bounded raster demo rejects catalog actions, associated files,
  optional-content layers and collections, and page annotations/actions or
  associated files before rendering. [PDF Association](https://pdfa.org/files-inside-pdf/)
  documents that attachments can reside outside the ordinary embedded-file
  name tree; [Adobe's PDF reference](https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.5_v6.pdf)
  describes optional-content groups. This is a narrow preflight, not a full
  PDF object-graph inventory.
- All rules-detected candidates in the native PDF text layer, including
  credentials, health, business-confidential and quasi-identifier spans, must
  now appear as whole values in the OCR transcript or the demo abstains.
  Prefixes of longer OCR tokens no longer satisfy this check. Earlier the
  cross-check covered only a subset of categories. Tests use synthetic
  omissions and overlong lookalikes.
- The raster candidate still discards original PDF objects and image metadata,
  but **OCR cannot establish complete visual or hidden-content coverage**.
  Nested associated files, scanned-image misses, QR/barcodes, signatures,
  tagged content and metadata-wide checks remain pending. No release claim is
  made from this same-engine cross-check.

## Fourth implementation tranche: explicit URL query identifiers

- HTTP(S) query parameters with explicit keys for session, patient/medical
  record, user/customer/passenger/employee, email, phone, birth date and SSN
  are candidate values. Percent-encoded *keys* are decoded for matching, while
  the raw value offsets are retained for whole-value suppression. Encoded
  email values require an email shape and receive a URL-safe demo alias that
  agrees with the same plain email elsewhere in the batch. This new URL rule
  leaves hosts, paths and unlisted parameters alone, though other existing
  detectors can independently match their contents. An explicit query-key
  category takes precedence over a generic number-length guess within its value.
- This addresses a real distribution channel: [OWASP's session guidance](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html)
  notes that session IDs can appear in URLs and should not be exposed in logs.
  [Google's detector guidance](https://docs.cloud.google.com/sensitive-data-protection/docs/concepts-infotypes)
  emphasizes contextual clues for ambiguous generic IDs. We therefore do not
  classify every `id`, `code`, `ref`, path component or public URL as PII.
- Synthetic tests cover encoded keys/values, exact source offsets, repeated
  parameters, fragments, public lookalikes, structured keys and two-file demo
  rendering. Rooted and dot-relative links now use the same explicit-key rule.
  Bare relative links, unusual query separators, HTML-escaped `&amp;`,
  provider-specific keys and values hidden in URL paths are not yet qualified.

## Fifth implementation tranche: source image metadata and alpha

- JPEG/PNG orientation is applied before copying only visible RGB pixels into
  a fresh image without the source `info` dictionary. Transparent source
  colors are composited onto white, not exposed by dropping alpha. The exact
  candidate PNG bytes are checked for pixel-only `IHDR`/`IDAT`/`IEND` chunks;
  EXIF, XMP, text, ICC and trailing data cause abstention if an encoder emits
  them. [Pillow's security guidance](https://pillow.readthedocs.io/en/stable/handbook/security.html)
  recommends treating image metadata as untrusted and stripping it when not
  needed. Synthetic tests cover EXIF orientation, private metadata, ancillary
  chunks and fully transparent dark pixels.
- This establishes a narrow **output-metadata** property for generated PNGs,
  not a source-metadata inventory or assurance that all visible text, QR codes,
  faces or other personal signals were found by OCR.

## Sixth implementation tranche: AWS access-key ID candidates

- Unlabelled, uppercase `AKIA`/`ASIA` plus 16 alphanumeric characters are now
  critical credential candidates in the core rules and synthetic batch demo.
  The separate aggregate residual scanner also flags this narrow shape in a
  candidate artifact. [AWS IAM's credential guidance](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html)
  describes access-key IDs and paired secret keys, and
  [AWS's git-secrets recognizer](https://github.com/awslabs/git-secrets) lists
  these prefixes among its patterns. Synthetic tests check exact boundaries,
  whole-value suppression, cross-file demo rendering and aggregate-only
  residual reporting. The detector identities are versioned for this change.
- A shape hit cannot establish a live credential or an associated person. It
  can match fictional values. Secret access keys without an explicit label,
  session tokens, other cloud providers, encoded keys and credentials split
  across lines remain unqualified. Both detectors use similar shapes, so the
  residual check is not independent evidence of coverage for this vector.

## Seventh implementation tranche: labelled precise location

- Explicit `GPS`, `geo coordinates` or `location coordinates` labels followed
  by a decimal latitude/longitude pair (3–12 fractional digits) now create a
  bounded quasi-identifier candidate, subject to geographic range checks.
  Structured `latitude`, `longitude` and coordinate field names are also
  treated as quasi-identifiers; sensitive numeric fields become `null` in core
  output. The synthetic batch demo generalizes labelled pairs and string-valued
  JSON coordinate fields; numeric sensitive JSON fields are nullified as JSON
  literals while preserving parseability. The aggregate residual scanner flags
  labelled pairs as a possible PII signal.

## Eighth implementation tranche: JSON scalar nullification in batch preview

- Sensitive JSON/JSONL numeric and boolean scalars now become literal `null`,
  matching the conservative core-processor behavior while retaining valid
  syntax. The detected entity and its mention show a `SCALAR_NULLIFICATION`
  strategy. Ordinary numeric fields are left unchanged. A full JSON number
  token, including exponent notation, must match the bounded field scanner;
  a parsed-object accounting pass rejects missed sensitive fields, duplicate
  keys and sensitive containers. Tests reparse the exact candidate. This is
  still a synthetic, review-only candidate and does not establish semantic
  recognition of arbitrary keys, utility, or release safety.

## Ninth implementation tranche: positively detected QR regions

- Before OCR, the bounded PDF/image demo now applies OpenCV's QR multi-region
  detector to each raster page and refuses the entire media file when it finds
  a region. It never decodes or returns the QR payload. Detector unavailability
  also causes abstention. Synthetic QR-in-PNG/PDF and ordinary text-PDF tests
  guard both the positive and false-positive paths. The single-region detector
  falsely flagged a plain text PDF in our test, so this bounded gate uses the
  multi-region path only.
- [OpenCV's QR detector documentation](https://docs.opencv.org/5.0/main_modules/classcv_1_1QRCodeDetector.html)
  describes detection separately from decoding. This is **not** a QR-free
  certification: small, damaged, warped, low-contrast or otherwise missed QR
  codes, and all other barcode symbologies, can still evade this one detector.
- [Azure's PII categories](https://learn.microsoft.com/en-us/azure/ai-services/language-service/personally-identifiable-information/concepts/entity-categories)
  describe geolocation as personal when it can pinpoint or track a person;
  [Google's detector guidance](https://docs.cloud.google.com/sensitive-data-protection/docs/concepts-infotypes)
  distinguishes precise street addresses from broad place names. These rules
  do not identify person linkage, movement traces, unlabelled coordinates,
  degrees-minutes-seconds, regional address formats, or geographic risk. A
  coordinate shape alone is not proof of personal information. The source and
  residual recognizers are correlated rules, not independent recall evidence.

## Tenth implementation tranche: labelled mobile advertising IDs and relative query links

- An explicit `IDFA`, `GAID`, `AAID` or advertising-ID label adjacent to a
  canonical UUID shape now creates a `DEVICE_ID` candidate in text. Structured
  keys for those aliases also map to `DEVICE_ID`. The all-zero unavailable or
  opt-out sentinel is not promoted by the labelled text rule, and numeric UUID
  substrings no longer become incidental card/number findings. Bare UUIDs are
  not promoted by this new rule, though generic numeric rules may still match
  an all-numeric UUID. [Apple](https://developer.apple.com/documentation/adsupport/asidentifiermanager/advertisingidentifier)
  describes IDFA as a UUID, and [Android](https://developer.android.com/identity/ad-id)
  documents a UUID-format advertising ID; the shape does not prove issuance,
  consent or device/user linkage.
- The separate aggregate residual scanner flags a nonzero labelled advertising
  ID as a possible PII family signal. This is an independent implementation of
  a similar shape rule, **not** independent recall evidence. Synthetic tests
  exercise Unicode source offsets, boundaries, all-zero and bare UUID negatives,
  structured redaction, and two-file demo consistency.
- Rooted (`/view?...`) and dot-relative (`./view?...`, `../view?...`) links now
  pass through the same explicit query-key policy as HTTP(S) links. Bare
  `view?...` tokens and protocol-relative URLs are excluded to limit accidental
  promotion. Synthetic tests cover public parameters, fragments, preserved
  path context, and two-file review. The proposal remains a review-only
  candidate; opaque replacements may not preserve executable URL semantics.

## Next implementation order

1. **P0 — Measured recall, not another broad regex claim.** Freeze the offered
   fictional text/PDF/image holdout, blind-label it, and measure names,
   addresses, identifier spans, OCR misses and final-byte residuals by format.
   Then add a local NER candidate adapter behind a fail-closed review boundary.
2. **P0 — Hidden-media surfaces.** Bounded PDF catalog/page abstentions and a
   broader native-text/OCR cross-check are done. PNG output-metadata and alpha
   handling are now bounded and checked. Continue PDF object-graph and source
   EXIF inventory, broader QR/barcode qualification, and unsupported Office/audio status
   before any downloadable candidate is called clean.
3. **P1 — Versioned regional recognizers.** Canadian SIN and UK NHS now have
   bounded labelled/check-digit candidates. Continue one jurisdiction at a
   time (for example more IBAN countries) with independent labelled scorecard
   slices, unsupported-country status and safe replacement policies.
4. **P1 — Domain-specific accounts and URLs.** Introduce a distinct
   travel/customer-record class and supplier-provided dictionaries. Explicit
   HTTP(S) and rooted/dot-relative query-key candidates are done; continue URL
   path/bare-link policies without masking every public URL or ordinary project
   code. Qualify URL-safe replacements before claiming usable transformed links.
5. **P2 — Specialized content.** Clinical narratives, faces/voices, handwriting,
   multilingual names, and linkage risk require separately evaluated models,
   parser provenance and reviewer controls, not a universal pattern list.
