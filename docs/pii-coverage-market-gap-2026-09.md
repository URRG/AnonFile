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
| Full postal addresses, places, geocoordinates, movement traces | Structured `address` and bounded synthetic US-style address; quasi fields and labelled context only | AWS/Azure/Presidio cover addresses and/or locations; Azure lists GPS coordinates. Need regional address parsing and linked-location risk scoring, not a blanket city-name redaction. |
| National IDs and regional tax IDs | PAN and Aadhaar shapes; passport/licence fields and narrow labelled prose. Labelled US SSN/ITIN shapes, UK NINO, Indian voter ID, and now Canadian SIN are `GOVERNMENT_ID` candidates | AWS, Azure, and Presidio list many country-specific types. Next: per-country recognizer registry, test vectors, checksum/context policy and explicit unsupported-country status. Do not imply issuance validity. |
| Health IDs and clinical content | Named structured fields, labelled UK NHS numbers, and short contextual clauses; no calibrated clinical NER | Presidio offers optional medical NER; AWS/Azure list health identifiers. Need independent PHI annotations, local clinical model review and no diagnosis-only identity assumptions. |
| Payment and banking | Card-length candidates, PAN shape, labelled US account/routing, GB/DE IBAN; structured CVV/PIN/crypto fields | AWS/Presidio list broader IBAN, SWIFT, crypto and expiry recognizers. Next: checksum-aware, jurisdiction-specific candidates with controlled false positives and non-working surrogates. |
| Device, account and online identity | IP/MAC, handles and structured IMEI/device/cookie/advertising IDs. This tranche fixes labelled IMEI and employee/staff IDs | AWS/Azure list URL, username, VIN/MAC. Add source-safe handling of personal data in URL paths/query strings, session IDs, mobile ad IDs and organization-specific identifiers. Public URLs alone are not always PII. |
| Travel/customer references | Demo-specific booking references and passenger context; generic core lacks a dedicated travel-record class | Vendor custom recognizer mechanisms can cover domain-specific IDs. Define a separate travel/customer-record taxonomy and supplier-specific dictionaries before deploying beyond the airline demo. |
| Credentials and cloud tokens | Generic labelled passwords/keys, authorization tokens; many provider-specific tokens and connection strings are not recognized | AWS lists access keys and Azure lists cloud secrets. Add provider-specific secret recognizers with strict tests; treat as security-sensitive even when not personal. |
| PDF/image/Office/audio and non-text identifiers | Bounded PDF/image OCR and review/redaction preview; no DOCX/XLSX, audio, face/signature/biometric, QR/barcode or metadata-wide guarantee | Presidio has image/structured examples and Azure document PII supports PDF/DOCX/TXT. These need separate parsers, media provenance, final-byte inspection and abstention; text rules alone cannot close them. |
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

## Next implementation order

1. **P0 — Measured recall, not another broad regex claim.** Freeze the offered
   fictional text/PDF/image holdout, blind-label it, and measure names,
   addresses, identifier spans, OCR misses and final-byte residuals by format.
   Then add a local NER candidate adapter behind a fail-closed review boundary.
2. **P0 — Hidden-media surfaces.** Inventory and either parse or abstain on
   PDF attachments/annotations/hidden layers, EXIF, QR/barcodes and unsupported
   Office or audio content before any downloadable candidate is called clean.
3. **P1 — Versioned regional recognizers.** Canadian SIN and UK NHS now have
   bounded labelled/check-digit candidates. Continue one jurisdiction at a
   time (for example more IBAN countries) with independent labelled scorecard
   slices, unsupported-country status and safe replacement policies.
4. **P1 — Domain-specific accounts and URLs.** Introduce a distinct
   travel/customer-record class, supplier-provided dictionaries, and URL
   component rules. Avoid masking every public URL or ordinary project code.
5. **P2 — Specialized content.** Clinical narratives, faces/voices, handwriting,
   multilingual names, and linkage risk require separately evaluated models,
   parser provenance and reviewer controls, not a universal pattern list.
