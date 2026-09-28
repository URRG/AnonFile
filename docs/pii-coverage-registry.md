# Personal-information coverage registry

This is a detector inventory, **not** a claim that the demo anonymizes all
personal information. A value can identify someone only in combination with
other data or context, and new local, sectoral, and organization-specific
identifiers can be created at any time. The current rules worker is an
unqualified, synthetic-data review aid. No item below authorizes release.

Reference taxonomies: [Google Sensitive Data Protection infoTypes](https://docs.cloud.google.com/sensitive-data-protection/docs/concepts-infotypes),
[Microsoft Presidio supported entities](https://microsoft.github.io/presidio/supported_entities/),
[Amazon Comprehend PII entity types](https://docs.aws.amazon.com/comprehend/latest/APIReference/API_PiiEntity.html),
and [ICO guidance on identifiers and context](https://ico.org.uk/for-organisations/uk-gdpr-guidance-and-resources/personal-information-what-is-it/what-is-personal-data/what-are-identifiers-and-related-factors/).
The [HHS de-identification guidance](https://www.hhs.gov/hipaa/for-professionals/special-topics/de-identification/index.html)
adds dates, fax numbers, account/plan numbers, URLs, vehicle/device serials,
biometrics, full-face images and other unique characteristics in its specific
health-data context; [NIST SP 800-188](https://csrc.nist.gov/pubs/sp/800/188/final)
emphasizes risk assessment and governance beyond direct-identifier removal.
These are comparison inventories, not product validation. Their breadth also
shows why a universal regex list is not a defensible completeness strategy.

| Vector / examples | Current bounded behavior | Important gap |
| --- | --- | --- |
| Person names, aliases, email addresses, phone numbers, postal addresses | Email and number rules; explicitly structured/header names; contextual US-style address; batch-local name and email surrogates | Arbitrary names in prose, international addresses and phones, transliteration, nicknames, person disambiguation |
| Birth dates, ages, sex/gender, demographic attributes | Explicit `DOB`/`born on` dates and named date fields | Unlabelled dates, ages, demographic context and quasi-identifier combinations |
| Government IDs | PAN shape; labeled passport/licence, SSN and government-ID fields; explicit tax/voter/national-ID fields; narrow SSN demo surrogate | Country/issuer-specific validation, unlabelled tax/voter IDs, safe format-preserving surrogates |
| Financial and payment | Payment-card/secret rules; GB/DE-shaped IBANs and labeled bank/routing accounts; explicit sort-code/wallet fields | Other-country IBANs, SWIFT/BIC, unlabelled crypto wallets, account ownership, transactions and checksum/issuer validation. Shape is a sensitive candidate, not proof of validity |
| Online and device identifiers | IPv4/IPv6, MAC addresses, labeled usernames/handles, explicit IMEI/IMSI/ad/cookie/RFID fields, internal URLs | Unlabelled device IDs, public/profile URLs, access-log joins, persistent cross-file links |
| Vehicle and property identifiers | Labeled VIN and explicit plate fields | Unlabelled licence plates, registrations, parcel/property identifiers, country-specific formats |
| Employment/education and business confidentiality | Labeled employee IDs and narrow contextual business secrets | Job/education histories, customer/contract IDs, proprietary plans, organization-specific dictionaries |
| Health, genetics, biometrics, beliefs and other sensitive attributes | Narrow health-context phrases and explicit patient/health-ID fields | Clinical narratives/codes, family history, biometrics, faces/voices, religion, political views, sexual orientation and contextual inferences |
| Location, relationships and behavior | Bounded explicit person/role edges; narrow location/address signals | GPS trails, meeting patterns, relatives, social graph and unique combinations of seemingly harmless fields |
| File and media side channels | Bounded TXT/CSV/JSON/JSONL/PDF/image preview, OCR and PDF visual corrections | EXIF/metadata, hidden layers, annotations, attachments, QR/barcodes, handwriting, arbitrary layouts, OCR omissions and unsupported media |

## Required path to qualified coverage

1. Maintain a versioned detector catalogue with jurisdiction, language,
   format, validation strength, transformation policy and known lookalikes.
   Every new detector must be propagated through the policy mapping, review
   register, scorecard label set, media cross-check and tests. Unknown labels
   must fail closed.
2. Annotate a rights-cleared, independently reviewed holdout of realistic
   fictional text, PDF and images, including negatives, OCR misses, partial
   identifiers, table cells and cross-document links. Measure per-type recall,
   precision and residual leakage; do not infer completeness from synthetic
   unit fixtures or from the same OCR engine that produced the candidate.
3. Add locale/industry adapters and configurable supplier-specific
   dictionaries. Validate issuer/checksum formats where appropriate, but do
   not emit a replacement that could plausibly be a live identifier merely to
   preserve shape. When a safe surrogate is not established, use an opaque
   replacement and mark the utility loss for review.
4. Keep the demo's downloadable copy labeled **review only**. Real-data
   ingestion, export and sale require separate rights, security, privacy,
   residual-risk and utility gates, plus independent reviewer approval.

The first bounded rules increment includes GB-shaped IBANs,
labeled bank/routing values, IPv6, MAC, labeled usernames, passport/licence
numbers, VINs and labeled birth dates. Tests establish behavior on fictional
examples, not field accuracy or global coverage.
The DE-shaped extension prevents the tested German example from being
partially classified as a payment card. Other national formats still need a
versioned adapter based on the [Swift IBAN registry](https://www.swift.com/standards/data-standards/iban-international-bank-account-number).

The next structured-field increment adds exact key matches for further
government, finance, device, vehicle, online-account, contact and patient-ID
families. It does **not** infer those categories from arbitrary field names,
unlabelled prose or embedded media. Numeric/boolean sensitive JSON values and
quoted multiline CSV cells remain unsupported in the batch preview rather
than being silently emitted or given a misleading schema-preservation claim.
