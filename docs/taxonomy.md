# Sensitive-data taxonomy and transformations

> Historical design reference, not implemented controls. M1 is synthetic-only, rules-based and withholds all release output. Scores, independent validation, infrastructure and approval described below are not current capabilities. Use [current development guide](development-m1.md) for runnable instructions.

## Baseline taxonomy

The baseline target is 74 entity types. Detection confidence, source context, and policy—not a label alone—determine treatment. Customer-specific recognizers may add types for proprietary identifiers and terminology.

| Family | Representative types | Default external treatment |
| --- | --- | --- |
| Identity and contact | full/partial names, aliases, usernames, email, phone, address, DOB, age, precise location, social handles | Remove or context-preserving synthetic replacement; coarsen age/location/date |
| Online/device | IP, MAC, cookie, advertising/device IDs, URLs, hostnames | Suppress or generalize; redact query identifiers |
| Government | SSN, Aadhaar, PAN, passport, driver licence, voter, tax/national ID, vehicle plate | Suppress; block if residual |
| Financial | card PAN/CVV/expiry, bank/account/routing/IFSC/IBAN, payment handle, crypto wallet | Suppress exact values; use ranges or categories where needed |
| Health and biometric | patient/provider/insurance ID, diagnosis, medicine, procedure, clinical event, genetics, biometrics | Remove or generalize; route high-risk combinations to review |
| Secrets | passwords, API keys, OAuth tokens, private keys, certificates, connection strings, cloud credentials | Suppress and `BLOCKED`; notify secret-remediation flow where configured |
| Enterprise/BII | employee/customer/vendor IDs, internal projects, repositories, tickets, contracts, invoices/POs, pricing, pipeline, revenue, internal metrics | Replace/suppress based on policy; preserve no rare confidential relation by default |
| HR and legal | compensation, performance, disciplinary records, applicants, legal matter, privilege, union/labour data | Suppress or aggregate; restricted policy by default |
| Special category and communications | race, religion, political opinion, sexuality, calendar/meeting, speaker/signature, attachment metadata | Suppress/generalize; review required unless explicitly permitted |

The taxonomy includes direct identifiers, quasi-identifiers, sensitive attributes, and business-identifying information (BII). Quasi-identifiers can re-identify a person when combined even if each field is harmless in isolation.

## Detection strategy

1. **Deterministic recognition:** regular patterns, checksum validation, field names, country/locality rules, and nearby context words.
2. **Statistical/local NER:** persons, organisations, locations, roles, medical entities, and enterprise terminology.
3. **Tenant recognizers:** explicit patterns, dictionaries, allowlists, and test fixtures for internal IDs and vocabulary.
4. **Adjudication:** resolve conflict or ambiguity using an approved local model; cloud models require egress permission and are never default.

Each finding records entity type, confidence, detector version, source location, and policy rationale. Detection does not expose plaintext in application logs.

## Transformation operators

| Operator | Use | Restriction |
| --- | --- | --- |
| Suppression | Credentials, government IDs, high-risk direct identifiers | Used whenever retention is unnecessary |
| Generalization | Date to month/year, location to region, amount to band | Must be evaluated with other quasi-identifiers |
| Per-entity date shift | Preserve ordering/intervals in restricted analysis | Never used as sole external-release control |
| Synthetic replacement | Retain grammar/role/readability for names or organisations | Generated values must not match source/customer identities |
| Release-scoped HMAC token | Stable linkage in restricted mode | Tenant + release + type scope; no global token reuse |
| Aggregation/small-cell suppression | Tables and statistical outputs | Enforce policy minimum group and diversity checks |

No plaintext hash is an anonymization operator. Unsalted hashes are vulnerable to lookup attacks; even HMAC tokens are pseudonyms, not anonymous identities.

## Mode-specific defaults

For `anonymized_external`, remove direct identifiers, avoid retained mapping, use document-local labels by default, generalize quasi-identifiers, and pass contextual attack tests. For `pseudonymized_restricted`, use release-scoped HMAC tokens and preserve approved relations, with KMS-isolated mappings only if re-identification is explicitly authorized.

## Quality controls

Every recognizer requires synthetic positive, negative, boundary, and adversarial fixtures. Evaluate precision and recall per entity type, format, language, and source category. A recognizer cannot be enabled in an external policy until it has a published benchmark and documented known limitations.
