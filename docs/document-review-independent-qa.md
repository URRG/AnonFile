# Independent document-review QA

An independent review after #154 found three cases outside the 50 annotated corpus checks. This follow-up preserves every observed spelling used for repeated-value matching, protects inline form labels, and prevents weak name proposals from starting after a combining mark.

## Corrected behavior

- `Name: Straße Müller` and `Name: Strasse Müller` previously shared a casefold key that retained only the last spelling. Lowercase repetitions of the overwritten spelling could survive while the known-value counter reported zero. Each observed spelling is now retained for matching and residual checks. Canonical replacement markers remain consistent, and weak spellings keep their weaker evidence unless an actual stronger match supersedes them.
- `Name: Анастасия Иванова  Customer ID: AB321` previously absorbed the next field label into the name. Name fields now index their inline labels once and use bounded lookups for contextual and capitalization proposals. Familiar labels work after one space; arbitrary bounded multiword labels use a two-space field separator and single spaces within the label. Repeated spaces inside names remain supported. Ambiguous layouts outside these rules still need manual review.
- A weak proposal could start inside `ÁElena Navarro` or `किElena Navarro` after a combining mark. Both ends of a weak proposal now respect those marks.

Boundary handling is scoped to explicit name fields and their supported single-line Latin continuation. Transcript speakers such as `MS. WALBURN:` remain name evidence; another labelled field or an honorific speaker cannot become a wrapped surname. Boundary indexing avoids repeated scans of long paragraphs. Every observed spelling counts toward the 1,000-seed work budget; the 20,000-match limit remains in force. The rules algorithm identity advances to v12.

## Regression evidence

The independent agent's original eight assertions included seven failures on the prior code. Its final expanded checks passed: 20 adversarial assertions, 20 whitespace/label cases, and 13 parser-worker scenarios. Its focused product run passed 142 tests. A 10,000-finding single paragraph completed in approximately 0.48 seconds during an isolated run; this is a fixture measurement, not a service latency guarantee.

The product name suite now includes 45 additional cases for these fixes, including casefold collisions from strong, weak, metadata and manual evidence; variant work limits; multiword labels; repeated whitespace; wrapped names; adjacent fields; transcript speakers; and a 10,000-finding paragraph. The final API suite passed 1,826 tests with 61 opt-in integration skips. Five of those opt-in tests passed in separate native live-service runs described below. All 112 web tests, 6 deployment checks, 3 HTTP integration checks, and the production web build passed. Python and npm audits reported zero known vulnerabilities.

All eight original uploads were rerun through production parser workers: all 43 selected values remained covered, all 17 expected contact detections remained, and none of the 20 previously rejected false matches returned. The expanded 66-file corpus was rerun on the final source: all 50 selected annotated checks passed, 55 reviews returned, all 11 expected rejections occurred, and the three negative-control files had no false findings. These are selected checks, not a general accuracy estimate.

## Validation without hosted Actions

Hosted GitHub Actions could not start jobs because of the account payment/spending-limit condition reported by GitHub. The user expects availability to reset on October 1. No workflow or branch rule was disabled to work around that condition.

Local native integration checks use the official OpenBao 2.5.5 and RustFS 1.0.0 releases, verified against their published GitHub asset SHA256 values before execution. Disposable loopback services use verified TLS, generated short-lived credentials, the repository's scoped policies, and automatic cleanup. The existing OpenBao tests (2), S3 ciphertext/versioning tests (2), and encrypted-worker test (1) all passed. These native checks do not establish that the digest-pinned Docker images or deployment images build and run here; DockerHub access is blocked. PostgreSQL live integration also remains unrun locally.

## Demo and remaining scope

The replacement demo records the actual default AnonFlow workbench in Chromium against Vite and Uvicorn. It shows fictional TXT/JSON/CSV upload, detected entities, an explicit reviewer correction, source/candidate comparison, relationship evidence, verification limits, and a demo-only download. The recording has no mocked API responses or recreated product interface. The optional subtitle track and pointer marker are presentation aids. A 24-second edit and a complete walkthrough are delivered separately from source control.

Every review stays unqualified and ineligible for production release. Selected corpus checks do not establish general name recall, handwriting or pixel coverage, original-format sanitization, a representative blind holdout result, or production deployment readiness. The broader external gates remain tracked in [pending product gaps](pending-product-gaps.md).
