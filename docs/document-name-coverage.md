# Name coverage follow-up

This records the #154 change. The subsequent [independent QA follow-up](document-review-independent-qa.md) covers observed spelling collisions, field boundaries, and transcript regressions.

The expanded challenge set at #153 left four annotated misses: three explicitly labelled names in Cyrillic, Devanagari and Chinese, and a capitalization-only name whose lowercase repetition survived on the next page. This change addresses all four while keeping every document result review-required.

## Detection and proposal behavior

English name-field labels followed by a colon now accept Unicode letters and attached combining marks. The values are bounded to six words and 150 characters; internal apostrophes/hyphens and initials are supported. Tabs, newlines, delimiters and subsequent inline labels end the field. Scripts without letter case can supply a single-word name. Unicode author/creator metadata can seed full-value repetitions elsewhere in the document. Original source offsets and consistent replacement markers are retained.

Capitalization-based proposals now carry over to full-value, case-insensitive repetitions with flexible whitespace. Their basis remains `capitalization-repeat-review`, and the document exposes `CAPITALIZATION_REPEAT_REVIEW_REQUIRED`. These are unconfirmed proposals, not newly established identities. They do not enter the known-value residual counter. An explicit reviewer correction takes precedence over the weak proposal. Title-word/court-caption exclusions remain active, partial-word matches are excluded, and repetition cannot leave an attached combining mark behind.

The shared limit of 1,000 distinct repetition seeds now includes weak proposals. The existing 20,000-match and worker resource limits still apply; exceeding a limit fails the review. Rules algorithm identity advances to v11 and includes the new field pattern, name-shape bounds, connectors and Unicode database version.

## Validation

The same 66-file corpus was rerun through production parser workers: all 50 annotated value checks passed, versus 46/50 at #153. All 55 returned reviews remained ineligible for release, all 11 expected rejections behaved as expected, and the three negative-control files had no false findings. These 50 checks are selected source-value checks, not a general accuracy estimate.

All eight original supplied documents were rerun. All 43 selected values remained covered, all 17 expected contact detections remained, and none of the 20 previously rejected false matches returned.

Regression cases in `services/api/tests/test_document_name_coverage.py` cover Cyrillic, Devanagari, Chinese, Japanese, Korean, Arabic, extended Latin, decomposed accents, format controls, inline labels, invalid value shapes, author metadata, presentation notes, spreadsheet cell boundaries, weak-proposal provenance, explicit corrections and the entity limit. Existing corpus extraction and numeric-identifier regressions remain in force.

The final local API suite passed 1,781 tests with 61 optional integration skips. The focused document/processor group passed 326 tests, including 45 added cases. All 112 web tests and the production build passed. Four real Chromium requests verified Unicode fields, weak repetition reasons, correction precedence and the negative court caption. No page errors or mobile overflow occurred, and responses retained `no-store` and the review-required posture.

## Limits

The rules recognize name-shaped text under explicit field evidence. They do not qualify arbitrary multilingual names in prose, translated field labels, OCR errors, unusual/multiline name formats, or every Unicode normalization variant. Weak capitalization proposals can still be false positives, including repeated ordinary phrases. Reviewers must inspect those proposals. Adding repeated proposals increases work for documents with many distinct names; the existing bounded worker remains a development review mechanism.

Pixels, handwriting, embedded Office content and original-format sanitization remain outside this text-candidate coverage. An empty residual count and a passing challenge set do not authorize sharing an original file. The earlier product-demo recording is a snapshot of #153 and its automatic name behavior should not be used to describe this follow-up.
