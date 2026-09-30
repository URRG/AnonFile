# Expanded document robustness follow-up

The review after #152 tested 66 additional files: 30 public structural fixtures and 36 synthetic labelled, negative-control, and rejection cases. The independent challenge set found seven defects in shared detection, document extraction/repetition, and frontend response validation. This change fixes those defects and adds focused regression coverage without changing the review-required release posture.

## Fixes and reproducible checks

| Failure | Result after the fix | Regression coverage |
| --- | --- | --- |
| Multi-space phone/card values were missed | Horizontal spacing is preserved inside the detected span; evidenced transcript gutters are separated; bare country codes stay part of the value | `test_numeric_spacing_preserves_complete_source_offsets`, `test_country_code_is_not_stripped_as_a_standalone_transcript_number` |
| Nationality, occupation, race and hyphenated gender values after “is” were missed | Field-specific alternatives restore those values while retaining ordinary age/sex discussion negatives | `test_quasi_identifier_values_follow_field_specific_context`, `test_ordinary_demographic_discussion_is_not_a_value` |
| An SSN detected on page one survived unlabelled on page two with zero known residuals | Contextually detected identifiers and form-context IDs seed document-wide repetition | `test_detected_identifiers_propagate_without_a_repeated_label`, `test_form_context_identifier_seeds_repetition` |
| A nine-page PDF with native headers and scanned IDs received no OCR | Sparse native text and image/form resources remain eligible; the eight-page OCR budget is retained and omissions are explicit | `test_sparse_mixed_pdf_uses_ocr_budget_and_records_omissions`, `test_image_resources_trigger_ocr_even_with_plentiful_native_text` |
| Word tabs/line breaks concatenated names | Structural whitespace survives extraction; explicitly labelled names can wrap across a line without absorbing the next field label | `test_word_controls_preserve_name_boundaries_and_detection`, `test_wrapped_name_does_not_consume_the_next_label` |
| Large valid review responses froze synchronous validation | Unicode code-point length is counted once per surface, without a full-text allocation per finding | Web tests for non-BMP offsets and a 10k-finding response with a subprocess time limit |
| Numbered jurisdictional court captions became addresses or weak name proposals | Court-caption evidence excludes both proposals while retaining addresses ending in Court and nearby names | `test_transcript_numbers_and_court_captions_are_not_identifiers`, `test_real_street_shapes_survive_court_caption_exclusion`, `test_court_caption_is_not_reintroduced_as_a_capitalization_proposal` |

The Python regressions are in `services/api/tests/test_document_robustness.py`. Existing document and processor tests remain in force. The shared rules algorithm revision is incremented to v10; the configuration digest includes the new patterns and exclusions.

## Corpus and results

The [public corpus manifest](validation/public-document-corpus.json) records all 30 source paths, immutable commits/blob identities, file sizes, and SHA-256 hashes. Sources are py-pdf/sample-files, python-openxml/python-docx, scanny/python-pptx, and jmcnamara/XlsxWriter. It comprises 14 PDFs, four DOCX files, four PPTX files and eight XLSX files. These are structural fixtures, not representative customer records; their PII content is not fully labelled. Repository license metadata is recorded without claiming that it independently establishes every fixture's license. Document bytes and extracted source text are kept outside the repository.

The 36 synthetic files include 50 labelled value checks, three negative-control files, and ten malformed/encrypted/over-limit cases. A value check passes only if its expected source occurrences are extracted and fully covered, with none retained in the candidate. The 400-page repeat and 10,000-email cases each count as one value check, preventing repetition from dominating the result.

| Measurement | Before | After |
| --- | ---: | ---: |
| Labelled value checks passed | 34 / 50 | 46 / 50 |
| Detection misses | 12 | 4 |
| Extraction misses | 4 | 0 |
| Negative-control files with a false finding | 1 / 3 | 0 / 3 |
| Expected rejections across both corpora | 11 / 11 | 11 / 11 |
| Unexpected rejection or harness failure | 0 | 0 |
| Successful reviews retaining `release_eligible: false` | 55 / 55 | 55 / 55 |

The worker path processed all 66 files. Public PDFs and the synthetic scan/mixed-page cases used OCR. Other synthetic PDFs disabled OCR to isolate native extraction and detection. The mixed nine-page PDF now uses eight OCR pages and explicitly reports the ninth as unmeasured.

All eight original user-supplied documents were also retested: all 43 selected values remained covered, all 17 expected contact detections remained, and none of the 20 previously rejected false matches returned. These are selected regression checks, not exhaustive document clearance.

## Performance and browser behavior

A roughly 43 KB synthetic DOCX produces 1,519,999 body characters and 10,000 email findings. Running the actual TypeScript response parser on Node 22.23.3 previously exceeded a 60-second timeout. The fixed parser processed the full response in 49 ms in this environment. This is a focused measurement rather than a browser-wide or production throughput guarantee.

A real Chromium session submitted five authenticated local review requests, including the large document and manual corrections. The large document completed end to end in 3.176 seconds in that run. No page errors occurred, and the mobile viewport had no horizontal overflow. Tokens were generated only for the local test and were not persisted in artifacts.

## Automated validation

The API suite passed 1,736 tests with 61 optional integration skips. Web tests passed 112 tests, deployment checks passed six, HTTP integration checks passed three, and the TypeScript/production build succeeded. The optional native integration skips are distinct from those executed checks; the PR CI exercises its configured Postgres/OpenBao/S3/worker environments separately.

## Remaining limitations

The four remaining labelled misses are Cyrillic, Devanagari and Chinese names plus a capitalization-only name proposal repeated in lowercase without contextual evidence. These require explicit reviewer corrections; they are not described as qualified automatic coverage. Manual exact-value corrections for the three non-Latin names and the repeated SSN were checked separately. Weak capitalization proposals intentionally do not propagate without confirmation.

This run does not establish production precision/recall, exhaustive multilingual OCR, handwriting/signature coverage, Office pixel/embedded-object coverage, complete international address recognition, original-format sanitization, or multi-user throughput. The document route remains a bounded development review tool. Every result stays `REVIEW_REQUIRED`; pixels remain `UNMEASURED`; no cleaned original-format file is produced.

## Product demo

The accompanying 24-second Brag/Hyperframes walkthrough uses screenshots of the real UI with fictional PDF and XLSX records. It shows source/candidate comparison, a very-hidden sheet, user-supplied corrections and the actual review-required warning. It does not imply automatic multilingual name recognition or safe-to-share original documents. Generated video and composition assets are delivered separately from this source change.
