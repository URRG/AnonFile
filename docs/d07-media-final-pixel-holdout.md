# D07 bounded synthetic final-pixel holdout

The `app.d07_media_holdout` module evaluates only a SHA-256-pinned synthetic manifest against caller-supplied final raster bytes and an independent OCR adapter. Each declared final raster is also SHA-256-bound before OCR receives it. The manifest carries fictional expected-final and forbidden-source canaries; a missing expected canary, observed forbidden canary, byte mismatch, incomplete case set, unavailable OCR, or OCR failure is blocked fail-closed. Its pin hashes source bytes after the only permitted normalization—legacy CRLF checkout bytes become LF; lone CR is rejected. It does not parse and re-serialize before hashing, so whitespace, key order, and all other source formatting remain pinned. Reports contain status codes and aggregate counts only: no case IDs, OCR transcripts, markers, source bytes, paths, or pixel digests are returned.

`TesseractPixelOcr` is an optional adapter for an already-provisioned concrete `TesseractCliVerifier`. It receives that verifier instance—not a command, executable path, or structural OCR substitute—so it cannot use PATH lookup or bypass its absolute allowlist, executable digest, runtime identity pin, explicit allowlisted tessdata directory, or `eng.traineddata` digest pin. OCR subprocesses use the pinned `--tessdata-dir` and a minimal environment that replaces ambient `TESSDATA_PREFIX`; callers cannot silently select another language model. Tesseract is deliberately unavailable by default in this demo environment. The adapter is not wired into a product endpoint, release process, or authorization path.

The suite has an opt-in local integration test for the exact fictional final PNG bytes. It requires `RUN_D07_TESSERACT_INTEGRATION=1`, `D07_TESSERACT_EXECUTABLE`, and `D07_TESSDATA_DIRECTORY` as absolute existing paths, and skips otherwise. The executable/model SHA pins still apply. The test supplies a checked-in runtime-identity digest for the approved official runtime; it never derives that digest from the runtime under test. The pinned identity includes stdin, PSM 6, explicit tessdata-directory, and English-language CLI semantics (`v2`). This test only verifies bounded fixture wiring for that explicitly pinned executable/model pair; it is not an OCR completeness, recall, or qualification assertion.

The two tiny fictional fixtures are valid, decoded PNGs. `pdf-page-1.png` is rendered from the adjacent fictional `pdf-page-1-source.pdf`; `generate_fixtures.py` records the limited regeneration procedure. The final PNG bytes—not the source PDF—are the values bound in the manifest. Regeneration is only fixture provenance and remains sensitive to its pinned media runtime; it is not evidence that a production renderer or Tesseract installation has been qualified.

It is not wired into release authorization. Every outcome is either blocked, inconclusive, or an observation of synthetic markers; no outcome qualifies a system or authorizes a release.

This remains a scaffold. Passing fictional canaries does not establish OCR completeness, residual-disclosure absence, rendering coverage, qualification, or a release decision. Qualification would require independently curated and access-controlled fixtures, signed lock custody, pinned rendering/OCR environments, adversarial format coverage, OCR calibration/recall analysis, and governed human review.

`app.d07_holdout_manifest.bind_final_artifacts` is a separate preflight for a
future supplied corpus. It verifies the exact bytes of every supplied final
artifact against a SHA-256-pinned manifest and produces only aggregate artifact
counts by format and annotated entity type. Its required manifest digest must
come from a trusted frozen-holdout custodian; the function cannot prove custody,
rights clearance, annotation independence/completeness, OCR coverage, or score
quality. It is not connected to any release path.
