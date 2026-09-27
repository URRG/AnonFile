# D07 bounded synthetic final-pixel holdout

The `app.d07_media_holdout` module evaluates only a SHA-256-pinned synthetic manifest against caller-supplied final raster bytes and an independent OCR adapter. Its pin hashes source bytes after the only permitted normalization—legacy CRLF checkout bytes become LF; lone CR is rejected. It does not parse and re-serialize before hashing, so whitespace, key order, and all other source formatting remain pinned. Reports contain status codes and aggregate counts only: no case IDs, OCR transcripts, markers, source bytes, paths, or pixel digests are returned.

It is not wired into release authorization. Every outcome is either blocked, inconclusive, or an observation of synthetic markers; no outcome qualifies a system or authorizes a release.

This remains a scaffold. Qualification would require independently curated and access-controlled fixtures, signed lock custody, pinned rendering/OCR environments, adversarial format coverage, OCR calibration/recall analysis, and governed human review.
