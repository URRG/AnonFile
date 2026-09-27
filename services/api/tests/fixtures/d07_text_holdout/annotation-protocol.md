# D07 frozen synthetic text holdout annotation protocol

This tiny, wholly synthetic reference set exists only to regression-test the
text exact-span evaluator. A fixture annotator authored its text and gold
annotations without using the synthetic demo label files or the checked-in
automatic predictions. The automatic predictions were authored afterwards to
exercise true positives, false negatives, and false positives.

Offsets are half-open Unicode code-point positions. Label every direct
sensitive span using the fixed evaluator entity registry; leave a record empty
only when it contains no such span. This protocol and its reference annotations
are deliberately not evidence of external annotation independence, corpus
representativeness, detector generalization, media redaction quality, or
release safety.
