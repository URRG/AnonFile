"""Narrow, deterministic contextual findings for the demo corpus.

These rules deliberately require an unambiguous label or a synthetic/internal
shape.  They are not general PII recognition and fail closed on long values.
"""

from __future__ import annotations

import re

from app.contracts import PayloadError


_MAX_VALUE_LENGTH = 80

_EMPLOYEE_ID = re.compile(
    r"\b(?:employee\s*[-_ ]?\s*id|owner\s+id|id)\s*[:=#-]?\s*"
    r"(?P<value>[A-Z0-9]+(?:-[A-Z0-9]+){1,7})\b",
    re.IGNORECASE,
)
_EMPLOYEE_SHAPE = re.compile(r"(?<!\w)[A-Z]{2,8}-EMP-[0-9]{3,8}(?!\w)", re.IGNORECASE)

# The host requirement is intentional: a normal public URL is not contextual
# evidence.  ``example.test`` is reserved for examples; *.internal and *.corp
# are conventional private-domain evidence.
_INTERNAL_HOST = re.compile(
    r"^(?:(?:[a-z0-9-]+\.)*example\.test|(?:[a-z0-9-]+\.)+(?:internal|corp))$",
    re.IGNORECASE,
)
_URL_TOKEN = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_URL_TRAILING_PUNCTUATION = ".,;:!?)]}"
_URL_LABEL = re.compile(
    r"\b(?:internal|intranet)[ \t]*(?:link|url)?[ \t]*[:=#-][ \t]*$",
    re.IGNORECASE,
)

_STREET_SUFFIX = (
    r"street|st\.?|road|rd\.?|avenue|ave\.?|boulevard|blvd\.?|"
    r"drive|dr\.?|lane|ln\.?|court|ct\.?|way|place|pl\.?|parkway|pkwy\.?|quay"
)
_ADDRESS = re.compile(
    rf"\b(?P<value>\d{{1,6}}\s+[A-Za-z0-9][A-Za-z0-9 .'-]{{0,48}}?\s+"
    rf"(?:{_STREET_SUFFIX})\s*,?\s*(?:\r?\n\s*|,\s*)"
    r"[A-Za-z][A-Za-z .'-]{1,40}\s*,?\s*(?:\r?\n\s*|,\s*)"
    r"[A-Z]{2}\s+\d{5}(?:-\d{4})?)\b",
    re.IGNORECASE,
)


def _bounded(start: int, end: int) -> bool:
    return 0 < end - start <= _MAX_VALUE_LENGTH


def _url_candidates(text: str) -> list[tuple[int, int, str]]:
    candidates: list[tuple[int, int, str]] = []
    for match in _URL_TOKEN.finditer(text):
        raw = match.group()
        value = raw.rstrip(_URL_TRAILING_PUNCTUATION)
        end = match.start() + len(value)
        host = value.split("/", 3)[2].split("@")[-1].split(":", 1)[0]
        preceding = text[max(0, match.start() - 96):match.start()]
        lines = preceding.split("\n")
        # OCR often separates a field label from its value. Accept the
        # immediately preceding line only, and never inherit a label across
        # a blank line or another field.
        same_line = lines[-1]
        labelled = bool(_URL_LABEL.search(same_line))
        if not labelled and not same_line.strip() and len(lines) > 1:
            labelled = bool(_URL_LABEL.search(lines[-2].rstrip("\r")))
        if labelled or _INTERNAL_HOST.fullmatch(host):
            if not _bounded(match.start(), end):
                raise PayloadError("An internal URL exceeds the synthetic review value limit.")
            candidates.append((match.start(), end, "INTERNAL_URL"))
    return candidates


def contextual_spans(text: str) -> list[tuple[int, int, str]]:
    """Return non-overlapping ``(start, end, kind)`` contextual findings.

    Captured values are always 80 characters or fewer. A recognized value that
    exceeds the limit rejects the batch rather than redacting a prefix.
    """
    if not isinstance(text, str) or not text:
        return []

    candidates: list[tuple[int, int, str]] = _url_candidates(text)
    for match in _EMPLOYEE_ID.finditer(text):
        start, end = match.span("value")
        if not _bounded(start, end):
            raise PayloadError("An employee identifier exceeds the synthetic review value limit.")
        candidates.append((start, end, "EMPLOYEE_ID"))
    for match in _EMPLOYEE_SHAPE.finditer(text):
        candidates.append((match.start(), match.end(), "EMPLOYEE_ID"))
    for match in _ADDRESS.finditer(text):
        start, end = match.span("value")
        if not _bounded(start, end):
            raise PayloadError("A postal address exceeds the synthetic review value limit.")
        candidates.append((start, end, "ADDRESS"))

    # Longest wins for identical starts; scanning left-to-right makes the
    # no-overlap decision stable even if future contextual rules are added.
    candidates.sort(key=lambda item: (item[0], -(item[1] - item[0]), item[2]))
    spans: list[tuple[int, int, str]] = []
    last_end = -1
    for candidate in candidates:
        if candidate[0] >= last_end:
            spans.append(candidate)
            last_end = candidate[1]
    return spans
