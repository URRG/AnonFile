"""Bounded contextual name/address candidates with original-text offsets.

These are explicit-context rules, not general multilingual NER. Unlabelled
names and arbitrary address formats still require review.
"""
from __future__ import annotations

import re
import unicodedata
from bisect import bisect_right

LETTER = r"[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'’-]+|[A-Z][ \t]*\."
NAME = rf"(?:{LETTER})(?:[ \t]+(?:{LETTER})){{0,4}}"
FULL_NAME = rf"(?:{LETTER})(?:[ \t]+(?:{LETTER})){{1,4}}"
# An explicitly labelled name can wrap within a Word paragraph or PDF line.
WRAPPED_FULL_NAME = rf"(?:{FULL_NAME}|(?:{LETTER})[ \t]*\r?\n[ \t]*(?:{NAME})(?![ \t]*:))"
_WRAPPED_NAME_SHAPE = re.compile(WRAPPED_FULL_NAME + r"(?!\w|[ \t]*:)")
_SPEAKER_PREFIX = re.compile(r"[ \t]*(?:[0-9]{1,3}[ \t]+)?(?i:Dr|Prof|Mr|Mrs|Ms|Miss|Rabbi|Smt|Shri|Sri)\.?[ \t]+")
_CONTEXTS = (
    re.compile(rf"\b(?i:Dr|Prof|Mr|Mrs|Ms|Miss|Rabbi|Smt|Shri|Sri)\.?[ \t]+(?P<value>{NAME})(?!\w)"),
    re.compile(rf"(?m)^(?:[ \t]*[0-9]{{1,3}}[ \t]+)?[ \t]*(?i:deposition of|reported by|taxpayer|name|full name|author|editor|last modified by)[ \t]*:?[ \t]*(?P<value>{WRAPPED_FULL_NAME})(?!\w|[ \t]*:)"),
    re.compile(rf"(?m)^[ \t]*(?P<value>{FULL_NAME})[ \t]+\([A-Za-z]{{2,4}}\)"),
    re.compile(rf"(?m)(?P<value>{FULL_NAME})[ \t]*,[ \t]*J\.(?!\w)"),
    re.compile(rf"(?m)^[ \t]*(?P<value>{NAME})(?:[ \t]+&[ \t]+(?i:ORS)\.?)?[ \t]+\.{{2,}}[ \t]*APPELLANT"),
    re.compile(rf"\b(?P<value>{FULL_NAME})[ \t]+(?:attended|prepared|signed|testified|joined|said|works|met)\b"),
)
_COURT_CAPTION = re.compile(
    r"(?i)^[ \t]*(?:[0-9]{1,6}[ \t]+)?(?:in[ \t]+the[ \t]+)?"
    r"(?:(?:state|commonwealth|county|province|republic)[ \t]+of|united[ \t]+states)\b"
    r".*\b(?:district|superior|supreme|high|circuit|appeals)[ \t]+court$"
)
_ADDRESS = re.compile(
    r"(?i)(?<![\w])(?P<value>[0-9]{1,6}[ \t]+(?:[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ.'’-]*[ \t]+){1,7}"
    r"(?:street|st\.?|road|rd\.?|avenue|ave\.?|boulevard|blvd\.?|drive|dr\.?|lane|ln\.?|"
    r"court|ct\.?|way|place|pl\.?|parkway|pkwy\.?|quay|mall))(?!\w)"
)
# Unicode letter/mark validation is deliberately confined to an explicit field.
# A bounded value ends before a delimiter or another inline field label, so a
# name cannot absorb the next email/phone label or an entire paragraph.
_INLINE_LABEL = (
    r"(?:[ ]{2,}[a-z][a-z_-]{0,30}(?:[ ][a-z][a-z_-]{0,30}){0,5}"
    r"|[ \t]+(?:[a-z][a-z_-]{0,30}|date of birth|full name|last modified by|"
    r"customer id|case number|social security(?: number)?))[ \t]*:"
)
_INLINE_FIELD = re.compile(_INLINE_LABEL, re.IGNORECASE)
_NAME_FIELD_PREFIX = (
    r"(?im)^(?:[ \t]*[0-9]{1,3}[ \t]+)?[ \t]*"
    r"(?:name|full name|taxpayer|author|editor|last modified by|reported by|deposition of)[ \t]*:[ \t]*"
)
_NAME_FIELD_START = re.compile(_NAME_FIELD_PREFIX)
_UNICODE_NAME_FIELD = re.compile(
    _NAME_FIELD_PREFIX +
    r"(?P<value>[^\t\r\n;,:<>]{1,150}?)"
    rf"(?={_INLINE_LABEL}|[ ]*(?:[\t;,\r\n]|$))"
)
_NAME_CONNECTORS = "'’\u2010\u2011-"


CONTEXTUAL_RULE_CONFIG = tuple((rule.pattern, rule.flags) for rule in (*_CONTEXTS, _ADDRESS, _COURT_CAPTION, _UNICODE_NAME_FIELD, _INLINE_FIELD, _SPEAKER_PREFIX)) + (
    ("unicode-name-shape", 150, 6, _NAME_CONNECTORS, unicodedata.unidata_version),
)


def is_unicode_name(value: str) -> bool:
    """A bounded non-ASCII name shape; only usable with explicit field evidence."""
    words = value.split()
    if not 2 <= len(value) <= 150 or not 1 <= len(words) <= 6:
        return False
    if not any(ord(char) > 127 and unicodedata.category(char)[0] in {"L", "M"} for char in value):
        return False
    letters = 0
    for word in words:
        if not word[0].isalpha():
            return False
        for index, char in enumerate(word):
            category = unicodedata.category(char)[0]
            if category == "L":
                letters += 1
            elif category == "M":
                if index == 0 or unicodedata.category(word[index - 1])[0] not in {"L", "M"}:
                    return False
            elif char in _NAME_CONNECTORS:
                if index == 0 or index == len(word) - 1 or not word[index + 1].isalpha():
                    return False
            elif char == "." and index == len(word) - 1 and len(word) == 2:
                continue
            else:
                return False
    return letters >= 2


def is_court_caption(value: str) -> bool:
    return bool(_COURT_CAPTION.search(value.rstrip()))


def _wrapped_name_match(text: str, start: int):
    match = _WRAPPED_NAME_SHAPE.match(text, start)
    newline = text.find('\n', start, match.end()) if match else -1
    if newline >= 0 and (_NAME_FIELD_START.match(text, newline + 1) or _SPEAKER_PREFIX.match(text, newline + 1)):
        return None
    return match


def inline_field_boundaries(text: str) -> tuple[list[int], list[int]]:
    """Index labels inside explicit name fields, never transcript speakers.

    Scanning each field line once avoids quadratic work for long paragraphs.
    An honorific speaker such as ``MS. WALBURN:`` is name evidence, not a field
    label to exclude from detection.
    """
    matches = []
    for field in _NAME_FIELD_START.finditer(text):
        end = text.find('\n', field.end())
        wrapped = _wrapped_name_match(text, field.end())
        if wrapped and end >= 0 and wrapped.end() > end:
            # The existing Latin rule permits one line break within a name.
            # Its continuation shares this field's inline-label protection.
            end = text.find('\n', end + 1)
        matches.extend(_INLINE_FIELD.finditer(text, field.end(), len(text) if end < 0 else end))
    bounds = sorted({(match.start(), match.end()) for match in matches})
    return [start for start, _ in bounds], [end for _, end in bounds]


def name_proposal_end(start: int, end: int, fields: tuple[list[int], list[int]]) -> int:
    """Keep inline field labels out of contextual and weak name proposals.

    Within an explicit name field, two spaces delimit arbitrary bounded labels; familiar labels also work
    after one space. A single space before unknown multiword labels remains
    ambiguous with Latin name tokens and requires manual review.
    """
    starts, ends = fields
    index = bisect_right(ends, start)
    if index < len(starts) and starts[index] < end:
        return max(start, starts[index])
    return end


def contextual_entities(text: str) -> list[tuple[int, int, str]]:
    found = set()
    fields = inline_field_boundaries(text)
    for rule in _CONTEXTS:
        for match in rule.finditer(text):
            start = match.start('value')
            if '\n' in match.group('value') and _wrapped_name_match(text, start) is None:
                continue
            end = name_proposal_end(start, match.end('value'), fields)
            if end > start:
                found.add((start, end, 'PERSON_NAME'))
    found.update((m.start('value'), m.end('value'), 'ADDRESS') for m in _ADDRESS.finditer(text)
                 if not is_court_caption(m.group('value')))
    for match in _UNICODE_NAME_FIELD.finditer(text):
        value = match.group('value').rstrip()
        if is_unicode_name(value):
            found.add((match.start('value'), match.start('value') + len(value), 'PERSON_NAME'))
    return sorted(found)
