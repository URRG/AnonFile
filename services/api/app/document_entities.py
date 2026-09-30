"""Bounded contextual name/address candidates with original-text offsets.

These are explicit-context rules, not general multilingual NER. Unlabelled
names and arbitrary address formats still require review.
"""
from __future__ import annotations

import re
import unicodedata

LETTER = r"[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'’-]+|[A-Z][ \t]*\."
NAME = rf"(?:{LETTER})(?:[ \t]+(?:{LETTER})){{0,4}}"
FULL_NAME = rf"(?:{LETTER})(?:[ \t]+(?:{LETTER})){{1,4}}"
# An explicitly labelled name can wrap within a Word paragraph or PDF line.
WRAPPED_FULL_NAME = rf"(?:{FULL_NAME}|(?:{LETTER})[ \t]*\r?\n[ \t]*(?:{NAME})(?![ \t]*:))"
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
_UNICODE_NAME_FIELD = re.compile(
    r"(?im)^(?:[ \t]*[0-9]{1,3}[ \t]+)?[ \t]*"
    r"(?:name|full name|taxpayer|author|editor|last modified by|reported by|deposition of)[ \t]*:[ \t]*"
    r"(?P<value>[^\t\r\n;,:<>]{1,150}?)"
    r"(?=[ \t]+(?:[a-z][a-z_-]{0,30}|date of birth|full name|last modified by)[ \t]*:|[ ]*(?:[\t;,\r\n]|$))"
)
_NAME_CONNECTORS = "'’\u2010\u2011-"


CONTEXTUAL_RULE_CONFIG = tuple((rule.pattern, rule.flags) for rule in (*_CONTEXTS, _ADDRESS, _COURT_CAPTION, _UNICODE_NAME_FIELD)) + (
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


def contextual_entities(text: str) -> list[tuple[int, int, str]]:
    found = {(m.start('value'), m.end('value'), 'PERSON_NAME')
             for rule in _CONTEXTS for m in rule.finditer(text)}
    found.update((m.start('value'), m.end('value'), 'ADDRESS') for m in _ADDRESS.finditer(text)
                 if not is_court_caption(m.group('value')))
    for match in _UNICODE_NAME_FIELD.finditer(text):
        value = match.group('value').rstrip()
        if is_unicode_name(value):
            found.add((match.start('value'), match.start('value') + len(value), 'PERSON_NAME'))
    return sorted(found)
