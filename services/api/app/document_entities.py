"""Bounded contextual name/address candidates with original-text offsets.

These are explicit-context rules, not general multilingual NER. Unlabelled
names and arbitrary address formats still require review.
"""
from __future__ import annotations

import re

LETTER = r"[A-ZÀ-ÖØ-Þ][A-Za-zÀ-ÖØ-öø-ÿ'’-]+|[A-Z][ \t]*\."
NAME = rf"(?:{LETTER})(?:[ \t]+(?:{LETTER})){{0,4}}"
FULL_NAME = rf"(?:{LETTER})(?:[ \t]+(?:{LETTER})){{1,4}}"
_CONTEXTS = (
    re.compile(rf"\b(?i:Dr|Prof|Mr|Mrs|Ms|Miss|Rabbi|Smt|Shri|Sri)\.?[ \t]+(?P<value>{NAME})(?!\w)"),
    re.compile(rf"(?m)^(?:[ \t]*[0-9]{{1,3}}[ \t]+)?[ \t]*(?i:deposition of|reported by|taxpayer|name|full name|author|editor|last modified by)[ \t]*:?[ \t]*(?P<value>{FULL_NAME})(?!\w)"),
    re.compile(rf"(?m)^[ \t]*(?P<value>{FULL_NAME})[ \t]+\([A-Za-z]{{2,4}}\)"),
    re.compile(rf"(?m)(?P<value>{FULL_NAME})[ \t]*,[ \t]*J\.(?!\w)"),
    re.compile(rf"(?m)^[ \t]*(?P<value>{NAME})(?:[ \t]+&[ \t]+(?i:ORS)\.?)?[ \t]+\.{{2,}}[ \t]*APPELLANT"),
    re.compile(rf"\b(?P<value>{FULL_NAME})[ \t]+(?:attended|prepared|signed|testified|joined|said|works|met)\b"),
)
_ADDRESS = re.compile(
    r"(?i)(?<![\w])(?P<value>[0-9]{1,6}[ \t]+(?:[A-Za-zÀ-ÿ][A-Za-zÀ-ÿ.'’-]*[ \t]+){1,7}"
    r"(?:street|st\.?|road|rd\.?|avenue|ave\.?|boulevard|blvd\.?|drive|dr\.?|lane|ln\.?|"
    r"court|ct\.?|way|place|pl\.?|parkway|pkwy\.?|quay|mall))(?!\w)"
)


CONTEXTUAL_RULE_CONFIG = tuple((rule.pattern, rule.flags) for rule in (*_CONTEXTS, _ADDRESS))

def contextual_entities(text: str) -> list[tuple[int, int, str]]:
    found = {(m.start('value'), m.end('value'), 'PERSON_NAME')
             for rule in _CONTEXTS for m in rule.finditer(text)}
    found.update((m.start('value'), m.end('value'), 'ADDRESS') for m in _ADDRESS.finditer(text))
    return sorted(found)
