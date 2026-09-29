"""Bounded sensitive query-value candidates in HTTP(S) and relative URLs.

Only explicit parameter names are signals. A public URL, host, path, or
ordinary query parameter is not automatically personal information. Offsets
refer to the raw input so percent-encoded values can be suppressed whole.
"""
from __future__ import annotations

from bisect import bisect_right
from dataclasses import dataclass
import re
from typing import Iterator
from urllib.parse import unquote_plus


URL_TOKEN = re.compile(r"(?i)\bhttps?://[^\s<>\"']+")
# Only path-rooted or dot-relative links are admitted. Bare ``view?x=y`` can
# be ordinary prose or a code token, so it is not promoted to URL context.
# The slash guards avoid matching the path inside an absolute HTTP(S) URL.
RELATIVE_URL_TOKEN = re.compile(r"(?<![\w/])(?:/(?!/)|\.{1,2}/)[^\s<>\"']+")
URL_TRAILING_PUNCTUATION = ".,;:!?)]}"
EMAIL_VALUE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
# Key names are canonicalized by removing ASCII separators after URL decoding.
# Ambiguous `id`, `code`, `ref` and public path components are excluded.
QUERY_KEY_TYPES: dict[str, tuple[str, str]] = {
    "sessionid": ("CREDENTIAL", "critical"),
    "sessiontoken": ("CREDENTIAL", "critical"),
    "patientid": ("HEALTH_SENSITIVE", "high"),
    "medicalrecordnumber": ("HEALTH_SENSITIVE", "high"),
    "userid": ("USER_ID", "high"),
    "customerid": ("USER_ID", "high"),
    "passengerid": ("USER_ID", "high"),
    "employeeid": ("USER_ID", "high"),
    "email": ("EMAIL", "high"),
    "emailaddress": ("EMAIL", "high"),
    "phone": ("PHONE", "high"),
    "phonenumber": ("PHONE", "high"),
    "dob": ("DATE_OF_BIRTH", "high"),
    "dateofbirth": ("DATE_OF_BIRTH", "high"),
    "ssn": ("GOVERNMENT_ID", "critical"),
    "socialsecuritynumber": ("GOVERNMENT_ID", "critical"),
}


@dataclass(frozen=True)
class UrlQueryCandidate:
    start: int
    end: int
    entity_type: str
    severity: str


def find_url_query_candidates(text: str) -> Iterator[UrlQueryCandidate]:
    absolute_tokens = list(URL_TOKEN.finditer(text))
    absolute_starts = [match.start() for match in absolute_tokens]
    tokens = absolute_tokens.copy()
    for match in RELATIVE_URL_TOKEN.finditer(text):
        index = bisect_right(absolute_starts, match.start()) - 1
        if index < 0 or match.start() >= absolute_tokens[index].end():
            tokens.append(match)
    for match in sorted(tokens, key=lambda token: token.start()):
        url = match.group().rstrip(URL_TRAILING_PUNCTUATION)
        question = url.find("?")
        fragment = url.find("#")
        if question < 0 or (fragment >= 0 and fragment < question):
            continue
        query_end = fragment if fragment >= 0 else len(url)
        position = question + 1
        while position < query_end:
            component_end = url.find("&", position, query_end)
            if component_end < 0:
                component_end = query_end
            equals = url.find("=", position, component_end)
            if position < equals < component_end - 1:
                raw_key = url[position:equals]
                key = "".join(char for char in unquote_plus(raw_key).casefold() if char.isascii() and char.isalnum())
                category = QUERY_KEY_TYPES.get(key)
                if category is not None:
                    raw_value = url[equals + 1:component_end]
                    if category[0] != "EMAIL" or EMAIL_VALUE.fullmatch(unquote_plus(raw_value)) is not None:
                        yield UrlQueryCandidate(match.start() + equals + 1, match.start() + component_end, *category)
            position = component_end + 1
