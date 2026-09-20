"""Independent, aggregate-only residual scanner for bounded candidate artifacts.

This scanner is intentionally not a second call into ``processing``.  It owns
its own compact recognition rules and evaluates only a deliberately narrow set
of families (PII, PAYMENT, and CREDENTIAL).  The scanner receives a transformed
candidate, never the source dataset, and its public result contains unit-level
family counts only--never matched values, paths, or snippets.

It is a detection control, not a privacy qualification.  In particular it does
not assess health, business-confidential, or quasi-identifier categories, and
does not make linkage, utility, or re-identification claims.
"""
from __future__ import annotations

import hashlib
import re
from collections.abc import Iterator
from typing import Any

from app.residual_eval import DetectorResult


ASSESSED_CATEGORIES = frozenset({"PII", "PAYMENT", "CREDENTIAL"})
DETECTOR_ID = "m8-independent-residual"
_IMPLEMENTATION_VERSION = "v1"

# These patterns are deliberately owned here rather than imported from the
# transformation worker.  They are not a copy of its pattern registry: this is
# a separate residual detector with a separate configuration identity.
_EMAIL = re.compile(r"(?i)(?<![\w.+-])[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+(?![\w.-])")
_PAN = re.compile(r"(?i)(?<![a-z0-9])[a-z]{5}[0-9]{4}[a-z](?![a-z0-9])")
_IPV4 = re.compile(r"(?<![0-9.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9.])")
_NUMBERISH = re.compile(r"(?<![0-9])(?:[0-9][ ()-]?){9,18}[0-9](?![0-9])")
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?ix)\b(?:api[ _-]?key|access[ _-]?token|authorization|password|passwd|secret|"
    r"private[ _-]?key|refresh[ _-]?token)\b\s*(?::|=)\s*(?:\S+|['\"][^'\"]+['\"])",
)
_AUTHORIZATION = re.compile(r"(?i)\b(?:bearer|basic)\s+[a-z0-9._~+/=-]{8,}")
_PAYMENT_SECRET = re.compile(r"(?ix)\b(?:cvv|cvc|card[ _-]?security[ _-]?code)\b\s*(?::|=)\s*[0-9]{3,4}\b")

# Evidence records bind to the concrete rule configuration.  A rule edit
# changes this digest and therefore cannot be presented as evidence from an
# earlier scanner configuration.
_CONFIG_BYTES = "\n".join((
    DETECTOR_ID, _IMPLEMENTATION_VERSION, *sorted(ASSESSED_CATEGORIES),
    *(_EMAIL.pattern, _PAN.pattern, _IPV4.pattern, _NUMBERISH.pattern,
      _CREDENTIAL_ASSIGNMENT.pattern, _AUTHORIZATION.pattern, _PAYMENT_SECRET.pattern),
)).encode("utf-8")
DETECTOR_CONFIG_DIGEST = "sha256:" + hashlib.sha256(_CONFIG_BYTES).hexdigest()


def _luhn(number: str) -> bool:
    """Validate a candidate payment-card number without retaining it."""
    if not 13 <= len(number) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = ord(char) - ord("0")
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _has_valid_ipv4(text: str) -> bool:
    for match in _IPV4.finditer(text):
        if all(int(part) <= 255 for part in match.group().split(".")):
            return True
    return False


def _families_in_text(text: str) -> set[str]:
    """Return family labels only; raw matches never leave this function."""
    families: set[str] = set()
    if _CREDENTIAL_ASSIGNMENT.search(text) or _AUTHORIZATION.search(text):
        families.add("CREDENTIAL")
    if _PAYMENT_SECRET.search(text):
        families.add("PAYMENT")
    if _EMAIL.search(text) or _PAN.search(text) or _has_valid_ipv4(text):
        families.add("PII")
    for match in _NUMBERISH.finditer(text):
        digits = "".join(char for char in match.group() if "0" <= char <= "9")
        if _luhn(digits):
            families.add("PAYMENT")
        elif 10 <= len(digits) <= 15:
            # Phone and government-identifier-shaped strings remain PII.  This
            # deliberately favors conservative residual reporting over trying
            # to infer a country-specific identity type from a bare number.
            families.add("PII")
    return families


def _strings(value: Any) -> Iterator[str]:
    """Yield candidate strings, including JSON keys, without paths or values in output."""
    stack = [value]
    while stack:
        current = stack.pop()
        if type(current) is str:
            yield current
        elif type(current) is dict:
            for key, child in current.items():
                # ``evaluate_candidate`` validates candidate graph and key
                # types before invoking this scanner.  Keep this defensive
                # check for callers that use this module directly.
                if type(key) is str:
                    stack.append(key)
                stack.append(child)
        elif type(current) is list:
            stack.extend(current)


def scan_residual_candidate(candidate: str | list[dict[str, Any]]) -> DetectorResult:
    """Scan one candidate artifact with independent rules and aggregate output.

    Counts are the number of top-level candidate units in which a family was
    observed.  The result explicitly names the only three assessed families;
    every other policy category remains unsupported rather than being reported
    as clean.
    """
    units: list[Any] = [candidate] if type(candidate) is str else candidate
    counts = {category: 0 for category in sorted(ASSESSED_CATEGORIES)}
    for unit in units:
        observed: set[str] = set()
        for value in _strings(unit):
            observed.update(_families_in_text(value))
        for category in observed:
            counts[category] += 1
    return DetectorResult(residual_counts=counts, scanned_units=len(units),
                          assessed_categories=ASSESSED_CATEGORIES)
