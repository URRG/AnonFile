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
import json
import re
from types import MappingProxyType
from typing import Any

from app.residual_eval import DetectorResult


ASSESSED_CATEGORIES = frozenset({"PII", "PAYMENT", "CREDENTIAL"})
DETECTOR_ID = "m8-independent-residual"
# Evidence-relevant, immutable release inputs.  Algorithm revision covers
# matching, classification and traversal semantics; build revision identifies
# the packaged control-plane build.  Bump either when its behavior changes.
ALGORITHM_REVISION = "independent-residual-algorithm-v2"
BUILD_REVISION = "anonflow-m8.1"
_CONFIG_SCHEMA = "residual-detector-config-v1"
MAX_DIRECT_SCAN_NODES = 100_000
MAX_DIRECT_SCAN_DEPTH = 32
MAX_DIRECT_TEXT_BYTES = 2_000_000

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
_AWS_ACCESS_KEY_ID = re.compile(r"(?<!\w)(?:AKIA|ASIA)[A-Z0-9]{16}(?!\w)")
_PAYMENT_SECRET = re.compile(r"(?ix)\b(?:cvv|cvc|card[ _-]?security[ _-]?code)\b\s*(?::|=)\s*[0-9]{3,4}\b")

_RULE_CONFIGURATION = (
    ("email", _EMAIL.pattern, _EMAIL.flags),
    ("pan", _PAN.pattern, _PAN.flags),
    ("ipv4", _IPV4.pattern, _IPV4.flags),
    ("numberish", _NUMBERISH.pattern, _NUMBERISH.flags),
    ("credential_assignment", _CREDENTIAL_ASSIGNMENT.pattern, _CREDENTIAL_ASSIGNMENT.flags),
    ("authorization", _AUTHORIZATION.pattern, _AUTHORIZATION.flags),
    ("aws_access_key_id", _AWS_ACCESS_KEY_ID.pattern, _AWS_ACCESS_KEY_ID.flags),
    ("payment_secret", _PAYMENT_SECRET.pattern, _PAYMENT_SECRET.flags),
)


def _identity_config(*, algorithm_revision: str, build_revision: str) -> dict[str, object]:
    """Build the canonical, source-free configuration bound into evidence."""
    return {
        "schema": _CONFIG_SCHEMA,
        "detector_id": DETECTOR_ID,
        "algorithm_revision": algorithm_revision,
        "build_revision": build_revision,
        "assessed_categories": sorted(ASSESSED_CATEGORIES),
        "rules": _RULE_CONFIGURATION,
    }


def _config_digest(*, algorithm_revision: str, build_revision: str) -> str:
    config = _identity_config(algorithm_revision=algorithm_revision, build_revision=build_revision)
    canonical = json.dumps(config, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


# MappingProxyType and tuple-only descendants prevent post-import mutation of
# the deployed identity configuration.  A rule, algorithm, or build change
# changes the bound digest and cannot be represented as earlier evidence.
DETECTOR_IDENTITY_CONFIG = MappingProxyType(_identity_config(
    algorithm_revision=ALGORITHM_REVISION, build_revision=BUILD_REVISION,
))
DETECTOR_CONFIG_DIGEST = _config_digest(
    algorithm_revision=ALGORITHM_REVISION, build_revision=BUILD_REVISION,
)


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
    if _CREDENTIAL_ASSIGNMENT.search(text) or _AUTHORIZATION.search(text) or _AWS_ACCESS_KEY_ID.search(text):
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


def _families_in_unit(value: Any) -> tuple[set[str], bool]:
    """Bounded direct traversal returning (observed families, complete)."""
    observed: set[str] = set()
    seen_containers: set[int] = set()
    nodes = 0
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_DIRECT_SCAN_NODES or depth > MAX_DIRECT_SCAN_DEPTH:
            return observed, False
        if type(current) is str:
            try:
                if len(current.encode("utf-8")) > MAX_DIRECT_TEXT_BYTES:
                    return observed, False
            except UnicodeError:
                return observed, False
            observed.update(_families_in_text(current))
        elif type(current) is dict:
            if id(current) in seen_containers or len(current) > MAX_DIRECT_SCAN_NODES:
                return observed, False
            seen_containers.add(id(current))
            for key, child in current.items():
                if type(key) is not str:
                    return observed, False
                stack.append((key, depth + 1))
                stack.append((child, depth + 1))
        elif type(current) is list:
            if id(current) in seen_containers or len(current) > MAX_DIRECT_SCAN_NODES:
                return observed, False
            seen_containers.add(id(current))
            stack.extend((child, depth + 1) for child in current)
        elif type(current) not in (int, float, bool) and current is not None:
            return observed, False
    return observed, True


def scan_residual_candidate(candidate: str | list[dict[str, Any]]) -> DetectorResult:
    """Scan one candidate artifact with independent rules and aggregate output.

    Counts are the number of top-level candidate units in which a family was
    observed.  The result explicitly names the only three assessed families;
    every other policy category remains unsupported rather than being reported
    as clean.
    """
    units: list[Any] = [candidate] if type(candidate) is str else candidate
    counts = {category: 0 for category in sorted(ASSESSED_CATEGORIES)}
    abstained = 0
    for unit in units:
        observed, complete = _families_in_unit(unit)
        if not complete:
            abstained += 1
        for category in observed:
            counts[category] += 1
    return DetectorResult(residual_counts=counts, scanned_units=len(units), abstained_units=abstained,
                          assessed_categories=ASSESSED_CATEGORIES)
