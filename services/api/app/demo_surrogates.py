"""Non-issuable, batch-local review surrogates for the synthetic demo.

These values preserve selected syntax, not validity, ownership or release safety.
Unknown jurisdictions and identifier families deliberately keep opaque markers.
"""
from __future__ import annotations

import re

PAN_SHAPE = re.compile(r"[A-Z]{5}[0-9]{4}[A-Z]", re.I)
SSN_SHAPE = re.compile(r"[0-9]{3}([- ]?)[0-9]{2}\1[0-9]{4}")
NANP_SHAPE = re.compile(r"\+1(?:[ .()\-]*[0-9]){10}")


def demo_field_kind(field_name: str, value: str, default: str) -> str:
    """Use explicit field evidence only; never guess a number's jurisdiction."""
    key = "".join(char for char in field_name.casefold() if char.isalnum())
    if key in {"pan", "pannumber"} and PAN_SHAPE.fullmatch(value):
        return "PAN"
    return default


def _with_original_separators(source: str, digits: str) -> str:
    iterator = iter(digits)
    return "".join(next(iterator) if char.isdigit() else char for char in source)


def typed_alias(kind: str, source: str, index: int) -> tuple[str, str] | None:
    """Return a syntax-preserving but intentionally unusable example, if safe.

    Caller supplies a unique batch-local ordinal and checks source collisions.
    """
    if kind == "PAN" and PAN_SHAPE.fullmatch(source) and 1 <= index <= 9999:
        # PAN holder-status character 4 is Z, outside the published status set.
        return f"TSTZA{index:04d}A", "PAN_INVALID_TEST"
    if kind == "GOVERNMENT_ID" and SSN_SHAPE.fullmatch(source) and 1 <= index <= 9999:
        # SSA does not assign area 000; preserve the source's separator style.
        return _with_original_separators(source, f"00001{index:04d}"), "US_SSN_INVALID"
    if kind == "PHONE" and NANP_SHAPE.fullmatch(source) and 1 <= index <= 100:
        # NANPA reserves 555-0100 through 555-0199 as fictitious nonworking lines.
        return _with_original_separators(source, f"1202555{index + 99:04d}"), "NANP_FICTIONAL"
    return None
