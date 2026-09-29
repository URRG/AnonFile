"""Narrow, labelled regional-ID candidates; check digits do not prove issuance.

Keep a labelled, mistyped or fictional value sensitive even when its check
digit fails. Never use a passing checksum as authority to generate an
apparently issued replacement identifier.
"""
from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterator


# The acronym SIN is case-sensitive: lower-case "sin" is an ordinary word.
# Both patterns require an explicit adjacent label; bare numeric lookalikes
# are intentionally outside this bounded recognizer's coverage.
CA_SIN = re.compile(
    r"\b(?:(?i:(?:canadian[ \t]+)?social[ \t]+insurance[ \t]+(?:number|no\.?))|SIN)"
    r"[ \t]*(?:[:=#-][ \t]*|[ \t]+)(?P<value>[0-9]{3}(?:[ -]?[0-9]{3}){2})(?![\w-])"
)
UK_NHS = re.compile(
    r"(?i)\bNHS[ \t]+(?:number|no\.?)"
    r"[ \t]*(?:[:=#-][ \t]*|[ \t]+)(?P<value>[0-9]{3}[ -]?[0-9]{3}[ -]?[0-9]{4})(?![\w-])"
)


@dataclass(frozen=True)
class RegionalIdentifierCandidate:
    start: int
    end: int
    entity_type: str
    severity: str
    # Check digit is only a syntactic integrity signal, not identity validation.
    recognizer: str


def ca_sin_mod10_passes(value: str) -> bool:
    """Luhn/Mod-10 for a nine-digit Canadian SIN shape, not issuance status."""
    digits = re.sub(r"[ -]", "", value)
    if len(digits) != 9 or not digits.isascii() or not digits.isdecimal():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        number = int(char)
        if index % 2:
            number *= 2
            if number > 9:
                number -= 9
        total += number
    return total % 10 == 0


def uk_nhs_mod11_passes(value: str) -> bool:
    """NHS Mod-11 check digit for ten-digit shape, not an NHS lookup."""
    digits = re.sub(r"[ -]", "", value)
    if len(digits) != 10 or not digits.isascii() or not digits.isdecimal():
        return False
    check = 11 - sum(int(char) * (10 - index) for index, char in enumerate(digits[:9])) % 11
    if check == 11:
        check = 0
    return check != 10 and check == int(digits[9])


def find_regional_identifier_candidates(text: str) -> Iterator[RegionalIdentifierCandidate]:
    for pattern, kind, severity, check_digit, name in (
        (CA_SIN, "GOVERNMENT_ID", "critical", ca_sin_mod10_passes, "ca-sin-mod10"),
        (UK_NHS, "HEALTH_SENSITIVE", "high", uk_nhs_mod11_passes, "uk-nhs-mod11"),
    ):
        for match in pattern.finditer(text):
            start, end = match.span("value")
            status = "pass" if check_digit(match.group("value")) else "mismatch"
            yield RegionalIdentifierCandidate(start, end, kind, severity, f"{name}-{status}-v1")
