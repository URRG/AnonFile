"""Shared processing interfaces for the first, non-production milestone.

Offsets are half-open Unicode code-point offsets into the ORIGINAL Python string.
Findings intentionally contain no matched values. These types confer no release
authorization, calibrated confidence, or claim of anonymity.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.candidate import LedgerAction


class PayloadError(ValueError):
    """Safe, fixed-message rejection of unsupported or oversized input."""


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    entity_type: str
    severity: str
    recognizer: str = "rules-v1"


@dataclass(frozen=True)
class Finding:
    entity_type: str
    severity: str
    count: int


@dataclass(frozen=True)
class ActualOutputOperation:
    """Aggregate operation actually applied by the rules worker.

    It deliberately carries only a detector entity type, operation kind and
    count.  The policy adapter maps it to a taxonomy family before it is used
    as candidate evidence; source values and locations never enter this type.
    """

    entity_type: str
    action: LedgerAction
    count: int


@dataclass(frozen=True)
class ProcessingResult:
    output: str | list[dict[str, Any]]
    findings: tuple[Finding, ...]
    actual_operations: tuple[ActualOutputOperation, ...]
    limitations: tuple[str, ...]
    critical_detected: bool
    changed_spans: int
    redacted_fields: int
    method_id: str = "rules-v1"
