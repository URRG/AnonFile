"""Bounded rules-only candidate processing, NEVER an anonymity certification.

Only text and JSON-compatible record objects are supported. Sensitive scalar
numbers/booleans become null, strings become markers. Sensitive container-valued
fields are rejected because their arbitrary nested keys may themselves be values.
Object keys containing detectable sensitive values and source strings containing
reserved output markers are rejected, not renamed. Offsets refer to original text.
"""
from __future__ import annotations

from collections import Counter
import json
import math
import re
import unicodedata
from typing import Any

from app.candidate import LedgerAction
from app.contracts import ActualOutputOperation, Finding, PayloadError, ProcessingResult, Span

MAX_BYTES = 2_000_000
MAX_RECORDS = 10_000
MAX_DEPTH = 32
MAX_NODES = 100_000
MODES = frozenset({"external_anonymized", "restricted_pseudonymized"})
LIMITATIONS = (
    "Rules-only coverage is incomplete; no privacy qualification or release approval.",
    "Free-text names, addresses, health context, business confidentiality and indirect identification are not comprehensively detected.",
    "Health, business-confidential and quasi-identifier recognizers are bounded contextual/field-name rules only; they are detection capabilities, not qualified category coverage.",
    "Only text and JSON records are supported; language, semantic, document, media and linkage coverage are unqualified.",
    "Pattern matches are candidates, not validated identity or payment identifiers; false positives and false negatives remain.",
    "Container-valued sensitive fields and reserved transformation markers in source strings or keys are unsupported and rejected.",
)
SEVERITY = {"medium": 1, "high": 2, "critical": 3}
PRIORITY = {"CREDENTIAL": 12, "PAYMENT_SECRET": 11, "CARD": 10, "AADHAAR": 9,
            "HEALTH_SENSITIVE": 8, "BUSINESS_CONFIDENTIAL": 8, "QUASI_IDENTIFIER": 7,
            "GOVERNMENT_ID": 6,
            "SENSITIVE_NUMBER": 5, "PAN": 4, "EMAIL": 3,
            "PHONE": 2, "IP_ADDRESS": 1, "PERSON_NAME": 1, "ADDRESS": 1, "DATE_OF_BIRTH": 1}
_RESERVED_MARKER = re.compile(r"\[(?:REDACTED_[A-Z_]+|GENERALIZED_QUASI_IDENTIFIER|[A-Z][A-Z_]*_[0-9]{4,})\]", re.IGNORECASE)

# Quoted alternatives consume spaces/escaped quotes inside secret values. A
# malformed/unterminated quoted value is suppressed through the end of its line.
_CREDENTIAL = re.compile(
    r'''(?ix)\b(?:api[_\s-]?key|password|passwd|secret|access[_\s-]?token|token|authorization)\b
        ["']?\s*[:=]\s*(?:"(?:[^"\\\r\n]|\\.)*(?:"|$)|'(?:[^'\\\r\n]|\\.)*(?:'|$)|[^\s,;}\]]+)''',
    re.MULTILINE,
)
_AUTH_TOKEN = re.compile(r"(?i)\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+")
_EMAIL = re.compile(r"(?<![\w.!#$%&'*+/=?^`{|}~-])[\w.!#$%&'*+/=?^`{|}~-]+@[\w-]+(?:\.[\w-]+)+", re.UNICODE)
_PAN = re.compile(r"(?<!\w)[A-Z]{5}[0-9]{4}[A-Z](?!\w)", re.IGNORECASE)
_IP = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
_NUMBER = re.compile(r"(?<!\w)\+?[0-9](?:[0-9 ()-]*[0-9])?(?!\w)")
# These are intentionally contextual rules, not vocabulary matches.  A bare
# word such as "allergy" or "confidential" is not enough to redact prose.
# Their value boundaries are bounded to avoid consuming an entire document.
_HEALTH_CONTEXT = re.compile(
    r'''(?ix)\b(?:diagnosis|medical[_\s-]?(?:condition|record(?:[_\s-]?number)?|history)|
        prescription|medication|treatment[_\s-]?plan|lab[_\s-]?result|allerg(?:y|ies)|
        disability|mental[_\s-]?health|health[_\s-]?insurance)\b\s*(?:[:=]|is\b)\s*
        (?:"(?:[^"\\\r\n]|\\.){1,256}"|'(?:[^'\\\r\n]|\\.){1,256}'|[^\r\n,;]{1,256})''',
    re.MULTILINE,
)
_BUSINESS_CONTEXT = re.compile(
    r'''(?ix)\b(?:trade[_\s-]?secret|confidential(?:[_\s-]?(?:business|internal|commercial))?|
        internal[_\s-]?(?:project|roadmap|forecast)|pricing[_\s-]?(?:strategy|model)|
        source[_\s-]?code)\b\s*(?:[:=]|is\b)\s*
        (?:"(?:[^"\\\r\n]|\\.){1,256}"|'(?:[^'\\\r\n]|\\.){1,256}'|[^\r\n,;]{1,256})''',
    re.MULTILINE,
)
_QUASI_CONTEXT = re.compile(
    r'''(?ix)\b(?:age|birth[_\s-]?year|postal[_\s-]?code|zip(?:[_\s-]?code)?|postcode|
        gender|sex|race|ethnicity|nationality|occupation|marital[_\s-]?status|household[_\s-]?size)\b
        \s*(?:[:=]|is\b)\s*(?:"(?:[^"\\\r\n]|\\.){1,64}"|'(?:[^'\\\r\n]|\\.){1,64}'|[^\r\n,;]{1,64})''',
    re.MULTILINE,
)
_FIELD_TYPES: dict[str, tuple[str, str]] = {}
for _names, _kind, _severity in (
    (("password", "passwd", "secret", "apikey", "token", "accesstoken", "refreshtoken", "authorization", "privatekey"), "CREDENTIAL", "critical"),
    (("cvv", "cvc", "pin", "cardsecuritycode"), "PAYMENT_SECRET", "critical"),
    (("cardnumber", "creditcard", "creditcardnumber", "debitcardnumber", "paymentcard"), "CARD", "critical"),
    (("aadhaar", "aadhar", "aadhaarnumber", "aadharnumber", "governmentid", "ssn", "socialsecuritynumber"), "GOVERNMENT_ID", "critical"),
    (("pan", "pannumber", "passport", "passportnumber", "driverslicense"), "GOVERNMENT_ID", "high"),
    (("name", "firstname", "lastname", "fullname", "customername", "passengername", "patientname"), "PERSON_NAME", "high"),
    (("address", "street", "streetaddress", "homeaddress", "billingaddress", "shippingaddress"), "ADDRESS", "high"),
    (("email", "emailaddress"), "EMAIL", "high"),
    (("phone", "phonenumber", "mobile", "mobilenumber", "telephone"), "PHONE", "high"),
    (("dob", "dateofbirth", "birthdate"), "DATE_OF_BIRTH", "high"),
    (("diagnosis", "medicalcondition", "medicalrecord", "medicalrecordnumber", "medicalhistory",
      "prescription", "medication", "treatmentplan", "labresult", "allergy", "allergies", "disability",
      "mentalhealth", "healthinsurance"), "HEALTH_SENSITIVE", "high"),
    (("tradesecret", "businesssecret", "confidentialbusiness", "confidentialinternal",
      "internalproject", "internalroadmap", "internalforecast", "pricingstrategy", "pricingmodel",
      "sourcecode"), "BUSINESS_CONFIDENTIAL", "high"),
    (("age", "birthyear", "postalcode", "zipcode", "zip", "postcode", "gender", "sex", "race",
      "ethnicity", "nationality", "occupation", "maritalstatus", "householdsize"), "QUASI_IDENTIFIER", "medium"),
):
    for _name in _names:
        _FIELD_TYPES[_name] = (_kind, _severity)


def _normalized(text: str) -> tuple[str, list[int]]:
    """Compatibility/case-independent detectors without losing original offsets."""
    chars: list[str] = []
    offsets: list[int] = []
    for index, char in enumerate(text):
        if unicodedata.category(char) == "Cf":
            continue
        for normalized_char in unicodedata.normalize("NFKC", char):
            chars.append(normalized_char)
            offsets.append(index)
    return "".join(chars), offsets


def _rank(kind: str, severity: str) -> tuple[int, int]:
    return SEVERITY[severity], PRIORITY[kind]


def _reject_reserved_markers(text: str) -> None:
    normalized, _ = _normalized(text)
    if _RESERVED_MARKER.search(normalized):
        raise PayloadError("Source transformation markers are unsupported.")


def detect_text(text: str) -> tuple[Span, ...]:
    """Detect against immutable original text and merge every overlapping interval.

    Overlap unions take their most sensitive label. Counts describe transformed
    spans, not independently validated entities. No matched values are returned.
    """
    if type(text) is not str:
        raise PayloadError("Text must be a string.")
    try:
        if len(text.encode("utf-8")) > MAX_BYTES:
            raise PayloadError("Payload exceeds the byte limit.")
    except UnicodeError:
        raise PayloadError("Payload contains invalid Unicode.") from None
    normalized, offsets = _normalized(text)
    candidates: list[Span] = []

    def add(start: int, end: int, kind: str, severity: str) -> None:
        candidates.append(Span(offsets[start], offsets[end - 1] + 1, kind, severity))

    for pattern, kind, severity in ((_CREDENTIAL, "CREDENTIAL", "critical"),
                                    (_AUTH_TOKEN, "CREDENTIAL", "critical"),
                                    (_EMAIL, "EMAIL", "high"), (_PAN, "PAN", "high"),
                                    (_HEALTH_CONTEXT, "HEALTH_SENSITIVE", "high"),
                                    (_BUSINESS_CONTEXT, "BUSINESS_CONFIDENTIAL", "high"),
                                    (_QUASI_CONTEXT, "QUASI_IDENTIFIER", "medium")):
        for match in pattern.finditer(normalized):
            add(match.start(), match.end(), kind, severity)
    for match in _IP.finditer(normalized):
        if all(int(part) <= 255 for part in match.group().split(".")):
            add(match.start(), match.end(), "IP_ADDRESS", "medium")
    for match in _NUMBER.finditer(normalized):
        value = match.group()
        digits = sum(char.isdecimal() for char in value)
        if digits < 10:
            continue
        if value.startswith("+") and 10 <= digits <= 12:
            kind, severity = "PHONE", "high"
        elif digits == 12:
            kind, severity = "AADHAAR", "critical"
        elif 13 <= digits <= 19:
            kind, severity = "CARD", "critical"
        elif digits <= 11:
            kind, severity = "PHONE", "high"
        else:
            kind, severity = "SENSITIVE_NUMBER", "critical"
        add(match.start(), match.end(), kind, severity)

    merged: list[Span] = []
    for candidate in sorted(candidates, key=lambda span: (span.start, span.end)):
        if merged and candidate.start < merged[-1].end:
            prior = merged.pop()
            strongest = max((prior, candidate), key=lambda span: _rank(span.entity_type, span.severity))
            merged.append(Span(prior.start, max(prior.end, candidate.end), strongest.entity_type, strongest.severity))
        else:
            merged.append(candidate)
    return tuple(merged)


def _field_type(key: str) -> tuple[str, str] | None:
    normalized, _ = _normalized(key)
    return _FIELD_TYPES.get("".join(char for char in normalized.lower() if char.isalnum()))


def _validate_records(records: Any) -> None:
    if type(records) is not list or not records or len(records) > MAX_RECORDS:
        raise PayloadError("Records must be a nonempty bounded list of objects.")
    if any(type(record) is not dict for record in records):
        raise PayloadError("Records must be a nonempty bounded list of objects.")
    nodes = 0
    # Includes JSON punctuation/escaping, while enforcing limits before encoding a
    # whole possibly enormous graph. The enter/exit stack catches cycles but permits
    # repeated references (which JSON serialization copies).
    active: set[int] = set()
    stack: list[tuple[Any, int, bool]] = [(records, 0, False)]
    byte_count = 0
    while stack:
        value, depth, exiting = stack.pop()
        if exiting:
            active.remove(id(value))
            continue
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise PayloadError("Payload exceeds structural limits.")
        kind = type(value)
        if kind in (dict, list):
            if len(value) > MAX_NODES:
                raise PayloadError("Payload exceeds structural limits.")
            if id(value) in active:
                raise PayloadError("Payload must contain only finite JSON values.")
            active.add(id(value))
            stack.append((value, depth, True))
            byte_count += 2 + max(0, len(value) - 1)
            if kind is dict:
                for key, child in value.items():
                    if type(key) is not str:
                        raise PayloadError("Object keys must be strings.")
                    if len(key) > MAX_BYTES:
                        raise PayloadError("Payload exceeds the byte limit.")
                    if detect_text(key):
                        raise PayloadError("Sensitive object keys are unsupported.")
                    stack.append((child, depth + 1, False))
                    stack.append((key, depth + 1, False))
                    byte_count += 1  # colon
            else:
                stack.extend((child, depth + 1, False) for child in value)
        elif kind in (str, int, float, bool) or value is None:
            if kind is float and not math.isfinite(value):
                raise PayloadError("Payload must contain only finite JSON values.")
            if kind is str and len(value) > MAX_BYTES:
                raise PayloadError("Payload exceeds the byte limit.")
            try:
                byte_count += len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8"))
            except (ValueError, OverflowError, UnicodeError):
                raise PayloadError("Payload must contain only finite JSON values.") from None
        else:
            raise PayloadError("Payload must contain only finite JSON values.")
        if byte_count > MAX_BYTES:
            raise PayloadError("Payload exceeds the byte limit.")
        if kind is str:
            _reject_reserved_markers(value)


def process_payload(*, content: str | None = None, records: list[dict] | None = None,
                    mode: str = "external_anonymized") -> ProcessingResult:
    """Produce internal candidates. This function NEVER grants release permission."""
    if not isinstance(mode, str) or mode not in MODES:
        raise PayloadError("Unsupported processing mode.")
    if (content is None) == (records is None):
        raise PayloadError("Provide exactly one content or records payload.")
    if content is not None and (type(content) is not str or not content.strip()):
        raise PayloadError("Content must be a nonempty string.")
    if records is not None:
        _validate_records(records)
    counts: Counter[tuple[str, str]] = Counter()
    operations: Counter[tuple[str, LedgerAction]] = Counter()
    aliases: dict[tuple[str, str], str] = {}
    changed_spans = 0
    redacted_fields = 0

    def marker(kind: str, original: str) -> tuple[str, LedgerAction]:
        # This is an intentionally total generalization: no source characters
        # survive, and all quasi values are mapped to one broad equivalence
        # class.  It is not presented as a utility-preserving generalization.
        if kind == "QUASI_IDENTIFIER":
            return "[GENERALIZED_QUASI_IDENTIFIER]", LedgerAction.GENERALIZE
        if mode == "external_anonymized" or kind in {"CREDENTIAL", "PAYMENT_SECRET"}:
            return f"[REDACTED_{kind}]", LedgerAction.REDACT
        key = (kind, original)  # exact original; never case-fold identities
        if key not in aliases:
            aliases[key] = f"[{kind}_{len(aliases) + 1:04d}]"
        return aliases[key], LedgerAction.PSEUDONYMIZE

    def record(kind: str, severity: str, action: LedgerAction) -> None:
        counts[(kind, severity)] += 1
        operations[(kind, action)] += 1

    def transform_text(text: str) -> str:
        nonlocal changed_spans
        spans = detect_text(text)
        _reject_reserved_markers(text)
        pieces: list[str] = []
        position = 0
        for span in spans:
            replacement, action = marker(span.entity_type, text[span.start:span.end])
            pieces.extend((text[position:span.start], replacement))
            position = span.end
            record(span.entity_type, span.severity, action)
            changed_spans += 1
        pieces.append(text[position:])
        return "".join(pieces)

    def transform(value: Any, sensitive: tuple[str, str] | None = None) -> Any:
        nonlocal redacted_fields
        if sensitive is not None and type(value) in (dict, list):
            raise PayloadError("Container-valued sensitive fields are unsupported.")
        if type(value) is dict:
            result = {}
            for key, child in value.items():
                field = _field_type(key)
                result[key] = transform(child, field)
            return result
        if type(value) is list:
            return [transform(child, sensitive) for child in value]
        if sensitive is not None and value is not None:
            kind, severity = sensitive
            # Keep the strongest classification if a field contains a credential.
            if type(value) is str:
                for span in detect_text(value):
                    if _rank(span.entity_type, span.severity) > _rank(kind, severity):
                        kind, severity = span.entity_type, span.severity
            redacted_fields += 1
            if type(value) is str:
                replacement, action = marker(kind, value)
                record(kind, severity, action)
                return replacement
            record(kind, severity, LedgerAction.NULLIFY)
            return None
        if type(value) is str:
            return transform_text(value)
        if type(value) in (int, float) and detect_text(str(value)):
            spans = detect_text(str(value))
            for span in spans:
                record(span.entity_type, span.severity, LedgerAction.NULLIFY)
            redacted_fields += 1
            return None
        return value

    output = transform_text(content) if content is not None else transform(records)
    limitations = list(LIMITATIONS)
    if mode == "restricted_pseudonymized":
        limitations.append("Restricted aliases are release-local ordinal labels, not cryptographic pseudonyms; they confer no anonymity or cross-release unlinkability guarantee.")
    if redacted_fields:
        limitations.append("Sensitive numeric and boolean scalar fields are replaced with null; downstream schema validation is required.")
    findings = tuple(Finding(kind, severity, count) for (kind, severity), count in sorted(counts.items()))
    actual_operations = tuple(ActualOutputOperation(kind, action, count)
                              for (kind, action), count in sorted(operations.items(), key=lambda item: (item[0][0], item[0][1].value)))
    return ProcessingResult(output=output, findings=findings, limitations=tuple(limitations),
                            actual_operations=actual_operations,
                            critical_detected=any(f.severity == "critical" for f in findings),
                            changed_spans=changed_spans, redacted_fields=redacted_fields)
