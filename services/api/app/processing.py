"""Bounded rules-only candidate processing, NEVER an anonymity certification.

Only text and JSON-compatible record objects are supported. Sensitive scalar
numbers/booleans become null, strings become markers. Sensitive container-valued
fields are rejected because their arbitrary nested keys may themselves be values.
Object keys containing detectable sensitive values and source strings containing
reserved output markers are rejected, not renamed. Offsets refer to original text.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import ipaddress
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
RULES_METHOD_ID = "rules-v1"
# Bump ``RULES_METHOD_ALGORITHM_REVISION`` whenever processing behavior changes
# beyond the declarative inputs below.  The digest is a reproducible identity,
# not an assertion that these bounded rules are sufficient for release.
RULES_METHOD_VERSION = "rules-processor-v1"
RULES_METHOD_ALGORITHM_REVISION = "rules-processing-algorithm-v2"
RULES_METHOD_BUILD_REVISION = "anonflow-m9"
_RULES_METHOD_CONFIG_SCHEMA = "rules-processing-config-v1"
LIMITATIONS = (
    "Rules-only coverage is incomplete; no privacy qualification or release approval.",
    "Free-text names, addresses, health context, business confidentiality and indirect identification are not comprehensively detected.",
    "Health, business-confidential and quasi-identifier recognizers are bounded contextual/field-name rules only; they are detection capabilities, not qualified category coverage.",
    "Only text and JSON records are supported; language, semantic, document, media and linkage coverage are unqualified.",
    "Pattern matches are candidates, not validated identity or payment identifiers; false positives and false negatives remain.",
    "Container-valued sensitive fields and reserved transformation markers in source strings or keys are unsupported and rejected.",
)
SEVERITY = {"medium": 1, "high": 2, "critical": 3}
PRIORITY = {"CREDENTIAL": 12, "PAYMENT_SECRET": 11, "FINANCIAL_ACCOUNT": 10,
            "CARD": 10, "AADHAAR": 9,
            "HEALTH_SENSITIVE": 8, "BUSINESS_CONFIDENTIAL": 8, "QUASI_IDENTIFIER": 7,
            "GOVERNMENT_ID": 6,
            "SENSITIVE_NUMBER": 5, "DEVICE_ID": 5, "VEHICLE_ID": 5,
            "USER_ID": 4, "PAN": 4, "EMAIL": 3,
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
# A deliberately narrow free-text IBAN shape. Other jurisdictions still need
# registry-backed adapters; a shape match is a sensitive candidate, not proof
# that an account exists or that the check digits are valid.
_GB_IBAN = re.compile(r"(?<!\w)GB[0-9]{2}[ ]?[A-Z]{4}(?:[ ]?[0-9]{4}){3}[ ]?[0-9]{2}(?!\w)", re.IGNORECASE)
_BANK_ACCOUNT = re.compile(
    r"(?i)\b(?:bank|checking|savings)\s+account(?:\s+(?:number|no\.?))?\s*(?:[:=#-]\s*|\s+)(?P<value>[0-9]{8,17})(?!\w)"
)
_BANK_ROUTING = re.compile(
    r"(?i)\b(?:bank\s+)?routing(?:\s+(?:number|no\.?))?\s*(?:[:=#-]\s*|\s+)(?P<value>[0-9]{9})(?!\w)"
)
_IP = re.compile(r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])")
_IPV6 = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])")
_MAC = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f])")
_USER_HANDLE = re.compile(
    r"(?i)\b(?:username|user\s*id|slack\s+handle|account\s+handle)\s*(?:[:=#-]\s*|\s+)(?P<value>@?[A-Za-z0-9](?:[A-Za-z0-9._-]{1,62}[A-Za-z0-9_])?)(?!\w)"
)
_IDENTITY_DOCUMENT = re.compile(
    r"(?i)\b(?:passport|driver'?s?\s+licen[cs]e)(?:\s+(?:number|no\.?))?\s*(?:[:=#-]\s*|\s+)(?P<value>[A-Z0-9]{6,16})(?!\w)"
)
_VEHICLE_VIN = re.compile(
    r"(?i)\b(?:vin|vehicle\s+identification\s+number)\s*(?:[:=#-]\s*|\s+)(?P<value>[A-HJ-NPR-Z0-9]{17})(?!\w)"
)
_BIRTH_CONTEXT = re.compile(
    r"(?i)\b(?:born\s+on|date\s+of\s+birth|dob)\s*(?:[:=#-]\s*|\s+)(?P<value>(?:[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{1,2}\s+[A-Za-z]{3,9}\s+[0-9]{4}))(?!\w)"
)
_NUMBER = re.compile(r"(?<!\w)\+?[0-9](?:[0-9 ()-]*[0-9])?(?!\w)")
# These are intentionally contextual rules, not vocabulary matches.  A bare
# word such as "allergy" or "confidential" is not enough to redact prose.
# A match consumes the entire delimited value.  Truncating at an arbitrary
# detector cap would redact a prefix then retain an unsafe tail; input-wide byte
# bounds already cap the work and an unquoted value ends at newline/comma/semicolon.
_HEALTH_CONTEXT = re.compile(
    r'''(?ix)\b(?:diagnosis|medical[_\s-]?(?:condition|record(?:[_\s-]?number)?|history)|
        prescription|medication|treatment[_\s-]?plan|lab[_\s-]?result|allerg(?:y|ies)|
        disability|mental[_\s-]?health|health[_\s-]?insurance)\b\s*(?:[:=]|is\b)\s*
        (?:"(?:[^"\\\r\n]|\\.)+"|'(?:[^'\\\r\n]|\\.)+'|[^\r\n,;]+)''',
    re.MULTILINE,
)
_BUSINESS_CONTEXT = re.compile(
    r'''(?ix)\b(?:trade[_\s-]?secret|confidential(?:[_\s-]?(?:business|internal|commercial))?|
        internal[_\s-]?(?:project|roadmap|forecast)|pricing[_\s-]?(?:strategy|model)|
        source[_\s-]?code)\b\s*(?:[:=]|is\b)\s*
        (?:"(?:[^"\\\r\n]|\\.)+"|'(?:[^'\\\r\n]|\\.)+'|[^\r\n,;]+)''',
    re.MULTILINE,
)
_QUASI_CONTEXT = re.compile(
    r'''(?ix)\b(?:age|birth[_\s-]?year|postal[_\s-]?code|zip(?:[_\s-]?code)?|postcode|
        gender|sex|race|ethnicity|nationality|occupation|marital[_\s-]?status|household[_\s-]?size)\b
        \s*(?:[:=]|is\b)\s*(?:"(?:[^"\\\r\n]|\\.)+"|'(?:[^'\\\r\n]|\\.)+'|[^\r\n,;]+)''',
    re.MULTILINE,
)
_FIELD_TYPES: dict[str, tuple[str, str]] = {}
for _names, _kind, _severity in (
    (("password", "passwd", "secret", "apikey", "token", "accesstoken", "refreshtoken", "authorization", "privatekey"), "CREDENTIAL", "critical"),
    (("cvv", "cvc", "pin", "cardsecuritycode"), "PAYMENT_SECRET", "critical"),
    (("cardnumber", "creditcard", "creditcardnumber", "debitcardnumber", "paymentcard"), "CARD", "critical"),
    (("bankaccount", "bankaccountnumber", "checkingaccount", "savingsaccount", "routingnumber",
      "bankroutingnumber", "sortcode", "iban", "cryptowalletaddress", "walletaddress"), "FINANCIAL_ACCOUNT", "critical"),
    (("aadhaar", "aadhar", "aadhaarnumber", "aadharnumber", "governmentid", "ssn", "socialsecuritynumber",
      "nationalid", "nationalidnumber", "taxid", "taxpayerid", "taxidentificationnumber", "voterid",
      "nationalinsurancenumber"), "GOVERNMENT_ID", "critical"),
    (("pan", "pannumber", "passport", "passportnumber", "passportid", "driverslicense",
      "driverlicense", "drivinglicence", "drivinglicense", "licencenumber", "licensenumber"), "GOVERNMENT_ID", "high"),
    (("vin", "vehicleidentificationnumber", "licenseplate", "licenceplate", "vehicleplate"), "VEHICLE_ID", "high"),
    (("macaddress", "deviceid", "deviceserial", "imei", "imsi", "advertisingid", "mobileadvertisingid",
      "cookieid", "rfidtag"), "DEVICE_ID", "high"),
    (("username", "userid", "accountid", "socialhandle", "socialmediahandle", "screenname",
      "profileid"), "USER_ID", "high"),
    (("name", "firstname", "lastname", "fullname", "customername", "passengername", "patientname"), "PERSON_NAME", "high"),
    (("address", "street", "streetaddress", "homeaddress", "billingaddress", "shippingaddress"), "ADDRESS", "high"),
    (("email", "emailaddress"), "EMAIL", "high"),
    (("phone", "phonenumber", "mobile", "mobilenumber", "telephone", "faxnumber"), "PHONE", "high"),
    (("dob", "dateofbirth", "birthdate"), "DATE_OF_BIRTH", "high"),
    (("diagnosis", "medicalcondition", "medicalrecord", "medicalrecordnumber", "medicalhistory",
      "patientid", "nhsnumber", "healthnumber", "medicareid", "healthinsuranceid", "insurancememberid",
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


def _rules_method_identity_config(*, algorithm_revision: str, build_revision: str) -> dict[str, object]:
    """Canonical, source-free identity for the rules processor semantics.

    Pattern/flag, label, bound and output-operation changes affect the digest.
    Algorithm revision captures control-flow changes not represented by those
    declarative values, and must be bumped with such a code change.
    """
    patterns = (
        ("reserved_marker", _RESERVED_MARKER.pattern, _RESERVED_MARKER.flags),
        ("credential", _CREDENTIAL.pattern, _CREDENTIAL.flags),
        ("authorization", _AUTH_TOKEN.pattern, _AUTH_TOKEN.flags),
        ("email", _EMAIL.pattern, _EMAIL.flags), ("pan", _PAN.pattern, _PAN.flags),
        ("gb_iban", _GB_IBAN.pattern, _GB_IBAN.flags),
        ("bank_account", _BANK_ACCOUNT.pattern, _BANK_ACCOUNT.flags),
        ("bank_routing", _BANK_ROUTING.pattern, _BANK_ROUTING.flags),
        ("ipv4", _IP.pattern, _IP.flags), ("number", _NUMBER.pattern, _NUMBER.flags),
        ("ipv6", _IPV6.pattern, _IPV6.flags), ("mac", _MAC.pattern, _MAC.flags),
        ("user_handle", _USER_HANDLE.pattern, _USER_HANDLE.flags),
        ("identity_document", _IDENTITY_DOCUMENT.pattern, _IDENTITY_DOCUMENT.flags),
        ("vehicle_vin", _VEHICLE_VIN.pattern, _VEHICLE_VIN.flags),
        ("birth_context", _BIRTH_CONTEXT.pattern, _BIRTH_CONTEXT.flags),
        ("health_context", _HEALTH_CONTEXT.pattern, _HEALTH_CONTEXT.flags),
        ("business_context", _BUSINESS_CONTEXT.pattern, _BUSINESS_CONTEXT.flags),
        ("quasi_context", _QUASI_CONTEXT.pattern, _QUASI_CONTEXT.flags),
    )
    return {
        "schema": _RULES_METHOD_CONFIG_SCHEMA, "method_id": RULES_METHOD_ID,
        "method_version": RULES_METHOD_VERSION, "algorithm_revision": algorithm_revision,
        "build_revision": build_revision, "modes": sorted(MODES),
        "bounds": {"max_bytes": MAX_BYTES, "max_records": MAX_RECORDS,
                   "max_depth": MAX_DEPTH, "max_nodes": MAX_NODES},
        "patterns": patterns, "field_types": sorted((key, *value) for key, value in _FIELD_TYPES.items()),
        "severity": sorted(SEVERITY.items()), "priority": sorted(PRIORITY.items()),
        "output_semantics": {"external": "redact", "restricted": "ordinal_alias",
                             "credential_payment_secret": "redact", "quasi_identifier": "generalize",
                             "sensitive_numeric_boolean": "nullify"},
    }


def rules_method_config_digest(*, algorithm_revision: str = RULES_METHOD_ALGORITHM_REVISION,
                               build_revision: str = RULES_METHOD_BUILD_REVISION) -> str:
    config = _rules_method_identity_config(algorithm_revision=algorithm_revision, build_revision=build_revision)
    canonical = json.dumps(config, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


RULES_METHOD_CONFIG_DIGEST = rules_method_config_digest()


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
    for match in _GB_IBAN.finditer(normalized):
        add(match.start(), match.end(), "FINANCIAL_ACCOUNT", "critical")
    for pattern in (_BANK_ACCOUNT, _BANK_ROUTING):
        for match in pattern.finditer(normalized):
            start, end = match.span("value")
            add(start, end, "FINANCIAL_ACCOUNT", "critical")
    for match in _IP.finditer(normalized):
        if all(int(part) <= 255 for part in match.group().split(".")):
            add(match.start(), match.end(), "IP_ADDRESS", "medium")
    ipv6_ranges: list[tuple[int, int]] = []
    for match in _IPV6.finditer(normalized):
        try:
            ipaddress.IPv6Address(match.group())
        except ipaddress.AddressValueError:
            continue
        ipv6_ranges.append(match.span())
        add(match.start(), match.end(), "IP_ADDRESS", "medium")
    for match in _MAC.finditer(normalized):
        # A long IPv6 address can contain six two-digit colon groups. Do not
        # relabel that substring as a MAC address solely because it overlaps.
        if any(start <= match.start() and match.end() <= end and end - start > match.end() - match.start()
               for start, end in ipv6_ranges):
            continue
        add(match.start(), match.end(), "DEVICE_ID", "high")
    for pattern, kind, severity in ((_USER_HANDLE, "USER_ID", "high"),
                                    (_IDENTITY_DOCUMENT, "GOVERNMENT_ID", "high"),
                                    (_VEHICLE_VIN, "VEHICLE_ID", "high"),
                                    (_BIRTH_CONTEXT, "DATE_OF_BIRTH", "high")):
        for match in pattern.finditer(normalized):
            start, end = match.span("value")
            add(start, end, kind, severity)
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
