"""Ephemeral, explicitly synthetic batch review; never a release pipeline.

Text and raster candidates are review-only. PDF/image candidates are rebuilt
from pixels, not original document objects. OCR can miss content; no input or
candidate is persisted or qualified for release by this module. A synthetic
demo copy may be downloaded after explicit acknowledgement.
"""
from __future__ import annotations

import base64
import binascii
import csv
import hashlib
from itertools import product
from io import StringIO
import json
import re
from collections import Counter
from pathlib import PurePath
from typing import Any

from app.contracts import PayloadError
from app.demo_surrogates import SSN_SHAPE, demo_field_kind, typed_alias
from app.evaluation import EvaluationError, evaluate, parse_gold, parse_predictions
from app.media_preview import extract_media, render_candidate
from app.processing import _field_type, detect_text

MAX_FILES = 3
MAX_TEXT_FILE_BYTES = 100_000
MAX_MEDIA_FILE_BYTES = 500_000
MAX_TOTAL_BYTES = 1_500_000
MAX_BATCH_MEDIA_PIXELS = 3_000_000
SUPPORTED = {".txt": "text", ".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".pdf": "pdf",
             ".png": "image", ".jpg": "image", ".jpeg": "image"}
NAME_FIELDS = {"name", "full_name", "first_name", "last_name", "customer_name", "passenger_name", "client_name", "account_owner"}
HEADER = re.compile(r"(?im)^(From|To|Cc):\s*([^<>\r\n]{2,80}?)\s*<([^<>\s]+@[^<>\s]+)>\s*$")
# Bounded Slack-style roster rows. An email on the same line is direct
# evidence for person/address linking; proximity in a conversation is not.
ROSTER_ROW = re.compile(r"(?im)^\s*([A-Z][A-Za-z'-]+(?: [A-Z][A-Za-z'-]+){1,2})\s*\|\s*([^|<>\s]+@[^|<>\s]+)\s*(?:\||$)")
JSON_NAME = re.compile(r'"(?:name|full_name|first_name|last_name|customer_name|passenger_name|client_name|account_owner)"\s*:\s*"([^"\\]{2,80})"', re.I)
JSON_FIELD = re.compile(r'"(?P<key>(?:[^"\\]|\\.){1,80})"\s*:\s*(?P<value>"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)', re.I)
TEXT_NAME = re.compile(r"(?im)^\s*(?:name|client|customer|passenger)\s*:\s*([A-Z][A-Za-z .'-]{1,78})\s*$")
SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z .'-]{1,79}$")
SAFE_ALIAS = re.compile(r"^[A-Za-z][A-Za-z '-]{1,79}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
SAFE_GRAPH_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 &'().-]{1,100}$")
# These patterns intentionally require labelled signature lines.  A person's
# name near a company name (or a title in ordinary prose) is not evidence of
# employment or reporting structure.
SIGNATURE_BLOCK = re.compile(
    r"(?im)^Name:\s*(?P<person>[A-Za-z][A-Za-z .'-]{1,79})\s*$\r?\n"
    r"^Title:\s*(?P<title>[^\r\n]{2,100})\s*$\r?\n"
    r"^Company:\s*(?P<organization>[A-Za-z0-9][A-Za-z0-9 &'().-]{1,100})\s*$"
)
ASSISTANT_TITLE = re.compile(r"^assistant\s+to\s+(?P<principal>[A-Za-z][A-Za-z .'-]{1,79})$", re.I)
ASSISTANT_FOR_TITLE = re.compile(r"^assistant\s+for\s+(?P<organization>[A-Za-z0-9][A-Za-z0-9 &'().-]{1,100})$", re.I)
INLINE_GRAPH_RECORD = re.compile(r"(?m)^\s*(?P<record>\{[^\r\n]{2,400}\})\s*$")
EXPLICIT_CLIENT_OF = re.compile(r"(?im)^(?P<person>[A-Za-z][A-Za-z .'-]{1,79}) is a client of (?P<organization>[A-Za-z0-9][A-Za-z0-9 &'().-]{1,100})\.$")
EXPLICIT_ASSISTANT_TO = re.compile(r"(?im)^(?P<assistant>[A-Za-z][A-Za-z .'-]{1,79}) is assistant to (?P<principal>[A-Za-z][A-Za-z .'-]{1,79})\.$")
EXPLICIT_ASSISTANT_FOR = re.compile(r"(?im)^(?P<assistant>[A-Za-z][A-Za-z .'-]{1,79}) is assistant for (?P<organization>[A-Za-z0-9][A-Za-z0-9 &'().-]{1,100})\.$")
EXPLICIT_WORKS_ON = re.compile(r"(?im)^(?P<person>[A-Za-z][A-Za-z .'-]{1,79}) works on (?P<project>[A-Za-z0-9][A-Za-z0-9 &'().-]{1,100})\.$")
EXPLICIT_ASSIGNED_TO = re.compile(r"(?im)^(?P<project>[A-Za-z0-9][A-Za-z0-9 &'().-]{1,100}) is assigned to (?P<person>[A-Za-z][A-Za-z .'-]{1,79})\.$")
MAX_GRAPH_NODES = 100
MAX_GRAPH_EDGES = 200
MAX_GRAPH_EVIDENCE_PER_EDGE = 20
MAX_GRAPH_FACTS = 500
# Curated fictional *name* substitutions, not arbitrary alphanumeric tokens.
# The PDF renderer replaces OCR text in its original box, so each component
# must have the same character width as the source component. These lists are
# deliberately bounded: an unsupported name shape needs reviewer input rather
# than a plausible-looking but silently unsafe or overflowing fallback.
GIVEN_NAME_POOL = (
    "Jo", "Al", "Ed", "Li", "Ava", "Ira", "Mia", "Leo", "Sam", "Ana", "Ian", "Eli", "Zoe", "Max", "Eva", "Uma",
    "John", "Gita", "Nina", "Sara", "Noah", "Liam", "Omar", "Asha", "Mina", "Tara", "Amir", "Aria", "Nila", "Rina", "Alex", "Mira", "Kira", "Lena", "Jude", "Ruth", "Eric", "Finn", "Hana", "Jaya", "Kavi", "Luca", "Ravi", "Tina", "Vera",
    "Leena", "David", "Maria", "Elena", "Priya", "Aaron", "Ethan", "Caleb", "Alice", "Anita", "Kiran", "Nadia", "Akira", "Emily", "Grace", "Henry", "James", "Julia", "Lucas", "Meera", "Oscar", "Peter", "Sarah", "Sofia",
    "Ananya", "Sophia", "Olivia", "Daniel", "Miriam", "Aditya", "Aayush", "Keisha", "Aaliya", "Amelia", "Ariana", "Arthur", "Claire", "Hannah", "Jasmine", "Julian", "Marcus", "Rachel", "Samuel", "Simone",
    "Michael", "Jessica", "William", "Natasha", "Aishani", "Sabrina", "Lakshmi", "Eleanor", "Abigail", "Anthony", "Cameron", "Crystal", "Dominic", "Natalie", "Rebecca",
    "Benjamin", "Isabella", "Victoria", "Florence", "Carolina", "Gabriela", "Jonathan", "Michelle", "Nicholas", "Penelope", "Savannah",
    "Katherine", "Elizabeth", "Alexander", "Gabriella", "Nathaniel", "Charlotte", "Catherine", "Sebastian",
    "Alexandria", "Jacqueline", "Maximilian", "Christiana",
    "Christopher",
)
FAMILY_NAME_POOL = (
    "Li", "Wu", "Yu", "Ng", "Ho", "Hu", "Ma", "Rao", "Lee", "Kim", "Roy", "Das", "Ali", "Fox", "Sen", "Ray", "Cox",
    "Singh", "Khan", "Shah", "Bose", "Park", "Chen", "Reed", "Hunt", "King", "Ross", "Gill", "Stone", "Blake", "Green", "Brown", "Adams", "Lewis", "Jones", "Mehta", "Patel",
    "Turner", "Martin", "Thomas", "Wilson", "Morgan", "Walker", "Sharma", "Kapoor", "Murphy", "Parker", "Cooper", "Brooks", "Rivera", "Bailey",
    "Bennett", "Jackson", "Stewart", "Collins", "Freeman", "Coleman", "Edwards", "Russell", "Griffin", "Mitchell",
    "Williams", "Anderson", "Campbell", "Sullivan", "Franklin", "Phillips", "Martinez", "Robinson",
    "Fernandez", "Rodriguez", "Henderson", "Patterson", "Robertson", "Hamilton", "Thompson", "Chaudhary",
    "Richardson", "Montgomery", "Washington", "Schneider",
)
NAME_COMPONENTS = re.compile(r"[A-Za-z]+(?:[ '-][A-Za-z]+)*\Z")
MAX_REFERENCE_LABELS_PER_FILE = 200
REVIEW_EXCLUSION_REASON = "FALSE_POSITIVE_CONFIRMED"
SUPPRESSIBLE_KINDS = frozenset({"PERSON_NAME", "EMAIL", "PHONE", "IP_ADDRESS"})
MANUAL_FINDING_KINDS = frozenset({"OTHER_SENSITIVE", "BUSINESS_CONFIDENTIAL", "QUASI_IDENTIFIER", "GOVERNMENT_ID", "DATE_OF_BIRTH"})
SAFE_MANUAL_VALUE = re.compile(r"^[^\x00-\x1f\x7f]{2,80}$")
TEXT_SSN = re.compile(r"(?im)\b(?:ssn|social[ -]?security[ -]?number)\s*[:=]\s*(?P<value>[0-9]{3}(?:[- ]?[0-9]{2})?[- ]?[0-9]{4})\b")
SAMPLE_TEXT_DIGESTS = {
    "01-email-thread.txt": "ef136ed6bb9c2931a07915d8ae22a487c5899cab825d211472cd63cd8f54f8ef",
    "02-passenger-list.csv": "09887d08254054222a6549ae76cbc8ec4f5f78ef2d6c599932f24e408a5610ca",
    "03-support-record.json": "3b937a15f585638d31e5c2d02b2b29664ece2aae592878b64997524860882e98",
}
SAMPLE_REFERENCE_VALUES = {
    "01-email-thread.txt": (("Riya", "PERSON_NAME"), ("Sita", "PERSON_NAME"),
                            ("riya@example.test", "EMAIL"), ("sita@example.test", "EMAIL"),
                            ("+1 415 555 0134", "PHONE")),
    "02-passenger-list.csv": (("Riya", "PERSON_NAME"), ("Sita", "PERSON_NAME"),
                              ("riya@example.test", "EMAIL"), ("sita@example.test", "EMAIL"),
                              ("DEMO123456", "GOVERNMENT_ID"), ("DEMO654321", "GOVERNMENT_ID"),
                              ("1990-01-01", "DATE_OF_BIRTH"), ("1992-02-02", "DATE_OF_BIRTH"),
                              ("DEMO-4821", "OTHER_SENSITIVE"), ("DEMO-4822", "OTHER_SENSITIVE")),
    "03-support-record.json": (("Riya", "PERSON_NAME"), ("Sita", "PERSON_NAME"),
                               ("DEMO-4822", "OTHER_SENSITIVE")),
}


def _verify_curated_sample(labelled: list[dict[str, Any]], documents: list[dict[str, Any]]) -> None:
    if {doc["name"]: hashlib.sha256(doc["text"].encode("utf-8")).hexdigest() for doc in documents} != SAMPLE_TEXT_DIGESTS:
        raise PayloadError("Curated sample labels require the exact built-in synthetic files.")
    by_id = {doc["id"]: doc for doc in documents}
    for item in labelled:
        doc = by_id[item["id"]]
        expected = []
        for value, kind in SAMPLE_REFERENCE_VALUES[doc["name"]]:
            start = 0
            while (start := doc["text"].find(value, start)) >= 0:
                expected.append((start, start + len(value), kind))
                start += len(value)
        supplied = [(span["start"], span["end"], span["entity_type"]) for span in item["annotations"]]
        if sorted(supplied) != sorted(expected):
            raise PayloadError("Curated sample labels do not match the built-in reference.")


def _score_reference_annotations(value: object, documents: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Score reviewed spans only against explicitly supplied synthetic labels.

    The caller's exhaustiveness assertion is not verified. This measures
    agreement with those labels, not independent detector quality or anonymity.
    """
    if value is None:
        return None
    if (not isinstance(value, dict) or set(value) != {"basis", "documents"}
            or value["basis"] not in {"REVIEWER_ATTESTED_EXHAUSTIVE", "CURATED_SYNTHETIC_SAMPLE"}):
        raise PayloadError("Invalid synthetic reference annotations.")
    labelled = value["documents"]
    if not isinstance(labelled, list) or len(labelled) != len(documents):
        raise PayloadError("Reference annotations must cover every demo file.")
    by_id = {document["id"]: document for document in documents}
    if any(not isinstance(item, dict) or set(item) != {"id", "annotations"}
           or not isinstance(item["id"], str) or item["id"] not in by_id
           or not isinstance(item["annotations"], list)
           or len(item["annotations"]) > MAX_REFERENCE_LABELS_PER_FILE for item in labelled):
        raise PayloadError("Invalid synthetic reference annotations.")
    if len({item["id"] for item in labelled}) != len(documents):
        raise PayloadError("Reference annotations must cover every demo file exactly once.")
    try:
        gold = parse_gold([{"id": item["id"], "text": by_id[item["id"]]["text"],
                            "annotations": item["annotations"]} for item in labelled])
        if value["basis"] == "CURATED_SYNTHETIC_SAMPLE":
            _verify_curated_sample(labelled, documents)
        predictions = parse_predictions([{"id": document["id"], "annotations": [
            {"start": match["start"], "end": match["end"], "entity_type": match["kind"]}
            for match in document["matches"] if match["applied"]]} for document in documents], gold)
        automatic_predictions = parse_predictions([{"id": document["id"], "annotations": [
            {"start": match["start"], "end": match["end"], "entity_type": match["kind"]}
            for match in document["matches"] if match["origin"] == "AUTOMATIC"]} for document in documents], gold)
        report = evaluate(gold, predictions)
        automatic_report = evaluate(gold, automatic_predictions)
    except EvaluationError:
        raise PayloadError("Invalid synthetic reference annotations.") from None
    exact = report["exact"]
    def counts(item: dict[str, Any]) -> dict[str, int]:
        return {"true_positives": item["true_positives"], "false_positives": item["false_positives"],
                "false_negatives": item["false_negatives"]}
    per_document = []
    for document in gold:
        expected = set(document.annotations)
        actual = set(predictions[document.id])
        matched = expected & actual
        missed = sorted(expected - actual, key=lambda span: (span.start, span.end, span.entity_type))
        per_document.append({"id": document.id,
                             "exact": {"true_positives": len(matched), "false_positives": len(actual - expected),
                                       "false_negatives": len(missed)},
                             "missed": [{"start": span.start, "end": span.end, "entity_type": span.entity_type}
                                        for span in missed]})
    return {"basis": value["basis"], "status": "OBSERVATIONAL_ONLY",
            "labelled_documents": len(documents), "gold_annotations": exact["corpus"]["gold_annotations"],
            "exact": counts(exact["corpus"]),
            "automatic_exact": counts(automatic_report["exact"]["corpus"]),
            "per_type": {kind: counts(item) for kind, item in exact["per_entity"].items()},
            "per_document": per_document}


def _validate_structured(format_name: str, content: str) -> None:
    try:
        if format_name == "json":
            parsed = json.loads(content)
            if not isinstance(parsed, (dict, list)):
                raise ValueError
        elif format_name == "jsonl":
            if not all(isinstance(json.loads(line), dict) for line in content.splitlines() if line.strip()):
                raise ValueError
        elif format_name == "csv":
            rows = list(csv.reader(StringIO(content), strict=True))
            if not rows or not rows[0] or any(len(row) != len(rows[0]) for row in rows[1:]):
                raise ValueError
    except (ValueError, csv.Error, UnicodeError, RecursionError):
        raise PayloadError("A structured demo file is invalid or unsupported.") from None


def _read_file(item: dict[str, Any]) -> dict[str, Any]:
    identifier, name, encoded = item.get("id"), item.get("name"), item.get("content_base64")
    if not isinstance(identifier, str) or not SAFE_ID.fullmatch(identifier):
        raise PayloadError("Invalid demo file identity.")
    if not isinstance(name, str) or not (1 <= len(name) <= 160) or "/" in name or "\\" in name:
        raise PayloadError("Invalid demo filename.")
    extension = PurePath(name.lower()).suffix
    if extension not in SUPPORTED:
        raise PayloadError("Supported demo files are TXT, CSV, JSON, JSONL, PDF, PNG, and JPEG.")
    kind = SUPPORTED[extension]
    if not isinstance(encoded, str) or len(encoded) > 670_000:
        raise PayloadError("Demo file exceeds the size limit.")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise PayloadError("Invalid demo file encoding.") from None
    limit = MAX_MEDIA_FILE_BYTES if kind in {"pdf", "image"} else MAX_TEXT_FILE_BYTES
    if not raw or len(raw) > limit:
        raise PayloadError("A demo file exceeds the size limit for its format.")
    media_pages = None
    if kind in {"pdf", "image"}:
        if kind == "pdf" and not raw.startswith(b"%PDF-"):
            raise PayloadError("The selected PDF is invalid.")
        content, media_pages = extract_media(raw, extension)
    else:
        try:
            content = raw.decode("utf-8-sig", errors="strict")
        except UnicodeError:
            raise PayloadError("Demo text files must be UTF-8.") from None
        if not content.strip():
            raise PayloadError("Demo files cannot be blank.")
        _validate_structured(kind, content)
    result = {"id": identifier, "name": name, "kind": kind, "text": content, "size_bytes": len(raw),
              "preview_fidelity": "raster_ocr_review" if media_pages is not None else "source_text"}
    if media_pages is not None:
        result["_media_pages"] = media_pages
    return result


def _csv_cells(line: str, base: int) -> list[tuple[int, int]]:
    """Map ordinary one-line CSV cells to raw offsets; fail closed on ambiguity."""
    cells = []
    position = 0
    while True:
        if position < len(line) and line[position] == '"':
            start = position + 1
            position = start
            while position < len(line):
                if line[position] == '"':
                    if position + 1 < len(line) and line[position + 1] == '"':
                        position += 2
                        continue
                    break
                position += 1
            if position >= len(line):
                raise PayloadError("Multiline or malformed CSV cells are unsupported in batch preview.")
            end = position
            position += 1
            if position < len(line) and line[position] != ',':
                raise PayloadError("Ambiguous CSV quoting is unsupported in batch preview.")
        else:
            start = position
            while position < len(line) and line[position] != ',':
                if line[position] == '"':
                    raise PayloadError("Ambiguous CSV quoting is unsupported in batch preview.")
                position += 1
            end = position
        cells.append((base + start, base + end))
        if position == len(line):
            break
        position += 1
    return cells


def _structured_fields(document: dict[str, Any]) -> list[tuple[int, int, str]]:
    text, kind = document["text"], document["kind"]
    result: list[tuple[int, int, str]] = []
    ssn_values: set[str] = set()
    if kind in {"json", "jsonl"}:
        for match in JSON_FIELD.finditer(text):
            try:
                field = _field_type(json.loads('"' + match.group("key") + '"'))
            except (ValueError, UnicodeError):
                continue
            if not field or match.group("value") == "null":
                continue
            value = match.group("value")
            if not value.startswith('"'):
                raise PayloadError("Numeric or boolean sensitive JSON fields are unsupported in batch preview.")
            start, end = match.start("value") + 1, match.end("value") - 1
            if end - start > 120:
                raise PayloadError("A sensitive structured field exceeds the review value limit.")
            field_name = json.loads('"' + match.group("key") + '"')
            field_kind = demo_field_kind(field_name, text[start:end], field[0])
            if "".join(char for char in field_name.casefold() if char.isalnum()) in {"ssn", "socialsecuritynumber"} and SSN_SHAPE.fullmatch(text[start:end]):
                ssn_values.add(text[start:end].casefold())
            result.append((start, end, field_kind))
    elif kind == "csv":
        offset = 0
        lines = text.splitlines(keepends=True)
        header: list[str] | None = None
        for raw_line in lines:
            line = raw_line.rstrip("\r\n")
            if not line and header is not None:
                offset += len(raw_line)
                continue
            try:
                values = next(csv.reader([line], strict=True))
            except (ValueError, csv.Error):
                raise PayloadError("Multiline CSV is unsupported in batch preview.") from None
            spans = _csv_cells(line, offset)
            if len(spans) != len(values):
                raise PayloadError("Ambiguous CSV cells are unsupported in batch preview.")
            if header is None:
                header = values
            else:
                for field_name, (start, end) in zip(header, spans):
                    field = _field_type(field_name)
                    if field and end > start:
                        if end - start > 120:
                            raise PayloadError("A sensitive structured field exceeds the review value limit.")
                        value = text[start:end]
                        field_kind = demo_field_kind(field_name, value, field[0])
                        if "".join(char for char in field_name.casefold() if char.isalnum()) in {"ssn", "socialsecuritynumber"} and SSN_SHAPE.fullmatch(value):
                            ssn_values.add(value.casefold())
                        result.append((start, end, field_kind))
            offset += len(raw_line)
    document["_ssn_values"] = ssn_values
    return result


def _names_and_headers(documents: list[dict[str, Any]]) -> tuple[set[str], list[tuple[str, str, str]]]:
    names: set[str] = set()
    edges: list[tuple[str, str, str]] = []
    for document in documents:
        text = document["text"]
        sender: str | None = None
        recipients: list[str] = []

        def flush_message() -> None:
            if sender:
                for recipient in recipients:
                    if sender.casefold() != recipient.casefold():
                        edges.append((sender, recipient, document["id"]))

        for match in HEADER.finditer(text):
            name = match.group(2).strip()
            if SAFE_NAME.fullmatch(name):
                names.add(name)
                if match.group(1).casefold() == "from":
                    flush_message()
                    sender, recipients = name, []
                elif sender:
                    recipients.append(name)
        flush_message()
        for match in ROSTER_ROW.finditer(text):
            if SAFE_NAME.fullmatch(match.group(1)):
                names.add(match.group(1))
        for match in JSON_NAME.finditer(text):
            if SAFE_NAME.fullmatch(match.group(1)):
                names.add(match.group(1))
        for match in TEXT_NAME.finditer(text):
            if SAFE_NAME.fullmatch(match.group(1)):
                names.add(match.group(1))
        if document["kind"] == "csv":
            rows = list(csv.DictReader(StringIO(text)))
            for row in rows:
                for key, value in row.items():
                    if key and key.strip().casefold() in NAME_FIELDS and value and SAFE_NAME.fullmatch(value.strip()):
                        names.add(value.strip())
    return names, edges


def _structured_records(documents: list[dict[str, Any]]):
    """Yield one parsed record at a time; never link values across records."""
    for document in documents:
        kind = document["kind"]
        if kind == "json":
            parsed = json.loads(document["text"])
            records = parsed if isinstance(parsed, list) else [parsed]
        elif kind == "jsonl":
            records = [json.loads(line) for line in document["text"].splitlines() if line.strip()]
        elif kind == "csv":
            records = list(csv.DictReader(StringIO(document["text"])))
        else:
            continue
        for record in records:
            if isinstance(record, dict):
                yield document, record


def _email_owners(documents: list[dict[str, Any]]) -> dict[str, str]:
    """Bind an address to a person only with a header or unambiguous same-record evidence."""
    owners: dict[str, str] = {}

    def bind(address: str, name: str) -> None:
        key = address.casefold()
        prior = owners.get(key)
        if prior is not None and prior != name.casefold():
            raise PayloadError("Conflicting person/email associations need manual identity review.")
        owners[key] = name.casefold()

    for document in documents:
        for match in HEADER.finditer(document["text"]):
            name = match.group(2).strip()
            if SAFE_NAME.fullmatch(name):
                bind(match.group(3), name)
        for match in ROSTER_ROW.finditer(document["text"]):
            name = match.group(1).strip()
            if SAFE_NAME.fullmatch(name):
                bind(match.group(2), name)
    for _, record in _structured_records(documents):
        names = {value.strip().casefold() for key, value in record.items()
                 if isinstance(key, str) and key.strip().casefold() in NAME_FIELDS
                 and isinstance(value, str) and SAFE_NAME.fullmatch(value.strip())}
        if len(names) != 1:
            continue
        addresses = [value.strip() for key, value in record.items()
                     if isinstance(key, str) and _field_type(key) and _field_type(key)[0] == "EMAIL"
                     and isinstance(value, str)]
        for address in addresses:
            bind(address, next(iter(names)))
    return owners


def _structured_role_edges(documents: list[dict[str, Any]]) -> list[tuple[str, str, str, str]]:
    """Read only direct owner/client fields in one parsed record, never proximity."""
    edges: list[tuple[str, str, str, str]] = []
    for document, record in _structured_records(documents):
        kind = document["kind"]
        owner, client = record.get("account_owner"), record.get("client_name")
        if (isinstance(owner, str) and isinstance(client, str)
                and SAFE_NAME.fullmatch(owner.strip()) and SAFE_NAME.fullmatch(client.strip())
                and owner.strip().casefold() != client.strip().casefold()):
            edges.append((owner.strip(), client.strip(), document["id"], kind))
    return edges


def _entity_graph_facts(documents: list[dict[str, Any]],
                        header_edges: list[tuple[str, str, str]]) -> list[dict[str, str]]:
    """Extract only relationship claims expressed by a bounded explicit form.

    Graph facts deliberately retain their source values only until aliases and
    pseudonymous graph labels are constructed.  Callers must never expose them.
    In particular, this function does not infer relationships from entity
    proximity, repeated domains, message threads, or arbitrary prose.
    """
    facts: list[dict[str, str]] = []

    def person(value: object) -> str | None:
        if isinstance(value, str) and SAFE_NAME.fullmatch(value.strip()):
            return value.strip()
        return None

    def label(value: object) -> str | None:
        if isinstance(value, str) and SAFE_GRAPH_LABEL.fullmatch(value.strip()):
            return value.strip()
        return None

    def add(type_: str, source_kind: str, source: str, target_kind: str,
            target: str, document_id: str, rule: str, field: str) -> None:
        if source.casefold() != target.casefold():
            if len(facts) >= MAX_GRAPH_FACTS:
                raise PayloadError("The explicit entity graph exceeds the synthetic demo review limit.")
            facts.append({"type": type_, "source_kind": source_kind, "source": source,
                          "target_kind": target_kind, "target": target,
                          "document_id": document_id, "rule": rule, "field": field})

    for sender, recipient, document_id in header_edges:
        add("sent_to", "person", sender, "person", recipient, document_id,
            "explicit_mail_header", "From/To/Cc")
    records = list(_structured_records(documents))
    # OCR/text fixtures can contain an exact one-line JSON record.  This is a
    # deliberate escape hatch for document evidence, not a JSON-like prose
    # parser: malformed or multiline content is ignored rather than guessed.
    for document in documents:
        if document["kind"] in {"json", "jsonl", "csv"}:
            continue
        for match in INLINE_GRAPH_RECORD.finditer(document["text"]):
            try:
                record = json.loads(match.group("record"))
            except (ValueError, TypeError):
                continue
            if isinstance(record, dict) and all(isinstance(key, str) for key in record):
                records.append((document, record))
    for document, record in records:
        assistant, principal = person(record.get("assistant")), person(record.get("assistant_to"))
        if assistant and principal:
            add("assistant_to", "person", assistant, "person", principal, document["id"],
                "explicit_structured_field_pair", "assistant,assistant_to")
        assistant_for = label(record.get("assistant_for"))
        if assistant and assistant_for:
            add("assistant_for", "person", assistant, "organization", assistant_for, document["id"],
                "explicit_structured_field_pair", "assistant,assistant_for")
        worker_field = "person_name" if person(record.get("person_name")) else "employee_name"
        worker = person(record.get(worker_field))
        organization_field = next((key for key in ("works_at", "company", "employer") if label(record.get(key))), None)
        organization = label(record.get(organization_field)) if organization_field else None
        if worker and organization:
            add("works_at", "person", worker, "organization", organization, document["id"],
                "explicit_structured_field_pair",
                f"{worker_field},works_at" if organization_field == "works_at" else organization_field)
        client, client_for = person(record.get("client_name")), label(record.get("client_for"))
        if client and client_for:
            add("client_of", "person", client, "organization", client_for, document["id"],
                "explicit_structured_field_pair", "client_name,client_for")
        contributor_field = "person_name" if person(record.get("person_name")) else "employee_name"
        contributor, project = person(record.get(contributor_field)), label(record.get("works_on"))
        if contributor and project:
            add("works_on", "person", contributor, "project", project, document["id"],
                "explicit_structured_field_pair", f"{contributor_field},works_on")
        assigned_project, assignee = label(record.get("project_name")), person(record.get("assigned_to"))
        if assigned_project and assignee:
            add("assigned_to", "project", assigned_project, "person", assignee, document["id"],
                "explicit_structured_field_pair", "project_name,assigned_to")
    for document in documents:
        for match in SIGNATURE_BLOCK.finditer(document["text"]):
            signer, organization = person(match.group("person")), label(match.group("organization"))
            if not signer or not organization:
                continue
            add("works_at", "person", signer, "organization", organization, document["id"],
                "explicit_signature_block", "Name,Title,Company")
            assistant_match = ASSISTANT_TITLE.fullmatch(match.group("title").strip())
            if assistant_match:
                principal = person(assistant_match.group("principal"))
                if principal:
                    add("assistant_to", "person", signer, "person", principal, document["id"],
                        "explicit_signature_title", "Title")
            assistant_for_match = ASSISTANT_FOR_TITLE.fullmatch(match.group("title").strip())
            if assistant_for_match:
                assisted_organization = label(assistant_for_match.group("organization"))
                if assisted_organization:
                    add("assistant_for", "person", signer, "organization", assisted_organization, document["id"],
                        "explicit_signature_title", "Title")
        # These are complete, line-bounded declarative claims.  Similar words
        # elsewhere in an email cannot create an affiliation edge.
        for match in EXPLICIT_CLIENT_OF.finditer(document["text"]):
            client, organization = person(match.group("person")), label(match.group("organization"))
            if client and organization:
                add("client_of", "person", client, "organization", organization, document["id"],
                    "explicit_role_statement", "client_of_statement")
        for match in EXPLICIT_ASSISTANT_TO.finditer(document["text"]):
            assistant, principal = person(match.group("assistant")), person(match.group("principal"))
            if assistant and principal:
                add("assistant_to", "person", assistant, "person", principal, document["id"],
                    "explicit_role_statement", "assistant_to_statement")
        for match in EXPLICIT_ASSISTANT_FOR.finditer(document["text"]):
            assistant, organization = person(match.group("assistant")), label(match.group("organization"))
            if assistant and organization:
                add("assistant_for", "person", assistant, "organization", organization, document["id"],
                    "explicit_role_statement", "assistant_for_statement")
        for match in EXPLICIT_WORKS_ON.finditer(document["text"]):
            contributor, project = person(match.group("person")), label(match.group("project"))
            if contributor and project:
                add("works_on", "person", contributor, "project", project, document["id"],
                    "explicit_role_statement", "works_on_statement")
        for match in EXPLICIT_ASSIGNED_TO.finditer(document["text"]):
            project, assignee = label(match.group("project")), person(match.group("person"))
            if project and assignee:
                add("assigned_to", "project", project, "person", assignee, document["id"],
                    "explicit_role_statement", "assigned_to_statement")
    return facts


def _public_entity_graph(facts: list[dict[str, str]], person_ids: dict[str, str],
                         person_labels: dict[str, str]) -> dict[str, list[dict[str, Any]]]:
    """Render source-free graph nodes and evidence from explicit facts only."""
    def unique_casefold(values: list[str]) -> list[str]:
        by_key: dict[str, str] = {}
        for value in sorted(values, key=lambda item: (item.casefold(), item)):
            by_key.setdefault(value.casefold(), value)
        return list(by_key.values())

    organization_values = unique_casefold([fact[side] for fact in facts for side in ("source", "target")
                                            if fact[f"{side}_kind"] == "organization"])
    project_values = unique_casefold([fact[side] for fact in facts for side in ("source", "target")
                                       if fact[f"{side}_kind"] == "project"])
    opaque_ids = {
        "organization": {value.casefold(): f"organization_{index}" for index, value in enumerate(organization_values, 1)},
        "project": {value.casefold(): f"project_{index}" for index, value in enumerate(project_values, 1)},
    }

    def node_id(kind: str, value: str) -> str | None:
        if kind == "person":
            return person_ids.get(value.casefold())
        return opaque_ids[kind].get(value.casefold())

    evidence_by_node: dict[str, set[str]] = {}
    grouped: dict[tuple[str, str, str], list[dict[str, str]]] = {}
    for fact in facts:
        source_id, target_id = node_id(fact["source_kind"], fact["source"]), node_id(fact["target_kind"], fact["target"])
        if not source_id or not target_id:
            continue
        evidence_by_node.setdefault(source_id, set()).add(fact["document_id"])
        evidence_by_node.setdefault(target_id, set()).add(fact["document_id"])
        grouped.setdefault((fact["type"], source_id, target_id), []).append(fact)
    if len(evidence_by_node) > MAX_GRAPH_NODES or len(grouped) > MAX_GRAPH_EDGES:
        raise PayloadError("The explicit entity graph exceeds the synthetic demo review limit.")
    nodes: list[dict[str, Any]] = []
    for value, entity_id in sorted(person_ids.items()):
        if entity_id in evidence_by_node:
            nodes.append({"id": entity_id, "kind": "person", "label": person_labels[value],
                          "document_ids": sorted(evidence_by_node[entity_id])})
    for kind, prefix in (("organization", "Organization"), ("project", "Project")):
        for index, value in enumerate((organization_values if kind == "organization" else project_values), 1):
            identifier = opaque_ids[kind][value.casefold()]
            nodes.append({"id": identifier, "kind": kind, "label": f"{prefix} {index}",
                          "document_ids": sorted(evidence_by_node.get(identifier, set()))})
    edges = []
    for index, ((type_, source_id, target_id), grouped_facts) in enumerate(sorted(grouped.items()), 1):
        evidence = sorted({(fact["document_id"], fact["rule"], fact["field"])
                           for fact in grouped_facts})
        if len(evidence) > MAX_GRAPH_EVIDENCE_PER_EDGE:
            raise PayloadError("An entity graph relationship has too much evidence for this demo.")
        edges.append({"id": f"relationship_{index}", "type": type_, "source_id": source_id,
                      "target_id": target_id, "evidence": [
                          {"document_id": doc_id, "rule": rule, "field": field}
                          for doc_id, rule, field in evidence]})
    return {"nodes": nodes, "edges": edges}


def _email_aliases(keys: list[tuple[str, str]], names_by_key: dict[str, str],
                   name_aliases: dict[str, str], owners: dict[str, str],
                   exclusions: dict[str, str], id_by_key: dict[tuple[str, str], str]) -> dict[str, str]:
    """Keep email syntax and owner/domain equivalence without using a routable domain."""
    emails = [value for kind, value in keys if kind == "EMAIL"]
    domains = sorted({value.rsplit("@", 1)[1] for value in emails})
    domain_aliases = {domain: f"org{index}.test"
                      for index, domain in enumerate((domain for domain in domains if domain != "example.test"), 1)}
    if "example.test" in domains:
        domain_aliases["example.test"] = "example.test"
    reserved = set(emails)
    used: set[str] = set()
    aliases: dict[str, str] = {}
    for index, email in enumerate(emails, 1):
        owner = owners.get(email)
        if owner not in names_by_key or id_by_key[("PERSON_NAME", owner)] in exclusions:
            owner = None
        local = re.sub(r"[^a-z0-9]", "", name_aliases[owner].casefold()) if owner else f"contact{index}"
        local = local or f"contact{index}"
        domain = domain_aliases[email.rsplit("@", 1)[1]]
        candidate = f"{local}@{domain}"
        suffix = 1
        while candidate in used or candidate in reserved:
            suffix += 1
            candidate = f"{local}{suffix}@{domain}"
        aliases[email] = candidate
        used.add(candidate)
    return aliases


def _choose_alias(name: str, used: set[str], protected_tokens: set[str]) -> str:
    """Choose a readable, same-shape alias; never invent an ``Axxxx`` token.

    Keeping the word boundaries and component lengths makes the result usable
    in a narrow OCR/PDF text box. It is not a guarantee of identical font
    metrics, so the raster renderer remains subject to visual review.
    """
    if not NAME_COMPONENTS.fullmatch(name):
        raise PayloadError("A person name needs a same-length alias chosen by a reviewer.")
    pieces = re.split(r"([ '-])", name)
    word_indexes = [index for index in range(0, len(pieces), 2)]
    # A batch of people should not collapse into a roster of identical given
    # names. Reuse remains possible when the finite same-width pool is small,
    # but choose the least-used eligible components first.
    component_use = Counter(component.casefold() for alias in used
                            for component in re.findall(r"[A-Za-z]+", alias)
                            if component.casefold() not in protected_tokens)
    choices = []
    for ordinal, index in enumerate(word_indexes):
        source = pieces[index].casefold()
        pool = FAMILY_NAME_POOL if len(word_indexes) > 1 and ordinal == len(word_indexes) - 1 else GIVEN_NAME_POOL
        eligible = [candidate for candidate in pool if len(candidate) == len(pieces[index])
                    and candidate.casefold() != source and candidate.casefold() not in protected_tokens
                    and candidate.casefold() not in used]
        choices.append(sorted(eligible, key=lambda candidate: component_use[candidate.casefold()]))
    for names in product(*choices):
        candidate_pieces = pieces.copy()
        for index, replacement in zip(word_indexes, names):
            candidate_pieces[index] = replacement
        candidate = "".join(candidate_pieces)
        if candidate.casefold() not in used:
            used.add(candidate.casefold())
            return candidate
    raise PayloadError("A person name needs a same-length alias chosen by a reviewer.")


def _exact_phrase_matches(text: str, value: str) -> list[re.Match[str]]:
    return list(re.finditer(r"(?<!\w)" + re.escape(value) + r"(?!\w)", text, re.I))


def analyze_batch(payload: dict[str, Any]) -> dict[str, Any]:
    """Return synthetic-only review data; never an anonymous or exportable artifact."""
    if payload.get("synthetic_only") is not True:
        raise PayloadError("Explicit synthetic-only acknowledgement is required.")
    items = payload.get("files")
    if not isinstance(items, list) or not 2 <= len(items) <= MAX_FILES or any(not isinstance(item, dict) for item in items):
        raise PayloadError("Provide two or three synthetic demo files.")
    documents = []
    media_pixels = 0
    for item in items:
        document = _read_file(item)
        if "_media_pages" in document:
            media_pixels += sum(page["image"].width * page["image"].height
                                for page in document["_media_pages"])
            if media_pixels > MAX_BATCH_MEDIA_PIXELS:
                raise PayloadError("The synthetic batch exceeds the three-million-pixel media review limit.")
        documents.append(document)
    if len({doc["id"] for doc in documents}) != len(documents) or sum(doc["size_bytes"] for doc in documents) > MAX_TOTAL_BYTES:
        raise PayloadError("Duplicate file identities or batch size over 1.5 MB.")
    phrases = payload.get("manual_names", [])
    manual_findings = payload.get("manual_findings", [])
    overrides = payload.get("alias_overrides", {})
    exclusions = payload.get("review_exclusions", {})
    if not isinstance(phrases, list) or len(phrases) > 20 or not all(isinstance(v, str) and SAFE_NAME.fullmatch(v) for v in phrases):
        raise PayloadError("Manual names must be at most 20 short person names.")
    if any(not any(re.search(r"(?<!\w)" + re.escape(name) + r"(?!\w)", doc["text"], re.I)
                   for doc in documents) for name in phrases):
        raise PayloadError("A manually added name must occur in at least one file.")
    if (not isinstance(manual_findings, list) or len(manual_findings) > 20 or
            any(not isinstance(item, dict) or set(item) != {"value", "kind"} or
                not isinstance(item["value"], str) or not SAFE_MANUAL_VALUE.fullmatch(item["value"]) or
                not all(char.isprintable() for char in item["value"]) or
                item["value"] != item["value"].strip() or not isinstance(item["kind"], str) or
                item["kind"] not in MANUAL_FINDING_KINDS
                for item in manual_findings) or
            len({(item["value"].casefold(), item["kind"]) for item in manual_findings}) != len(manual_findings)):
        raise PayloadError("Invalid manually reviewed sensitive findings.")
    if any(not any(_exact_phrase_matches(doc["text"], item["value"]) for doc in documents) for item in manual_findings):
        raise PayloadError("A manual finding must occur in at least one file.")
    if not isinstance(overrides, dict) or len(overrides) > 100 or not all(isinstance(k, str) and isinstance(v, str) for k, v in overrides.items()):
        raise PayloadError("Invalid alias overrides.")
    if (not isinstance(exclusions, dict) or len(exclusions) > 100
            or any(not isinstance(key, str) or reason != REVIEW_EXCLUSION_REASON for key, reason in exclusions.items())):
        raise PayloadError("Invalid reviewer exclusions.")

    for document in documents:
        document["_fields"] = _structured_fields(document)
        document["_labelled_ssns"] = [(match.start("value"), match.end("value")) for match in TEXT_SSN.finditer(document["text"])
                                     if SSN_SHAPE.fullmatch(match.group("value"))]
        document["_ssn_values"].update(document["text"][start:end].casefold()
                                       for start, end in document["_labelled_ssns"])
    names, raw_edges = _names_and_headers(documents)
    email_owners = _email_owners(documents)
    role_edges = _structured_role_edges(documents)
    graph_facts = _entity_graph_facts(documents, raw_edges)
    for fact in graph_facts:
        if fact["source_kind"] == "person":
            names.add(fact["source"])
        if fact["target_kind"] == "person":
            names.add(fact["target"])
    for document in documents:
        for start, end, kind in document["_fields"]:
            value = document["text"][start:end]
            if kind == "PERSON_NAME" and SAFE_NAME.fullmatch(value):
                names.add(value)
    automatic_name_keys = {name.casefold() for name in names}
    names.update(phrases)
    names_by_key = {name.casefold(): name for name in sorted(names, key=lambda value: (value.casefold(), value))}
    keys = [("PERSON_NAME", value) for value in names_by_key]
    source_by_key: dict[tuple[str, str], str] = {}

    def remember(kind: str, source: str) -> None:
        key = (kind, source.casefold())
        keys.append(key)
        source_by_key.setdefault(key, source)

    for doc in documents:
        for span in detect_text(doc["text"]):
            remember(span.entity_type, doc["text"][span.start:span.end])
        for start, end, kind in doc["_fields"]:
            remember(kind, doc["text"][start:end])
        for start, end in doc["_labelled_ssns"]:
            remember("GOVERNMENT_ID", doc["text"][start:end])
    for item in manual_findings:
        remember(item["kind"], item["value"])
    keys = sorted(set(keys))
    id_by_key = {key: f"E{index + 1}" for index, key in enumerate(keys)}
    if set(overrides) - set(id_by_key.values()):
        raise PayloadError("An alias override refers to an unknown entity.")
    if set(exclusions) - set(id_by_key.values()) or any(
            kind not in SUPPRESSIBLE_KINDS for (kind, _), entity_id in id_by_key.items() if entity_id in exclusions):
        raise PayloadError("Only supported noncritical findings can be excluded after reviewer confirmation.")
    if set(overrides).intersection(exclusions):
        raise PayloadError("An excluded entity cannot also have an alias override.")
    reserved_aliases = {value.casefold() for value in overrides.values()}
    if len(reserved_aliases) != len(overrides) or reserved_aliases.intersection(names_by_key):
        raise PayloadError("Person aliases must be unique and must not be another source name.")
    used_aliases: set[str] = set(names_by_key)
    protected_tokens = {part.casefold() for name in names_by_key.values()
                        for part in re.findall(r"[A-Za-z]+", name)}
    default_aliases: dict[str, str] = {}
    for kind, normalized in keys:
        if kind != "PERSON_NAME":
            continue
        try:
            default_aliases[normalized] = _choose_alias(names_by_key[normalized], used_aliases, protected_tokens)
        except PayloadError:
            if id_by_key[(kind, normalized)] not in overrides:
                raise
    for (kind, normalized), entity_id in id_by_key.items():
        if kind != "PERSON_NAME" or entity_id not in overrides:
            continue
        alias = overrides[entity_id]
        if not SAFE_ALIAS.fullmatch(alias) or len(alias) != len(names_by_key[normalized]) or alias.casefold() == normalized:
            raise PayloadError("Person aliases must be distinct, safe, and the same character length as the source name.")
        if any(alias.casefold() == other.casefold() for other_name, other in default_aliases.items()
               if other_name != normalized and id_by_key[("PERSON_NAME", other_name)] not in overrides):
            raise PayloadError("An alias conflicts with another person's proposed replacement.")
    name_aliases = {normalized: (overrides[entity_id] if entity_id in overrides else default_aliases[normalized])
                    for normalized in names_by_key
                    for entity_id in (id_by_key[("PERSON_NAME", normalized)],)}
    email_aliases = _email_aliases(keys, names_by_key, name_aliases, email_owners, exclusions, id_by_key)
    source_values = {source.casefold() for source in names_by_key.values()} | {source.casefold() for source in source_by_key.values()}
    used_typed_aliases: set[str] = set()
    typed_ordinals = {"PAN": 0, "GOVERNMENT_ID": 0, "PHONE": 0}
    entities: list[dict[str, Any]] = []
    for kind, normalized in keys:
        entity_id = id_by_key[(kind, normalized)]
        if kind == "PERSON_NAME":
            display = names_by_key[normalized]
        elif kind in {"CREDENTIAL", "PAYMENT_SECRET"}:
            display = "[sensitive value]"
        else:
            raw_display = source_by_key[(kind, normalized)]
            display = raw_display[:100] + ("…" if len(raw_display) > 100 else "")
        if kind == "PERSON_NAME":
            alias = name_aliases[normalized]
            strategy = "NAME_LENGTH_MATCH"
        elif kind == "EMAIL":
            if entity_id in overrides:
                raise PayloadError("Only person-name aliases can be changed in this demo.")
            alias = email_aliases[normalized]
            strategy = "EMAIL_TEST_ADDRESS"
        else:
            if entity_id in overrides:
                raise PayloadError("Only person-name aliases can be changed in this demo.")
            alias, strategy = f"[{kind}_{entity_id}]", "OPAQUE_REDACTION"
            eligible = kind in typed_ordinals and (kind != "GOVERNMENT_ID" or any(
                normalized in doc["_ssn_values"] for doc in documents))
            if eligible:
                limit = 100 if kind == "PHONE" else 9999
                while typed_ordinals[kind] < limit:
                    typed_ordinals[kind] += 1
                    proposal = typed_alias(kind, source_by_key[(kind, normalized)], typed_ordinals[kind])
                    if proposal is None:
                        break
                    if proposal[0].casefold() not in source_values and proposal[0].casefold() not in used_typed_aliases:
                        alias, strategy = proposal
                        used_typed_aliases.add(alias.casefold())
                        break
        entities.append({"id": entity_id, "kind": kind, "source": display, "alias": alias,
                         "strategy": strategy, "mentions": 0, "excluded": entity_id in exclusions})
    entities_by_id = {entity["id"]: entity for entity in entities}

    total_mentions = transformed_mentions = 0
    for doc in documents:
        text = doc["text"]
        spans: list[tuple[int, int, str, int, str]] = []
        for start, end, kind in doc["_fields"]:
            entity_id = id_by_key[(kind, text[start:end].casefold())]
            spans.append((start, end, entity_id, 3, "AUTOMATIC"))
        for start, end in doc["_labelled_ssns"]:
            entity_id = id_by_key[("GOVERNMENT_ID", text[start:end].casefold())]
            spans.append((start, end, entity_id, 3, "AUTOMATIC"))
        for span in detect_text(text):
            entity_id = id_by_key[(span.entity_type, text[span.start:span.end].casefold())]
            spans.append((span.start, span.end, entity_id, 2, "AUTOMATIC"))
        for normalized in names_by_key:
            for match in re.finditer(r"(?<!\w)" + re.escape(normalized) + r"(?!\w)", text, re.I):
                spans.append((match.start(), match.end(), id_by_key[("PERSON_NAME", normalized)], 1,
                              "AUTOMATIC" if normalized in automatic_name_keys else "MANUAL"))
        for item in manual_findings:
            entity_id = id_by_key[(item["kind"], item["value"].casefold())]
            for match in _exact_phrase_matches(text, item["value"]):
                spans.append((match.start(), match.end(), entity_id, 1, "MANUAL"))
        spans.sort(key=lambda item: (-item[3], item[0], -(item[1] - item[0])))
        selected: list[tuple[int, int, str, str]] = []
        for start, end, entity_id, _, origin in spans:
            if not any(start < right and end > left for left, right, _, _ in selected):
                selected.append((start, end, entity_id, origin))
        selected.sort()
        candidate_parts: list[str] = []
        offset = 0
        matches = []
        for start, end, entity_id, origin in selected:
            entity = entities_by_id[entity_id]
            applied = not entity["excluded"]
            candidate_parts.extend((text[offset:start], entity["alias"] if applied else text[start:end]))
            matches.append({"start": start, "end": end, "source": text[start:end], "entity_id": entity_id,
                            "kind": entity["kind"], "replacement": entity["alias"], "applied": applied,
                            "origin": origin})
            entity["mentions"] += 1
            total_mentions += 1
            transformed_mentions += applied
            offset = end
        candidate_parts.append(text[offset:])
        candidate = "".join(candidate_parts)
        structure = "not_applicable"
        if doc["kind"] in {"csv", "json", "jsonl"}:
            try:
                _validate_structured(doc["kind"], candidate)
                structure = "pass"
            except PayloadError:
                structure = "fail"
        doc.update(candidate_text=candidate, matches=matches, structure_check=structure)
        if "_media_pages" in doc:
            doc["media_preview"] = render_candidate(doc.pop("_media_pages"), matches, doc["kind"])
        doc.pop("_fields")
        doc.pop("_ssn_values")
        doc.pop("_labelled_ssns")

    person_id = {value: id_by_key[("PERSON_NAME", value)] for value in names_by_key}
    graph_person_labels = {value: ("Source retained" if person_id[value] in exclusions else name_aliases[value])
                           for value in person_id}
    entity_graph = _public_entity_graph(graph_facts, person_id, graph_person_labels)
    relationships = []
    seen_edges: set[tuple[str, str, str, str]] = set()
    for sender, recipient, document_id in raw_edges:
        source_id, target_id = person_id.get(sender.casefold()), person_id.get(recipient.casefold())
        if not source_id or not target_id:
            continue
        edge = (source_id, target_id, document_id, "EMAILED")
        if edge not in seen_edges:
            seen_edges.add(edge)
            relationships.append({"source_id": source_id, "target_id": target_id, "type": "EMAILED",
                                  "document_id": document_id, "basis": "explicit From/To or Cc header"})
    for owner, client, document_id, kind in role_edges:
        source_id, target_id = person_id.get(owner.casefold()), person_id.get(client.casefold())
        if not source_id or not target_id:
            continue
        edge = (source_id, target_id, document_id, "ACCOUNT_OWNER_OF")
        if edge not in seen_edges:
            seen_edges.add(edge)
            relationships.append({"source_id": source_id, "target_id": target_id,
                                  "type": "ACCOUNT_OWNER_OF", "document_id": document_id,
                                  "basis": f"same {kind.upper()} record account_owner/client_name"})
    residual = sum(len(detect_text(doc["candidate_text"])) for doc in documents)
    source_value_residuals = sum(
        any(_exact_phrase_matches(doc["candidate_text"], names_by_key[normalized] if kind == "PERSON_NAME"
                                  else source_by_key[(kind, normalized)]) for doc in documents)
        for kind, normalized in keys
    )
    media_documents = [doc for doc in documents if "media_preview" in doc]
    visual_residuals = sum(doc["media_preview"]["self_ocr_residual_sources"] for doc in media_documents)
    visual_fallbacks = sum(doc["media_preview"]["fallback_lines"] for doc in media_documents)
    if any(entity["excluded"] and not entity["mentions"] for entity in entities):
        raise PayloadError("A reviewer exclusion must refer to a detected mention.")
    if any(not entities_by_id[id_by_key[(item["kind"], item["value"].casefold())]]["mentions"]
           for item in manual_findings):
        raise PayloadError("A manual finding cannot override an existing detected span.")
    structure_failures = sum(doc["structure_check"] == "fail" for doc in documents)
    annotation_score = _score_reference_annotations(payload.get("reference_annotations"), documents)
    return {
        "posture": "SYNTHETIC_DEMO_ONLY", "release_authorized": False, "export_available": False,
        "documents": documents, "entities": entities, "relationships": relationships,
        "entity_graph": entity_graph,
        "summary": {"files": len(documents), "detected_mentions": total_mentions,
                    "transformed_mentions": transformed_mentions, "suppressed_mentions": total_mentions - transformed_mentions,
                    "linked_entities": sum(e["mentions"] > 0 for e in entities),
                    "explicit_relationships": len(relationships)},
        "verification": {
            "status": "REVIEW_REQUIRED", "known_rule_residual_matches": residual,
            "source_value_residuals": source_value_residuals,
            "structure_failures": structure_failures, "annotation_score": annotation_score,
            "checks": [
                {"name": "Selected-span application", "status": "PASS" if total_mentions and transformed_mentions == total_mentions else "REVIEW",
                 "detail": f"{transformed_mentions} of {total_mentions} selected matches received a proposed replacement. Reviewer exclusions retain source values and require further review."},
                {"name": "Reviewer exclusions", "status": "REVIEW" if exclusions else "NOT_APPLICABLE",
                 "detail": f"{total_mentions - transformed_mentions} matches were retained after explicit false-positive review. No exclusion authorizes release."},
                {"name": "Structured syntax", "status": "FAIL" if structure_failures else "PASS",
                 "detail": "CSV/JSON/JSONL candidates were reparsed where applicable."},
                {"name": "Source-value persistence", "status": "REVIEW" if source_value_residuals else "PASS",
                 "detail": f"{source_value_residuals} detected source values still occur in candidate text. This exact-value check cannot find source values that detection missed or independently assess pixels."},
                {"name": "Residual known-rule scan", "status": "REVIEW" if residual or exclusions else "PASS",
                 "detail": f"{residual} bounded-rule matches occur in candidate text, including expected email- or PAN-shaped pseudonyms. This pattern count is not the number of retained source values; zero does not prove anonymity."},
                {"name": "Raster media and OCR review", "status": "REVIEW" if media_documents else "NOT_TESTED",
                 "detail": f"{len(media_documents)} media files were rasterized and OCR-reviewed; {visual_residuals} source values remain under the same OCR engine and {visual_fallbacks} lines needed solid-redaction fallback. This is not independent visual validation or release approval."
                 if media_documents else "No PDF/image was processed in this batch."},
                {"name": "Reference-label agreement", "status": "REVIEW" if annotation_score else "NOT_MEASURED",
                 "detail": "Exact-span counts compare the reviewed candidate with supplied synthetic labels; they are not an independent model benchmark."
                 if annotation_score else "No complete reference labels were supplied for this batch."},
            ],
        },
        "limitations": [
            "This is a bounded, synthetic-only text review. It does not establish complete PII detection or anonymity.",
            "Person names are found from structured name fields, email headers, and manually added exact names; names in arbitrary prose can be missed.",
            "Manually added sensitive phrases are exact bounded corrections, not automatic recognition of similar unseen values.",
            "Structured field recognition is bounded to supported JSON key/value syntax and one-line CSV cells; unsupported forms are rejected rather than silently passed through.",
            "Exact-name linking can merge different people who share a name; ambiguous identities need human resolution.",
            "Email-shaped pseudonyms use reserved .test domains and preserve only explicitly evidenced person/email and source-domain equivalence within this batch; they are not deliverable contact addresses.",
            "PAN and explicitly identified US SSN examples are deliberately invalid; explicit +1 NANP phones use a reserved fictional range. Other identifiers remain opaque. Syntax preservation is not validity or release qualification.",
            "PDF candidates are rebuilt as image-only PDFs in memory. A digest-checked local demo copy may be downloaded; this is not an authorized release or delivery.",
            "Image and scanned-PDF OCR may miss or misread content. The same-engine raster recheck is not independent validation, and source content outside recognized OCR lines may remain visible.",
            "Entity-graph edges require explicit mail headers, labelled signature blocks, or named field pairs in one parsed record; they do not infer social, employment, client, or organizational ties from proximity, prose, or email domains.",
            "Graph evidence identifies only the source document and bounded extraction rule/field. Graph organization and project labels are batch-local pseudonyms, and the graph is capped for review rather than treated as a complete organization model.",
            "Pseudonyms and retained relationships may remain linkable. No release, sale, or production export is authorized; demo downloads are unverified synthetic review copies only.",
            "Reference-label agreement, when present, depends on the reviewer's completeness assertion and does not establish generalization or anonymity.",
        ],
    }
