"""Ephemeral, explicitly synthetic batch review; never a release pipeline.

Text and raster candidates are review-only. PDF/image candidates are rebuilt
from pixels, not original document objects. OCR can miss content; no input or
candidate is persisted or qualified for release by this module.
"""
from __future__ import annotations

import base64
import binascii
import csv
import hashlib
from io import StringIO
import json
import re
from collections import Counter
from pathlib import PurePath
from typing import Any

from app.contracts import PayloadError
from app.evaluation import EvaluationError, evaluate, parse_gold, parse_predictions
from app.media_preview import extract_media, render_candidate
from app.processing import _field_type, detect_text

MAX_FILES = 3
MAX_FILE_BYTES = 100_000
MAX_TOTAL_BYTES = 300_000
MAX_BATCH_MEDIA_PIXELS = 3_000_000
SUPPORTED = {".txt": "text", ".csv": "csv", ".json": "json", ".jsonl": "jsonl", ".pdf": "pdf",
             ".png": "image", ".jpg": "image", ".jpeg": "image"}
NAME_FIELDS = {"name", "full_name", "first_name", "last_name", "customer_name", "passenger_name", "client_name", "account_owner"}
HEADER = re.compile(r"(?im)^(From|To|Cc):\s*([^<>\r\n]{2,80}?)\s*<([^<>\s]+@[^<>\s]+)>\s*$")
JSON_NAME = re.compile(r'"(?:name|full_name|first_name|last_name|customer_name|passenger_name|client_name|account_owner)"\s*:\s*"([^"\\]{2,80})"', re.I)
JSON_FIELD = re.compile(r'"(?P<key>(?:[^"\\]|\\.){1,80})"\s*:\s*(?P<value>"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?|true|false|null)', re.I)
TEXT_NAME = re.compile(r"(?im)^\s*(?:name|client|customer|passenger)\s*:\s*([A-Z][A-Za-z .'-]{1,78})\s*$")
SAFE_NAME = re.compile(r"^[A-Za-z][A-Za-z .'-]{1,79}$")
SAFE_ALIAS = re.compile(r"^[A-Za-z][A-Za-z '-]{1,79}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9_-]{1,48}$")
NAME_POOL = ("Gita", "Maya", "Mira", "Nina", "Arun", "Noah", "Asha", "Anika", "Kiran", "Leela", "Ava", "Ira", "Miriam", "Rohan", "Nora", "Elena")
MAX_REFERENCE_LABELS_PER_FILE = 200
REVIEW_EXCLUSION_REASON = "FALSE_POSITIVE_CONFIRMED"
SUPPRESSIBLE_KINDS = frozenset({"PERSON_NAME", "EMAIL", "PHONE", "IP_ADDRESS"})
MANUAL_FINDING_KINDS = frozenset({"OTHER_SENSITIVE", "BUSINESS_CONFIDENTIAL", "QUASI_IDENTIFIER", "GOVERNMENT_ID", "DATE_OF_BIRTH"})
SAFE_MANUAL_VALUE = re.compile(r"^[^\x00-\x1f\x7f]{2,80}$")
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
    if not isinstance(encoded, str) or len(encoded) > 140_000:
        raise PayloadError("Demo file exceeds the size limit.")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise PayloadError("Invalid demo file encoding.") from None
    if not raw or len(raw) > MAX_FILE_BYTES:
        raise PayloadError("Each demo file must be between 1 byte and 100 KB.")
    kind = SUPPORTED[extension]
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
            result.append((start, end, field[0]))
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
                        result.append((start, end, field[0]))
            offset += len(raw_line)
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


def _structured_role_edges(documents: list[dict[str, Any]]) -> list[tuple[str, str, str, str]]:
    """Read only direct owner/client fields in one parsed record, never proximity."""
    edges: list[tuple[str, str, str, str]] = []
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
            if not isinstance(record, dict):
                continue
            owner, client = record.get("account_owner"), record.get("client_name")
            if (isinstance(owner, str) and isinstance(client, str)
                    and SAFE_NAME.fullmatch(owner.strip()) and SAFE_NAME.fullmatch(client.strip())
                    and owner.strip().casefold() != client.strip().casefold()):
                edges.append((owner.strip(), client.strip(), document["id"], kind))
    return edges


def _choose_alias(name: str, used: set[str]) -> str:
    for candidate in NAME_POOL:
        if len(candidate) == len(name) and candidate.casefold() != name.casefold() and candidate.casefold() not in used:
            used.add(candidate.casefold())
            return candidate
    # A deterministic length-preserving fallback, explicitly a pseudonym rather
    # than a realistic name. Never silently overflow a short PDF text run.
    seed = "A" + "x" * (len(name) - 1)
    candidate = seed
    counter = 0
    while candidate.casefold() in used or candidate.casefold() == name.casefold():
        counter += 1
        suffix = str(counter)
        candidate = seed[:max(1, len(name) - len(suffix))] + suffix
    used.add(candidate.casefold())
    return candidate


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
        raise PayloadError("Duplicate file identities or batch size over 300 KB.")
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
    names, raw_edges = _names_and_headers(documents)
    role_edges = _structured_role_edges(documents)
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
    default_aliases = {normalized: _choose_alias(names_by_key[normalized], used_aliases)
                       for kind, normalized in keys if kind == "PERSON_NAME"}
    for (kind, normalized), entity_id in id_by_key.items():
        if kind != "PERSON_NAME" or entity_id not in overrides:
            continue
        alias = overrides[entity_id]
        if not SAFE_ALIAS.fullmatch(alias) or len(alias) != len(names_by_key[normalized]) or alias.casefold() == normalized:
            raise PayloadError("Person aliases must be distinct, safe, and the same character length as the source name.")
        if any(alias.casefold() == other.casefold() for other_name, other in default_aliases.items()
               if other_name != normalized and id_by_key[("PERSON_NAME", other_name)] not in overrides):
            raise PayloadError("An alias conflicts with another person's proposed replacement.")
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
            alias = overrides.get(entity_id) or default_aliases[normalized]
        else:
            if entity_id in overrides:
                raise PayloadError("Only person-name aliases can be changed in this demo.")
            alias = f"[{kind}_{entity_id}]"
        entities.append({"id": entity_id, "kind": kind, "source": display, "alias": alias,
                         "mentions": 0, "excluded": entity_id in exclusions})
    entities_by_id = {entity["id"]: entity for entity in entities}

    total_mentions = transformed_mentions = 0
    for doc in documents:
        text = doc["text"]
        spans: list[tuple[int, int, str, int, str]] = []
        for start, end, kind in doc["_fields"]:
            entity_id = id_by_key[(kind, text[start:end].casefold())]
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

    person_id = {value: id_by_key[("PERSON_NAME", value)] for value in names_by_key}
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
        "summary": {"files": len(documents), "detected_mentions": total_mentions,
                    "transformed_mentions": transformed_mentions, "suppressed_mentions": total_mentions - transformed_mentions,
                    "linked_entities": sum(e["mentions"] > 0 for e in entities),
                    "explicit_relationships": len(relationships)},
        "verification": {
            "status": "REVIEW_REQUIRED", "known_rule_residual_matches": residual,
            "structure_failures": structure_failures, "annotation_score": annotation_score,
            "checks": [
                {"name": "Selected-span application", "status": "PASS" if total_mentions and transformed_mentions == total_mentions else "REVIEW",
                 "detail": f"{transformed_mentions} of {total_mentions} selected matches received a proposed replacement. Reviewer exclusions retain source values and require further review."},
                {"name": "Reviewer exclusions", "status": "REVIEW" if exclusions else "NOT_APPLICABLE",
                 "detail": f"{total_mentions - transformed_mentions} matches were retained after explicit false-positive review. No exclusion authorizes release."},
                {"name": "Structured syntax", "status": "FAIL" if structure_failures else "PASS",
                 "detail": "CSV/JSON/JSONL candidates were reparsed where applicable."},
                {"name": "Residual known-rule scan", "status": "REVIEW" if residual or exclusions else "PASS",
                 "detail": f"{residual} bounded-rule matches remain in candidate text. Reviewer-excluded names may not be covered by this scan; zero matches do not prove anonymity."},
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
            "PDF candidates are rebuilt as image-only PDFs in memory, but only raster page previews and a digest are returned; no PDF download or delivery is authorized.",
            "Image and scanned-PDF OCR may miss or misread content. The same-engine raster recheck is not independent validation, and source content outside recognized OCR lines may remain visible.",
            "Relationship edges require explicit mail headers or account_owner/client_name in the same parsed record; they do not infer social or organizational ties.",
            "Pseudonyms and retained relationships may remain linkable. No release, sale, or export is authorized.",
            "Reference-label agreement, when present, depends on the reviewer's completeness assertion and does not establish generalization or anonymity.",
        ],
    }
