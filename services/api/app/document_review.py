"""Source-aware document review, with explicitly unqualified text candidates.

This path accepts public/rights-cleared documents without the synthetic demo's
attestation. It cannot publish, approve, or download a cleaned original file.
"""
from __future__ import annotations

import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
from threading import BoundedSemaphore
import unicodedata

from app.document_entities import FULL_NAME, LETTER, inline_field_boundaries, is_court_caption, is_unicode_name, name_proposal_end
from app.document_extract import DocumentError, MAX_FILE_BYTES, extract_office, extract_pdf
from app.independent_residual import scan_residual_candidate
from app.processing import detect_text

MAX_REQUEST_BYTES = 11_000_000
MAX_MATCHES = 20_000
_SLOT = BoundedSemaphore(1)
_NAME_WORD = re.compile(rf"(?:{LETTER})(?!\w)")
_POSSIBLE_NAME = re.compile(rf"(?<![\w]){FULL_NAME}(?!\w)")
_AUTHOR = re.compile(r"(?im)^(?:author|creator|lastmodifiedby|editor):[ \t]*(.+)$")
_FORM_CONTEXT = re.compile(r"(?i)\b(?:PrimarySSN|SpouseSSN|DependentSSN|ssn|social\s+security|taxpayer\s+identification)\b")
_FORM_ID = re.compile(r"(?<!\w)[0-9]{3}[ \t|:'’.-]{1,4}[0-9]{2}[ \t|:'’.-]{1,4}[0-9]{4}(?![\w-])")
_URL = re.compile(r"(?i)\b(?:https?://|www\.)[^\s<>\"']+")
_REPEAT_KINDS = frozenset({"PERSON_NAME", "GOVERNMENT_ID", "PAN", "AADHAAR", "EMAIL", "PHONE", "CARD",
                           "FINANCIAL_ACCOUNT", "DEVICE_ID", "USER_ID", "VEHICLE_ID", "IP_ADDRESS", "IDENTIFYING_LINK"})
_WEAK_NAME_BASES = frozenset({"capitalization-review", "capitalization-repeat-review"})
# These common document/title words are not identity evidence on their own.
# Capitalization proposals are always labelled for review, never qualified NER.
_TITLE_WORDS = frozenset("The This That These Those Court Supreme United States Department Ministry Government Report Table Figure Page Section Chapter Basic Rights Public Meeting Minutes Document Annual Smart Grid Forum Work Stream Form Schedule Tax Return Total Income Address Social Security Number Date Name Telephone Email University College School Conference Presentation See Note Notes For Of And No Yes Not None".casefold().split())


def _key(value: str) -> str:
    return " ".join(value.casefold().split())


def _occurrences(text: str, value: str):
    # Preserve offsets in the actual source surface; flexible whitespace handles
    # the same identifier split across transcript lines or OCR word boundaries.
    pattern = r"(?<!\w)" + r"\s+".join(re.escape(word) for word in value.split()) + r"(?!\w)"
    for match in re.finditer(pattern, text, re.IGNORECASE):
        # Python's \w excludes combining marks. Do not remove a prefix of a
        # differently accented name or leave a dangling script vowel mark.
        if match.start() and unicodedata.category(text[match.start() - 1])[0] == "M":
            continue
        if match.end() < len(text) and unicodedata.category(text[match.end()])[0] == "M":
            continue
        yield match


def review_document(name: str, raw: bytes, *, ocr: bool = True, reviewed_values: list[dict] | None = None) -> dict:
    if not isinstance(name, str) or not 1 <= len(name) <= 200 or len(raw) > MAX_FILE_BYTES or not raw:
        raise DocumentError("FILE_LIMIT")
    extension = name.rsplit(".", 1)[-1].lower()
    if extension not in {"pdf", "docx", "pptx", "xlsx"}:
        raise DocumentError("UNSUPPORTED_FORMAT")
    reviewed_values = reviewed_values or []
    if len(reviewed_values) > 100 or any(set(item) != {"value", "kind"} or
            item["kind"] not in {"PERSON_NAME", "ADDRESS", "GOVERNMENT_ID", "OTHER_SENSITIVE"} or
            not isinstance(item["value"], str) or not 2 <= len(item["value"]) <= 150 or not item["value"].strip()
            for item in reviewed_values):
        raise DocumentError("INVALID_REVIEW_VALUES")
    source = extract_pdf(raw, ocr=ocr) if extension == "pdf" else extract_office(raw, extension)
    # A casefold identity may have several observed spellings (ß / ss), while
    # re.IGNORECASE does not equate those spellings. Keep every spelling for
    # repetition and residual checks; canonical replacement IDs remain shared.
    seeds: dict[tuple[str, str], set[str]] = {}
    possible_names: dict[str, set[str]] = {}
    per_surface = []
    for surface in source.surfaces:
        text = surface["text"]
        fields = inline_field_boundaries(text)
        spans = [{"start": span.start, "end": span.end, "kind": span.entity_type, "basis": "contextual-rule"}
                 for span in detect_text(text)]
        if surface["kind"] == "metadata":
            for match in _AUTHOR.finditer(text):
                if _POSSIBLE_NAME.fullmatch(match.group(1).strip()) or is_unicode_name(match.group(1).strip()):
                    value = match.group(1).strip()
                    seeds.setdefault(("PERSON_NAME", _key(value)), set()).add(value)
        # Document-only proposals catch rosters and name cells. These weaker
        # candidates stay visibly distinct from explicit-context findings.
        if surface["kind"] in {"pdf-native", "pdf-ocr", "docx-part", "pptx-slide", "pptx-notes", "xlsx-sheet"} or surface["id"].endswith("sharedStrings.xml"):
            # Tabs separate spreadsheet cells, never tokens in one name.
            for line in re.finditer(r"[^\t\r\n]+", text):
                if is_court_caption(line.group()):
                    continue
                for match in _POSSIBLE_NAME.finditer(line.group()):
                    tokens = list(_NAME_WORD.finditer(match.group()))
                    runs, run = [], []
                    for token in tokens:
                        if token.group().casefold() in _TITLE_WORDS:
                            if run:
                                runs.append(run)
                            run = []
                        else:
                            run.append(token)
                    if run:
                        runs.append(run)
                    for run in runs:
                        if len(run) >= 2:
                            start = line.start() + match.start() + run[0].start()
                            end = line.start() + match.start() + run[-1].end()
                            end = name_proposal_end(start, end, fields)
                            if end <= start or (start and unicodedata.category(text[start - 1])[0] == "M"):
                                continue
                            if end < len(text) and unicodedata.category(text[end])[0] == "M":
                                continue
                            spans.append({"start": start, "end": end, "kind": "PERSON_NAME", "basis": "capitalization-review"})
        if _FORM_CONTEXT.search(text):
            for match in _FORM_ID.finditer(text):
                spans.append({"start": match.start(), "end": match.end(), "kind": "GOVERNMENT_ID", "basis": "form-context-review"})
        for match in _URL.finditer(text):
            spans.append({"start": match.start(), "end": match.end(), "kind": "IDENTIFYING_LINK", "basis": "link-review"})
        # Keep weaker name proposals separate from contextually evidenced IDs.
        # Repeated weak proposals retain that basis instead of becoming known
        # identities merely because the same text occurs on another page.
        for span in spans:
            value = text[span["start"]:span["end"]]
            if span["basis"] in _WEAK_NAME_BASES:
                if len(value) <= 150:
                    possible_names.setdefault(_key(value), set()).add(value)
            elif span["kind"] in _REPEAT_KINDS:
                seeds.setdefault((span["kind"], _key(value)), set()).add(value)
        per_surface.append(spans)
    for item in reviewed_values:
        if not any(next(_occurrences(surface["text"], item["value"]), None) for surface in source.surfaces):
            raise DocumentError("REVIEW_VALUE_NOT_FOUND")
        seeds.setdefault((item["kind"], _key(item["value"])), set()).add(item["value"])
    # Only stronger evidence with the same matching behavior can supersede a
    # weak spelling; casefold equality alone must not silently discard it.
    for key, values in list(possible_names.items()):
        confirmed = seeds.get(("PERSON_NAME", key), set()) | {
            item["value"] for item in reviewed_values if _key(item["value"]) == key}
        remaining = {value for value in values if not any(next(_occurrences(value, known), None) for known in confirmed)}
        if remaining:
            possible_names[key] = remaining
        else:
            del possible_names[key]
    if sum(map(len, seeds.values())) + sum(map(len, possible_names.values())) > 1_000:
        raise DocumentError("ENTITY_LIMIT")
    if possible_names:
        source.gaps.add("CAPITALIZATION_REPEAT_REVIEW_REQUIRED")

    entities, counts, total_matches, residual_units = {}, Counter(), 0, 0
    for surface, spans in zip(source.surfaces, per_surface):
        text = surface["text"]
        for (kind, _), values in seeds.items():
            for value in sorted(values):
                for match in _occurrences(text, value):
                    spans.append({"start": match.start(), "end": match.end(), "kind": kind, "basis": "document-repeat"})
        for value in (value for values in possible_names.values() for value in sorted(values)):
            for match in _occurrences(text, value):
                spans.append({"start": match.start(), "end": match.end(), "kind": "PERSON_NAME", "basis": "capitalization-repeat-review"})
        if surface["kind"] in {"metadata", "signature-metadata", "custom-xml", "package-relationship"} and text:
            # Property blocks can contain paths, dates, usernames and arbitrary
            # custom values. Drop all from the text candidate; do not pretend a
            # detector has classified every property or edited original bytes.
            spans = [{"start": 0, "end": len(text), "kind": "METADATA", "basis": "property-or-auxiliary-removal"}]
        merged = []
        priority = {"GOVERNMENT_ID": 5, "CREDENTIAL": 6, "CARD": 5, "EMAIL": 4, "PHONE": 4, "PERSON_NAME": 1}
        for span in sorted(spans, key=lambda item: (item["start"], item["end"])):
            if merged and span["start"] < merged[-1]["end"]:
                prior = merged.pop()
                strongest = max((prior, span), key=lambda item: (priority.get(item["kind"], 3), item["basis"] not in _WEAK_NAME_BASES))
                merged.append({**strongest, "start": prior["start"], "end": max(prior["end"], span["end"])})
            else:
                merged.append(span)
        total_matches += len(merged)
        if total_matches > MAX_MATCHES:
            raise DocumentError("MATCH_LIMIT")
        parts, position = [], 0
        for span in merged:
            value = text[span["start"]:span["end"]]
            key = (span["kind"], _key(value))
            if key not in entities:
                entities[key] = f"{span['kind']}_{len(entities) + 1:04d}"
            span["replacement"] = f"[{entities[key]}]"
            parts.extend((text[position:span["start"]], span["replacement"]))
            position = span["end"]
            counts[span["kind"]] += 1
        parts.append(text[position:])
        candidate = "".join(parts)
        residual = scan_residual_candidate(candidate)
        residual_units += any(residual.residual_counts.values())
        # This is a source-aware equality check, explicitly separate from the
        # independent candidate scanner and not a measure of unknown entities.
        retained = sum(any(_occurrences(candidate, value)) for values in seeds.values() for value in values)
        surface.update({"matches": merged, "candidate": candidate,
                        "residual_families": dict(residual.residual_counts), "known_values_remaining": retained})
    source.gaps.update({"NAME_ADDRESS_SEMANTIC_COVERAGE_UNQUALIFIED", "TEXT_CANDIDATE_ONLY_ORIGINAL_UNCHANGED"})
    return {"schema": "document-review-v1", "posture": "REVIEW_REQUIRED", "release_eligible": False,
            "name": name, "sha256": hashlib.sha256(raw).hexdigest(), "format": extension,
            "inventory": source.inventory, "surfaces": source.surfaces, "gaps": sorted(source.gaps),
            "summary": {"surfaces": len(source.surfaces), "nonempty_surfaces": sum(bool(s["text"].strip()) for s in source.surfaces),
                        "pages": sum(item["kind"] == "pdf-page" for item in source.inventory),
                        "findings": dict(sorted(counts.items())), "matches": total_matches,
                        "residual_units": residual_units, "known_values_remaining": sum(s["known_values_remaining"] for s in source.surfaces)},
            "coverage": {"text": "PARSED_WITH_GAPS", "names_addresses": "UNQUALIFIED",
                         "pixels": "UNMEASURED", "original_format_output": "NOT_PRODUCED"},
            "limitations": ["Text candidates retain undetected identifiers. Review source text, findings and coverage gaps.",
                            "Capitalization, repeated capitalization, and form-context proposals may be false positives; OCR can corrupt or omit values.",
                            "Explicit name fields use bounded Unicode letter rules, not general multilingual name recognition.",
                            "Repeated known values are checked separately; unknown names, handwriting and image content can remain.",
                            "No original-format file is changed or authorized for release."]}


def run_document_review(payload: dict) -> dict:
    """One disposable parser process with CPU, memory and wall-clock limits.

    The child gets a minimal environment, no app credentials, no source paths,
    and a disposable working directory. No shell, document code or links run.
    """
    if not _SLOT.acquire(blocking=False):
        raise DocumentError("REVIEW_BUSY")
    try:
        with tempfile.TemporaryDirectory(prefix="anonfile-document-review-") as directory:
            environment = {key: os.environ[key] for key in ("PATH", "SYSTEMROOT", "LANG") if key in os.environ}
            environment.update({"PYTHONPATH": str(Path(__file__).resolve().parent.parent),
                                "OMP_THREAD_LIMIT": "1", "OPENBLAS_NUM_THREADS": "1", "PYTHONDONTWRITEBYTECODE": "1"})
            process = subprocess.Popen([sys.executable, "-m", "app.document_review_worker"],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                       cwd=directory, env=environment, start_new_session=True)
            try:
                output, _ = process.communicate(json.dumps(payload).encode(), timeout=180)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise DocumentError("REVIEW_TIMEOUT") from None
            if process.returncode or len(output) > 32_000_000:
                raise DocumentError("PARSER_RESOURCE_LIMIT")
            try:
                result = json.loads(output)
            except (ValueError, UnicodeError):
                raise DocumentError("PARSER_FAILED") from None
            if "error" in result:
                raise DocumentError(result["error"])
            return result
    finally:
        _SLOT.release()


def decode_review_payload(payload: dict) -> dict:
    if payload.get("review_only") is not True:
        raise DocumentError("REVIEW_ACKNOWLEDGMENT_REQUIRED")
    encoded = payload.get("content_base64", "")
    if not isinstance(encoded, str) or len(encoded) > (MAX_FILE_BYTES + 2) // 3 * 4:
        raise DocumentError("FILE_LIMIT")
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (ValueError, TypeError):
        raise DocumentError("INVALID_BASE64") from None
    return review_document(payload.get("name", ""), raw, ocr=payload.get("ocr", True),
                           reviewed_values=payload.get("reviewed_values", []))
