"""Strict bounded in-memory adapters for synthetic development sources.

No file paths, URLs, dialect guessing, value coercion or partial batches. Parsing
does not detect PII, establish rights, sanitize spreadsheet formulas or authorize
release. Original source bytes must be escrowed separately by the calling API.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
import hashlib
import io
import json
import math
from typing import Any

MAX_BYTES = 2_000_000
MAX_RECORDS = 10_000
MAX_DEPTH = 32
MAX_NODES = 100_000
MAX_COLUMNS = 256
MAX_FIELD_CHARS = 100_000
PARSER_ID = "strict-stdlib-v1"
FORMATS = frozenset({"text", "json", "jsonl", "csv"})


class IngestionError(ValueError):
    """Only fixed non-source-bearing messages may leave this parser."""


@dataclass(frozen=True)
class ParsedSource:
    content: str | None
    records: list[dict[str, Any]] | None
    manifest: dict[str, Any]
    provenance: tuple[dict[str, int], ...]


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise IngestionError("Duplicate object members are unsupported.")
        result[key] = value
    return result


def _no_constant(value: str) -> None:
    raise IngestionError("Nonfinite numeric values are unsupported.")


def _finite_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise IngestionError("Nonfinite numeric values are unsupported.")
    # Reject underflow/rounding that changes the numeric value on JSON round-trip.
    # Original lexical spelling remains available only in the source escrow.
    try:
        if Decimal(str(number)) != Decimal(value):
            raise IngestionError("JSON numeric precision is unsupported.")
    except InvalidOperation:
        raise IngestionError("JSON numeric precision is unsupported.") from None
    return number


def _load_json(source: str) -> Any:
    try:
        return json.loads(source, object_pairs_hook=_unique_object,
                          parse_constant=_no_constant, parse_float=_finite_float)
    except IngestionError:
        raise
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise IngestionError("Invalid JSON source.") from None


def _validate_records(records: list[dict[str, Any]]) -> None:
    if not records or len(records) > MAX_RECORDS:
        raise IngestionError("Record count is outside supported limits.")
    if any(type(record) is not dict for record in records):
        raise IngestionError("Records must be JSON objects.")
    stack: list[tuple[Any, int]] = [(records, 0)]
    nodes = 0
    normalized_bytes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise IngestionError("Source exceeds structural limits.")
        if type(value) is dict:
            normalized_bytes += 2 + max(0, len(value) - 1) + len(value)
            if len(value) * 2 + nodes > MAX_NODES:
                raise IngestionError("Source exceeds structural limits.")
            for key, child in value.items():
                stack.extend(((key, depth + 1), (child, depth + 1)))
        elif type(value) is list:
            normalized_bytes += 2 + max(0, len(value) - 1)
            if len(value) + nodes > MAX_NODES:
                raise IngestionError("Source exceeds structural limits.")
            stack.extend((child, depth + 1) for child in value)
        elif type(value) is str:
            if len(value) > MAX_FIELD_CHARS:
                raise IngestionError("Source exceeds field limits.")
            try:
                normalized_bytes += len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
            except UnicodeError:
                raise IngestionError("Source contains invalid Unicode.") from None
        elif type(value) is float and not math.isfinite(value):
            raise IngestionError("Nonfinite numeric values are unsupported.")
        else:
            normalized_bytes += len(json.dumps(value, allow_nan=False).encode("utf-8"))
        if normalized_bytes > MAX_BYTES:
            raise IngestionError("Normalized source exceeds the byte limit.")


def _check_csv_quoting(source: str) -> None:
    """Reject quote-in-unquoted-field syntax that csv.reader otherwise accepts.

    Fixed comma delimiter and double-quote quoting; doubled quotes only. This is
    a bounded linear lexical check, not another value parser. Never mutate the
    process-global csv.field_size_limit, which would race concurrent requests.
    """
    state = "start"
    index = 0
    while index < len(source):
        char = source[index]
        if char == "\x00":
            raise IngestionError("Invalid CSV source.")
        if state == "quoted":
            if char == '"':
                state = "closed"
        elif state == "closed":
            if char == '"':
                state = "quoted"
            elif char == ",":
                state = "start"
            elif char in "\r\n":
                state = "start"
            else:
                raise IngestionError("Invalid CSV quoting.")
        elif state == "start":
            if char == '"':
                state = "quoted"
            elif char not in ",\r\n":
                state = "unquoted"
        else:
            if char == '"':
                raise IngestionError("Invalid CSV quoting.")
            if char in ",\r\n":
                state = "start"
        index += 1
    if state == "quoted":
        raise IngestionError("Invalid CSV quoting.")


def _parse_csv(source: str) -> tuple[list[dict[str, str]], tuple[dict[str, int], ...]]:
    _check_csv_quoting(source)
    reader = csv.reader(io.StringIO(source, newline=""), delimiter=",", quotechar='"',
                        doublequote=True, skipinitialspace=False, strict=True)
    try:
        headers = next(reader)
        if (not headers or len(headers) > MAX_COLUMNS
                or any(not header.strip() or len(header) > MAX_FIELD_CHARS
                       or any(ord(char) < 32 or ord(char) == 127 for char in header)
                       for header in headers)
                or len(set(headers)) != len(headers)):
            raise IngestionError("Invalid CSV headers.")
        records: list[dict[str, str]] = []
        provenance = []
        previous_line = reader.line_num
        for row in reader:
            line_start, line_end = previous_line + 1, reader.line_num
            previous_line = line_end
            if not row or all(not value.strip() for value in row):
                raise IngestionError("Blank CSV records are unsupported.")
            if len(row) != len(headers):
                raise IngestionError("CSV column counts do not match.")
            if any(len(value) > MAX_FIELD_CHARS for value in row):
                raise IngestionError("Source exceeds field limits.")
            if len(records) >= MAX_RECORDS:
                raise IngestionError("Record count is outside supported limits.")
            provenance.append({"record_index": len(records), "line_start": line_start, "line_end": line_end})
            records.append(dict(zip(headers, row)))
        return records, tuple(provenance)
    except IngestionError:
        raise
    except (csv.Error, StopIteration, UnicodeError, ValueError):
        raise IngestionError("Invalid CSV source.") from None


def parse_source(*, content: str, format: str) -> ParsedSource:
    """Parse all input or reject; manifest/provenance contain no source values."""
    if type(format) is not str or format not in FORMATS:
        raise IngestionError("Unsupported source format.")
    if type(content) is not str or not content.strip():
        raise IngestionError("Source must be nonempty text.")
    # Fast rejection before allocating an encoded copy of a wildly oversized input.
    if len(content) > MAX_BYTES:
        raise IngestionError("Source exceeds the byte limit.")
    try:
        encoded = content.encode("utf-8")
    except UnicodeError:
        raise IngestionError("Source contains invalid Unicode.") from None
    if len(encoded) > MAX_BYTES:
        raise IngestionError("Source exceeds the byte limit.")
    if content.startswith("\ufeff"):
        raise IngestionError("Byte-order marks are unsupported.")

    records: list[dict[str, Any]] | None = None
    normalized_content: str | None = None
    provenance: tuple[dict[str, int], ...]
    limitations = ["Parsing is not sensitive-data detection, anonymization, data-rights verification or release approval.",
                   "Both source UTF-8 and normalized compact JSON records are bounded; JSON decimals must round-trip without numeric value loss."]
    blank_lines: int | None = None
    if format == "text":
        normalized_content = content  # never trim or normalize original text
        line_count = sum(1 for _ in io.StringIO(content, newline=""))
        provenance = ({"record_index": 0, "line_start": 1, "line_end": line_count},)
        limitations.append("Plain text has no inferred schema or document structure.")
    elif format == "json":
        parsed = _load_json(content)
        if type(parsed) is not list:
            raise IngestionError("JSON source must be an array of objects.")
        records = parsed
        _validate_records(records)
        provenance = tuple({"record_index": index} for index in range(len(records)))
        limitations.append("JSON provenance records array positions, not original field byte offsets.")
    elif format == "jsonl":
        records, positions = [], []
        blank_lines = 0
        for line_number, line in enumerate(io.StringIO(content, newline=""), start=1):
            if not line.strip():
                blank_lines += 1
                continue
            if len(records) >= MAX_RECORDS:
                raise IngestionError("Record count is outside supported limits.")
            record = _load_json(line)
            if type(record) is not dict:
                raise IngestionError("Records must be JSON objects.")
            positions.append({"record_index": len(records), "line_start": line_number, "line_end": line_number})
            records.append(record)
        _validate_records(records)
        provenance = tuple(positions)
        limitations.append("Whitespace-only JSONL physical lines are counted but do not become records.")
    else:
        records, provenance = _parse_csv(content)
        _validate_records(records)
        limitations.extend(("CSV uses a fixed comma delimiter and double-quote escaping; no dialect or scalar type inference.",
                            "CSV strings may contain spreadsheet formulas; parsing does not neutralize them or authorize spreadsheet export.",
                            "CSV headers remain exact source strings in internal records; physical data-line provenance excludes headers."))

    manifest: dict[str, Any] = {"format": format, "source_sha256": hashlib.sha256(encoded).hexdigest(),
                                "source_bytes": len(encoded), "record_count": len(records) if records is not None else 1,
                                "parser_id": PARSER_ID, "limitations": limitations}
    if blank_lines is not None:
        manifest["blank_lines"] = blank_lines
    return ParsedSource(content=normalized_content, records=records, manifest=manifest, provenance=provenance)
