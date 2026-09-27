"""Bounded D07 synthetic final-pixel evaluator.

This is evidence collection only.  It is intentionally not imported by any
release path and cannot return an approval or qualification decision.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from io import BytesIO
from pathlib import Path
from typing import Protocol

from PIL import Image, UnidentifiedImageError

from app.tesseract_verifier import TesseractCliVerifier


VERSION = "d07-synthetic-media-final-pixels-v1"
_FIXTURE_DIRECTORY = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "d07_media_holdout"
_MANIFEST_SHA256 = "8ceeffdad535192b675ef554162e083239016b8953c82c006618c4ba3dca1941"
_MAX_CASES = 16
_MAX_MANIFEST_BYTES = 16_384
_MAX_PIXELS_PER_CASE = 10_000_000
_MAX_OCR_CHARACTERS = 100_000
_CASE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")


class D07MediaHoldoutError(ValueError):
    """Fixed failure that reveals neither corpus content nor filesystem details."""


class MediaKind(str, Enum):
    PDF_RENDERED_PAGE = "pdf_rendered_page"
    IMAGE = "image"


class EvaluationStatus(str, Enum):
    BLOCKED = "BLOCKED"
    SYNTHETIC_CANARIES_CONFIRMED = "SYNTHETIC_CANARIES_CONFIRMED"


@dataclass(frozen=True)
class RenderedPixels:
    """One final raster only; source PDFs, text layers, and metadata are excluded."""

    case_id: str
    pixels: bytes


class PixelOcr(Protocol):
    def extract_text(self, *, pixels: bytes, kind: MediaKind) -> str: ...


@dataclass(frozen=True)
class TesseractPixelOcr:
    """D07 adapter for an already provisioned Tesseract final-PNG verifier.

    It deliberately accepts a verifier instance rather than an executable path:
    D07 cannot discover a binary through PATH or relax its provisioned hash and
    runtime-identity checks.  It is opt-in and has no product or release wiring.
    """

    verifier: TesseractCliVerifier

    def __post_init__(self) -> None:
        # This named adapter cannot be satisfied by a structural/mock OCR
        # object.  Generic test adapters remain supported through PixelOcr.
        if type(self.verifier) is not TesseractCliVerifier:
            raise TypeError("D07 Tesseract adapter requires a provisioned TesseractCliVerifier.")

    def extract_text(self, *, pixels: bytes, kind: MediaKind) -> str:
        if not isinstance(kind, MediaKind):
            _reject()
        return self.verifier.extract_final_png_text(pixels)


def _reject() -> None:
    raise D07MediaHoldoutError("D07 media holdout verification failed; no report was produced.")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _parse_manifest(raw: bytes) -> dict[str, object]:
    try:
        if not raw:
            _reject()
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        if not isinstance(parsed, dict):
            _reject()
        return parsed
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _reject()


def _canonical_manifest_bytes(directory: Path) -> bytes:
    """Bound the manifest and normalize only legacy CRLF checkout bytes.

    This deliberately does not parse/re-serialize JSON.  Thus whitespace,
    key-order, and every non-line-ending source-byte change remains pinned.
    """
    try:
        with (directory / "manifest.json").open("rb") as stream:
            raw = stream.read(_MAX_MANIFEST_BYTES + 1)
        if len(raw) > _MAX_MANIFEST_BYTES:
            _reject()
        canonical = raw.replace(b"\r\n", b"\n")
        if b"\r" in canonical:
            _reject()
        return canonical
    except (OSError, D07MediaHoldoutError):
        _reject()


def _load_cases(directory: Path) -> tuple[tuple[str, MediaKind, str, tuple[str, ...], tuple[str, ...]], ...]:
    """Load minimally-normalized source-pinned bytes without returning markers."""
    try:
        raw = _canonical_manifest_bytes(directory)
        if hashlib.sha256(raw).hexdigest() != _MANIFEST_SHA256:
            _reject()
        manifest = _parse_manifest(raw)
        if set(manifest) != {"schema_version", "fixture_id", "cases"}:
            _reject()
        if manifest["schema_version"] != VERSION or manifest["fixture_id"] != "d07-synthetic-media-final-pixels-v1":
            _reject()
        cases = manifest["cases"]
        if not isinstance(cases, list) or not 1 <= len(cases) <= _MAX_CASES:
            _reject()
        result: list[tuple[str, MediaKind, str, tuple[str, ...], tuple[str, ...]]] = []
        seen: set[str] = set()
        for item in cases:
            if not isinstance(item, dict) or set(item) != {"case_id", "kind", "final_raster_sha256", "expected_final_markers", "forbidden_markers"}:
                _reject()
            case_id, kind = item["case_id"], item["kind"]
            digest, expected_final, forbidden = (item["final_raster_sha256"], item["expected_final_markers"],
                                                  item["forbidden_markers"])
            if not isinstance(case_id, str) or not _CASE_ID.fullmatch(case_id) or case_id in seen:
                _reject()
            if not isinstance(kind, str) or kind not in {value.value for value in MediaKind}:
                _reject()
            if (not isinstance(digest, str) or not _DIGEST.fullmatch(digest) or
                    not isinstance(expected_final, list) or not 1 <= len(expected_final) <= 8 or
                    not isinstance(forbidden, list) or not 1 <= len(forbidden) <= 8 or
                    any(not isinstance(marker, str) or not 3 <= len(marker) <= 160
                        for marker in (*expected_final, *forbidden)) or
                    len(set(expected_final)) != len(expected_final) or len(set(forbidden)) != len(forbidden) or
                    set(expected_final).intersection(forbidden)):
                _reject()
            seen.add(case_id)
            result.append((case_id, MediaKind(kind), digest, tuple(expected_final), tuple(forbidden)))
        return tuple(result)
    except (OSError, D07MediaHoldoutError, TypeError, ValueError, RecursionError):
        _reject()


def _blocked(reason: str, aggregate: dict[str, object] | None = None) -> dict[str, object]:
    report: dict[str, object] = {
        "schema_version": VERSION,
        "classification": "SYNTHETIC_FINAL_PIXEL_HOLDOUT",
        "qualification": "NOT_QUALIFIED",
        "status": EvaluationStatus.BLOCKED.value,
        "reason": reason,
        "measurement_status": {"pdf_final_pixels": "NOT_MEASURED", "image_final_pixels": "NOT_MEASURED", "ocr": "UNAVAILABLE"},
        "limitations": _limitations(),
    }
    if aggregate is not None:
        report["aggregate"] = aggregate
    return report


def _limitations() -> list[str]:
    return [
        "This bounded synthetic check is not source-completeness, recall, or production qualification evidence.",
        "Only final raster pixels supplied to this evaluator are inspected; PDF text layers and source metadata are excluded.",
        "This report is not a release authorization, legal determination, or compliance decision.",
    ]


def _validate_final_png(pixels: bytes) -> None:
    """Require a bounded, decodable PNG before it reaches an OCR adapter."""
    try:
        with Image.open(BytesIO(pixels)) as image:
            if image.format != "PNG":
                _reject()
            if image.width < 16 or image.height < 16 or image.width * image.height > 2_000_000:
                _reject()
            image.load()
    except (OSError, ValueError, UnidentifiedImageError, D07MediaHoldoutError):
        _reject()


def evaluate_final_pixels(*, rendered: tuple[RenderedPixels, ...], ocr: PixelOcr | None,
                          fixture_directory: Path = _FIXTURE_DIRECTORY) -> dict[str, object]:
    """Evaluate locked synthetic markers with an independent OCR adapter.

    Reports contain aggregate counts and status codes only.  OCR failures,
    malformed inputs, fixture drift, and incomplete final pixels fail closed.
    """
    if ocr is None:
        return _blocked("INDEPENDENT_PIXEL_OCR_UNAVAILABLE")
    try:
        cases = _load_cases(fixture_directory)
        if not isinstance(rendered, tuple) or len(rendered) != len(cases):
            _reject()
        supplied: dict[str, bytes] = {}
        for item in rendered:
            if not isinstance(item, RenderedPixels) or not _CASE_ID.fullmatch(item.case_id):
                _reject()
            if item.case_id in supplied or not isinstance(item.pixels, bytes) or not 1 <= len(item.pixels) <= _MAX_PIXELS_PER_CASE:
                _reject()
            supplied[item.case_id] = item.pixels
        if set(supplied) != {case[0] for case in cases}:
            _reject()

        expected_final = observed_final = missing_final = expected_forbidden = observed_forbidden = 0
        by_kind: dict[str, dict[str, int]] = {
            kind.value: {"cases": 0, "expected_final_markers": 0, "observed_final_markers": 0,
                         "missing_final_markers": 0, "forbidden_markers": 0,
                         "observed_forbidden_markers": 0}
            for kind in MediaKind
        }
        for case_id, kind, digest, expected, forbidden in cases:
            if hashlib.sha256(supplied[case_id]).hexdigest() != digest:
                _reject()
            _validate_final_png(supplied[case_id])
            text = ocr.extract_text(pixels=supplied[case_id], kind=kind)
            if not isinstance(text, str) or len(text) > _MAX_OCR_CHARACTERS:
                _reject()
            folded = text.casefold()
            final_found = sum(marker.casefold() in folded for marker in expected)
            forbidden_found = sum(marker.casefold() in folded for marker in forbidden)
            expected_final += len(expected)
            observed_final += final_found
            missing_final += len(expected) - final_found
            expected_forbidden += len(forbidden)
            observed_forbidden += forbidden_found
            aggregates = by_kind[kind.value]
            aggregates["cases"] += 1
            aggregates["expected_final_markers"] += len(expected)
            aggregates["observed_final_markers"] += final_found
            aggregates["missing_final_markers"] += len(expected) - final_found
            aggregates["forbidden_markers"] += len(forbidden)
            aggregates["observed_forbidden_markers"] += forbidden_found
        aggregate = {"cases": len(cases), "expected_final_markers": expected_final,
                     "observed_final_markers": observed_final, "missing_final_markers": missing_final,
                     "forbidden_markers": expected_forbidden,
                     "observed_forbidden_markers": observed_forbidden, "by_kind": by_kind}
        if missing_final or observed_forbidden:
            return _blocked("SYNTHETIC_CANARY_EXPECTATION_MISMATCH", aggregate)
        return {
            "schema_version": VERSION,
            "classification": "SYNTHETIC_FINAL_PIXEL_HOLDOUT",
            "qualification": "NOT_QUALIFIED",
            "status": EvaluationStatus.SYNTHETIC_CANARIES_CONFIRMED.value,
            "reason": "SYNTHETIC_FINAL_CANARIES_CONFIRMED",
            "aggregate": aggregate,
            "measurement_status": {"pdf_final_pixels": "MEASURED_SYNTHETIC_MARKERS", "image_final_pixels": "MEASURED_SYNTHETIC_MARKERS", "ocr": "INDEPENDENT_ADAPTER_SUPPLIED"},
            "limitations": _limitations(),
        }
    except Exception:
        return _blocked("FINAL_PIXEL_EVALUATION_FAILED_CLOSED")
