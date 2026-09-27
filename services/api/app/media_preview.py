"""Bounded raster/OCR media preview for the synthetic demo only.

The source is decoded into pixels and the candidate is a newly encoded PNG
(and, for PDF input, a newly constructed image-only PDF). Neither source PDF
objects nor image metadata are copied into the candidate. OCR coverage and
residual detection are *not* independent privacy qualification.
"""
from __future__ import annotations

import base64
from collections import Counter
from functools import lru_cache
import hashlib
from io import BytesIO
import math
from pathlib import Path
import re
from threading import Lock
from typing import Any

from app.contracts import PayloadError
from app.demo_contextual import contextual_spans
from app.processing import detect_text

MAX_MEDIA_PAGES = 2
MAX_PAGE_PIXELS = 2_000_000
MAX_TOTAL_PIXELS = 3_000_000
MAX_OCR_LINES = 200
MAX_OCR_CHARS = 30_000
MAX_PNG_BYTES = 2_500_000
MAX_CANDIDATE_PDF_BYTES = 10_000_000
PDF_SCALE = 1.7
_OCR_LOCK = Lock()
_PDFIUM_LOCK = Lock()  # PDFium is not thread-safe, even across separate documents.
_EXPLICIT_HEADER_NAME = re.compile(
    r"(?im)^(?:from|to|cc):\s*(?P<name>[A-Za-z][A-Za-z .'-]{1,79}?)\s*<[^<>\s]+@[^<>\s]+>\s*$"
)
_EXPLICIT_NAME_FIELD = re.compile(r"(?im)^\s*name:\s*(?P<name>[A-Za-z][A-Za-z .'-]{1,79})\s*$")
_EXPLICIT_ROLE_NAME = re.compile(
    r"(?im)^(?P<name>[A-Za-z][A-Za-z .'-]{1,79}) is (?:a client of|assistant (?:to|for)) [^.\r\n]{2,100}\.\r?$|"
    r"^(?P<worker>[A-Za-z][A-Za-z .'-]{1,79}) works on [^.\r\n]{2,100}\.\r?$|"
    r"^[^.\r\n]{2,100} is assigned to (?P<assignee>[A-Za-z][A-Za-z .'-]{1,79})\.\r?$"
)


@lru_cache(maxsize=1)
def _engine() -> Any:
    from rapidocr import RapidOCR

    return RapidOCR()


def _ocr_lines(image: Any, *, require_confidence: bool = True) -> list[dict[str, Any]]:
    import numpy as np

    with _OCR_LOCK:
        result = _engine()(np.asarray(image))
    if result.txts is None or result.boxes is None or result.scores is None:
        return []
    if not len(result.txts) == len(result.boxes) == len(result.scores) or len(result.txts) > MAX_OCR_LINES:
        raise PayloadError("The demo OCR result exceeds its review limits.")
    lines = []
    for value, box, confidence in zip(result.txts, result.boxes, result.scores):
        text = str(value).strip()
        if not text:
            continue
        if len(text) > 500 or not all(char.isprintable() for char in text):
            raise PayloadError("The demo OCR text is unsupported for review.")
        score = float(confidence)
        if not math.isfinite(score) or not 0.0 <= score <= 1.0 or (require_confidence and score < 0.60):
            raise PayloadError("OCR confidence is too low for a visual candidate; inspect the source manually.")
        xs, ys = [float(point[0]) for point in box], [float(point[1]) for point in box]
        if (len(xs) != 4 or any(not math.isfinite(number) for number in (*xs, *ys)) or
                min(xs) < -2 or min(ys) < -2 or max(xs) > image.width + 2 or max(ys) > image.height + 2):
            raise PayloadError("The demo OCR geometry is invalid.")
        bounds = (max(0, math.floor(min(xs)) - 5), max(0, math.floor(min(ys)) - 5),
                  min(image.width, math.ceil(max(xs)) + 5), min(image.height, math.ceil(max(ys)) + 5))
        if bounds[2] <= bounds[0] or bounds[3] <= bounds[1]:
            raise PayloadError("The demo OCR geometry is invalid.")
        lines.append({"text": text, "box": bounds, "confidence": round(score, 4)})
    return sorted(lines, key=lambda line: (line["box"][1], line["box"][0]))


def _image_pages(raw: bytes, extension: str) -> list[Any]:
    from PIL import Image, ImageOps, UnidentifiedImageError

    try:
        source = Image.open(BytesIO(raw))
        expected = "PNG" if extension == ".png" else "JPEG"
        if source.format != expected or getattr(source, "n_frames", 1) != 1:
            raise ValueError
        if (source.width < 16 or source.height < 16 or
                source.width * source.height > MAX_PAGE_PIXELS):
            raise ValueError
        image = ImageOps.exif_transpose(source)
        image.load()
        return [image.convert("RGB")]
    except (ValueError, OSError, UnidentifiedImageError):
        raise PayloadError("The image is unsupported or exceeds the synthetic demo pixel limit.") from None


def _pdf_pages(raw: bytes) -> tuple[list[Any], list[str]]:
    with _PDFIUM_LOCK:
        return _pdf_pages_locked(raw)


def _pdf_pages_locked(raw: bytes) -> tuple[list[Any], list[str]]:
    from pypdf import PdfReader
    import pypdfium2 as pdfium

    try:
        reader = PdfReader(BytesIO(raw), strict=True)
        root = reader.trailer["/Root"]
        if (reader.is_encrypted or not 1 <= len(reader.pages) <= MAX_MEDIA_PAGES or
                root.get("/AcroForm") or root.get("/Names") or root.get("/OpenAction")):
            raise ValueError
        pdf = pdfium.PdfDocument(raw)
        try:
            if len(pdf) != len(reader.pages):
                raise ValueError
            pages = []
            native_texts = []
            total_pixels = 0
            for index in range(len(pdf)):
                page = pdf[index]
                try:
                    width = math.ceil(page.get_width() * PDF_SCALE)
                    height = math.ceil(page.get_height() * PDF_SCALE)
                    total_pixels += width * height
                    if width < 16 or height < 16 or width * height > MAX_PAGE_PIXELS or total_pixels > MAX_TOTAL_PIXELS:
                        raise ValueError
                    textpage = page.get_textpage()
                    try:
                        if textpage.count_chars() > MAX_OCR_CHARS:
                            raise ValueError
                        native_texts.append(textpage.get_text_bounded())
                    finally:
                        textpage.close()
                    bitmap = page.render(scale=PDF_SCALE, draw_annots=True, rev_byteorder=True)
                    try:
                        pages.append(bitmap.to_pil().convert("RGB").copy())
                    finally:
                        bitmap.close()
                finally:
                    page.close()
        finally:
            pdf.close()
        return pages, native_texts
    except Exception:
        raise PayloadError("The PDF is unsupported for bounded raster review (two pages maximum).") from None


def extract_media(raw: bytes, extension: str) -> tuple[str, list[dict[str, Any]]]:
    """Return OCR text and private page objects; no output is authorized."""
    if extension in {".png", ".jpg", ".jpeg"}:
        images = _image_pages(raw, extension)
        native_texts = [""] * len(images)
    elif extension == ".pdf":
        images, native_texts = _pdf_pages(raw)
    else:
        raise PayloadError("Unsupported synthetic media type.")
    pages = []
    text_parts = []
    offset = 0
    for number, (image, native_text) in enumerate(zip(images, native_texts), 1):
        lines = _ocr_lines(image)
        if not lines:
            raise PayloadError("No readable OCR text was found in a media page.")
        _verify_pdf_text_layer(native_text, lines)
        for line in lines:
            if text_parts:
                offset += 1
            line["start"] = offset
            offset += len(line["text"])
            line["end"] = offset
            text_parts.append(line["text"])
        pages.append({"number": number, "image": image, "lines": lines})
    text = "\n".join(text_parts)
    if len(text) > MAX_OCR_CHARS or len(text.encode("utf-8")) > 100_000:
        raise PayloadError("Extracted media text exceeds the synthetic demo limit.")
    return text, pages


def _verify_pdf_text_layer(native_text: str, lines: list[dict[str, Any]]) -> None:
    """Reject an OCR transcript that omits a recognized born-digital signal.

    This is a partial cross-check, not a scanned-page or pixel coverage proof.
    """
    if not native_text:
        return
    ocr_values = [line["text"].casefold() for line in lines]
    required: Counter[tuple[str, str]] = Counter()
    for span in detect_text(native_text):
        if span.entity_type not in {"EMAIL", "PAN", "PHONE", "IP_ADDRESS", "AADHAAR", "CARD"}:
            continue
        source = native_text[span.start:span.end].casefold()
        if span.entity_type in {"PHONE", "AADHAAR", "CARD"}:
            source = "".join(char for char in source if char.isdigit())
        required[(span.entity_type, source)] += 1
    # A native text layer can expose explicit relationship evidence that is not
    # matched by detect_text.  Require OCR to preserve those bounded person
    # signals too, otherwise a graph could claim a relationship from text the
    # review candidate never actually saw.
    for pattern in (_EXPLICIT_HEADER_NAME, _EXPLICIT_NAME_FIELD, _EXPLICIT_ROLE_NAME):
        for match in pattern.finditer(native_text):
            for group in ("name", "worker", "assignee"):
                value = match.groupdict().get(group)
                if value:
                    required[("PERSON_NAME", value.strip().casefold())] += 1
    for start, end, kind in contextual_spans(native_text):
        source = native_text[start:end].casefold()
        if kind == "ADDRESS":
            source = " ".join(source.split())
        required[(kind, source)] += 1
    for (kind, source), count in required.items():
        if kind == "ADDRESS":
            present = " ".join(" ".join(ocr_values).split()).count(source)
        else:
            values = ("".join(char for char in line if char.isdigit()) for line in ocr_values) if kind in {"PHONE", "AADHAAR", "CARD"} else iter(ocr_values)
            present = sum(line.count(source) for line in values)
        if present < count:
            raise PayloadError("PDF text-layer and OCR disagree on a sensitive value; inspect the source manually.")


def _png_bytes(image: Any) -> bytes:
    stream = BytesIO()
    image.save(stream, format="PNG", optimize=True)
    data = stream.getvalue()
    if len(data) > MAX_PNG_BYTES:
        raise PayloadError("A media preview page exceeds the synthetic demo response limit.")
    return data


def _draw_line(image: Any, box: tuple[int, int, int, int], value: str) -> bool:
    from PIL import ImageDraw, ImageFont
    import reportlab

    draw = ImageDraw.Draw(image)
    x0, y0, x1, y1 = box
    draw.rectangle((x0, y0, x1 - 1, y1 - 1), fill="white")
    available_width, available_height = x1 - x0 - 4, y1 - y0 - 4
    font_path = Path(reportlab.__file__).parent / "fonts" / "Vera.ttf"
    for size in range(min(32, max(7, available_height)), 6, -1):
        try:
            font = ImageFont.truetype(str(font_path), size)
        except OSError:
            break
        bounds = draw.textbbox((0, 0), value, font=font)
        if bounds[2] - bounds[0] <= available_width and bounds[3] - bounds[1] <= available_height:
            draw.text((x0 + 2 - bounds[0], y0 + 2 - bounds[1]), value, font=font, fill="black")
            return False
    # A solid mark is safer than clipping a long replacement into adjacent text.
    draw.rectangle((x0, y0, x1 - 1, y1 - 1), fill="black")
    return True


def _image_pdf(images: list[Any]) -> bytes:
    from reportlab.lib.utils import ImageReader
    from reportlab.pdfgen import canvas

    stream = BytesIO()
    pdf = canvas.Canvas(stream, pagesize=(images[0].width, images[0].height), invariant=1)
    for image in images:
        pdf.setPageSize((image.width, image.height))
        pdf.drawImage(ImageReader(BytesIO(_png_bytes(image))), 0, 0, width=image.width, height=image.height)
        pdf.showPage()
    pdf.save()
    return stream.getvalue()


def render_candidate(pages: list[dict[str, Any]], matches: list[dict[str, Any]], kind: str,
                     coordinate_regions: dict[int, list[dict[str, Any]]] | None = None) -> dict[str, Any]:
    """Paint affected OCR lines into new raster pages; inspect again with OCR."""
    public_pages = []
    candidate_images = []
    assigned = set()
    fallback_lines = 0
    visual_residuals = 0
    candidate_low_confidence_lines = 0
    coordinate_regions = coordinate_regions or {}
    for page in pages:
        source_image = page["image"]
        candidate = source_image.copy()
        page_sources = set()
        for line in page["lines"]:
            line_matches = []
            for index, match in enumerate(matches):
                if match["start"] < line["end"] and match["end"] > line["start"]:
                    if match["start"] < line["start"] or match["end"] > line["end"]:
                        raise PayloadError("A media finding crosses an OCR line; no visual candidate was made.")
                    assigned.add(index)
                    line_matches.append(match)
            applied = [match for match in line_matches if match["applied"]]
            if not applied:
                continue
            parts = []
            cursor = line["start"]
            for match in applied:
                parts.extend((line["text"][cursor - line["start"]:match["start"] - line["start"]],
                              match["replacement"]))
                cursor = match["end"]
                page_sources.add(match["source"])
            parts.append(line["text"][cursor - line["start"]:])
            fallback_lines += _draw_line(candidate, line["box"], "".join(parts))
        # Reviewer coordinates are opaque visual corrections.  They are applied
        # after OCR-line substitutions, never produce text/entity matches, and
        # therefore cannot inflate text scoring or alter candidate_text.
        manual_regions = coordinate_regions.get(page["number"], [])
        if manual_regions:
            from PIL import ImageDraw
            draw = ImageDraw.Draw(candidate)
            for region in manual_regions:
                draw.rectangle((region["x0"], region["y0"], region["x1"] - 1, region["y1"] - 1), fill="black")
        # Input OCR still requires 0.60 confidence. A newly rendered alias can
        # itself lower candidate OCR confidence across platforms; it does not
        # restore the original pixels. Count that uncertainty separately, and
        # never present this same-engine recheck as a safety certificate.
        candidate_lines = _ocr_lines(candidate, require_confidence=False)
        candidate_low_confidence_lines += sum(line["confidence"] < 0.60 for line in candidate_lines)
        candidate_ocr = "\n".join(line["text"] for line in candidate_lines)
        for source in page_sources:
            if re.search(r"(?<!\w)" + re.escape(source) + r"(?!\w)", candidate_ocr, re.I):
                visual_residuals += 1
        source_png = _png_bytes(source_image)
        candidate_png = _png_bytes(candidate)
        public_pages.append({"number": page["number"], "width": source_image.width, "height": source_image.height,
                             "source_png_base64": base64.b64encode(source_png).decode("ascii"),
                             "source_png_sha256": hashlib.sha256(source_png).hexdigest(),
                             "candidate_png_base64": base64.b64encode(candidate_png).decode("ascii"),
                             "candidate_png_sha256": hashlib.sha256(candidate_png).hexdigest(),
                             "manual_regions": manual_regions,
                             "ocr_lines": len(page["lines"])})
        candidate_images.append(candidate)
    if len(assigned) != len(matches):
        raise PayloadError("A finding cannot be located on an OCR page; no visual candidate was made.")
    pdf_evidence = None
    candidate_pdf_base64 = None
    if kind == "pdf":
        generated = _image_pdf(candidate_images)
        if len(generated) > MAX_CANDIDATE_PDF_BYTES:
            raise PayloadError("The raster PDF candidate exceeds the synthetic demo response limit.")
        pdf_evidence = {"sha256": hashlib.sha256(generated).hexdigest(), "bytes": len(generated),
                        "pages": len(candidate_images), "source_objects_copied": False}
        candidate_pdf_base64 = base64.b64encode(generated).decode("ascii")
    return {"pages": public_pages, "fallback_lines": fallback_lines,
            "candidate_low_confidence_lines": candidate_low_confidence_lines,
            "self_ocr_residual_sources": visual_residuals, "pdf_raster_evidence": pdf_evidence,
            "candidate_pdf_base64": candidate_pdf_base64}
