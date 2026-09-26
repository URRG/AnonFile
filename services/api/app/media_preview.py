"""Bounded raster/OCR media preview for the synthetic demo only.

The source is decoded into pixels and the candidate is a newly encoded PNG
(and, for PDF input, a newly constructed image-only PDF). Neither source PDF
objects nor image metadata are copied into the candidate. OCR coverage and
residual detection are *not* independent privacy qualification.
"""
from __future__ import annotations

import base64
from functools import lru_cache
import hashlib
from io import BytesIO
import math
from pathlib import Path
import re
from threading import Lock
from typing import Any

from app.contracts import PayloadError

MAX_MEDIA_PAGES = 2
MAX_PAGE_PIXELS = 2_000_000
MAX_TOTAL_PIXELS = 3_000_000
MAX_OCR_LINES = 200
MAX_OCR_CHARS = 30_000
MAX_PNG_BYTES = 2_500_000
PDF_SCALE = 1.5
_OCR_LOCK = Lock()


@lru_cache(maxsize=1)
def _engine() -> Any:
    from rapidocr import RapidOCR

    return RapidOCR()


def _ocr_lines(image: Any) -> list[dict[str, Any]]:
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
        if not math.isfinite(float(confidence)) or float(confidence) < 0.60:
            raise PayloadError("OCR confidence is too low for a visual candidate; inspect the source manually.")
        xs, ys = [float(point[0]) for point in box], [float(point[1]) for point in box]
        if (len(xs) != 4 or any(not math.isfinite(number) for number in (*xs, *ys)) or
                min(xs) < -2 or min(ys) < -2 or max(xs) > image.width + 2 or max(ys) > image.height + 2):
            raise PayloadError("The demo OCR geometry is invalid.")
        bounds = (max(0, math.floor(min(xs)) - 5), max(0, math.floor(min(ys)) - 5),
                  min(image.width, math.ceil(max(xs)) + 5), min(image.height, math.ceil(max(ys)) + 5))
        if bounds[2] <= bounds[0] or bounds[3] <= bounds[1]:
            raise PayloadError("The demo OCR geometry is invalid.")
        lines.append({"text": text, "box": bounds, "confidence": round(float(confidence), 4)})
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


def _pdf_pages(raw: bytes) -> list[Any]:
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
            total_pixels = 0
            for index in range(len(pdf)):
                page = pdf[index]
                try:
                    width = math.ceil(page.get_width() * PDF_SCALE)
                    height = math.ceil(page.get_height() * PDF_SCALE)
                    total_pixels += width * height
                    if width < 16 or height < 16 or width * height > MAX_PAGE_PIXELS or total_pixels > MAX_TOTAL_PIXELS:
                        raise ValueError
                    bitmap = page.render(scale=PDF_SCALE, draw_annots=True, rev_byteorder=True)
                    try:
                        pages.append(bitmap.to_pil().convert("RGB").copy())
                    finally:
                        bitmap.close()
                finally:
                    page.close()
        finally:
            pdf.close()
        return pages
    except Exception:
        raise PayloadError("The PDF is unsupported for bounded raster review (two pages maximum).") from None


def extract_media(raw: bytes, extension: str) -> tuple[str, list[dict[str, Any]]]:
    """Return OCR text and private page objects; no output is authorized."""
    if extension in {".png", ".jpg", ".jpeg"}:
        images = _image_pages(raw, extension)
    elif extension == ".pdf":
        images = _pdf_pages(raw)
    else:
        raise PayloadError("Unsupported synthetic media type.")
    pages = []
    text_parts = []
    offset = 0
    for number, image in enumerate(images, 1):
        lines = _ocr_lines(image)
        if not lines:
            raise PayloadError("No readable OCR text was found in a media page.")
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


def render_candidate(pages: list[dict[str, Any]], matches: list[dict[str, Any]], kind: str) -> dict[str, Any]:
    """Paint affected OCR lines into new raster pages; inspect again with OCR."""
    public_pages = []
    candidate_images = []
    assigned = set()
    fallback_lines = 0
    visual_residuals = 0
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
        candidate_ocr = "\n".join(line["text"] for line in _ocr_lines(candidate))
        for source in page_sources:
            if re.search(r"(?<!\w)" + re.escape(source) + r"(?!\w)", candidate_ocr, re.I):
                visual_residuals += 1
        source_png = _png_bytes(source_image)
        candidate_png = _png_bytes(candidate)
        public_pages.append({"number": page["number"], "width": source_image.width, "height": source_image.height,
                             "source_png_base64": base64.b64encode(source_png).decode("ascii"),
                             "candidate_png_base64": base64.b64encode(candidate_png).decode("ascii"),
                             "ocr_lines": len(page["lines"])})
        candidate_images.append(candidate)
    if len(assigned) != len(matches):
        raise PayloadError("A finding cannot be located on an OCR page; no visual candidate was made.")
    pdf_evidence = None
    if kind == "pdf":
        generated = _image_pdf(candidate_images)
        pdf_evidence = {"sha256": hashlib.sha256(generated).hexdigest(), "bytes": len(generated),
                        "pages": len(candidate_images), "source_objects_copied": False}
    return {"pages": public_pages, "fallback_lines": fallback_lines,
            "self_ocr_residual_sources": visual_residuals, "pdf_raster_evidence": pdf_evidence}
