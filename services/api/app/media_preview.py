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
from app.tesseract_verifier import IndependentFinalOcrVerifier

MAX_MEDIA_PAGES = 2
MAX_PAGE_PIXELS = 2_000_000
MAX_TOTAL_PIXELS = 3_000_000
MAX_OCR_LINES = 200
MAX_OCR_CHARS = 30_000
MAX_PNG_BYTES = 2_500_000
MAX_CANDIDATE_PDF_BYTES = 10_000_000
PDF_SCALE = 1.7
# A claimed OCR line with no pixel transition at all is not defensible source
# geometry. This deliberately detects only catastrophic blur/flat raster data;
# it is not a readability, language, or OCR-coverage threshold.
MIN_OCR_LINE_EDGE_DELTA = 12
# A single OCR claim may be overbroad even when it reports a plausible string
# and has a local raster edge. Do not let its repaint erase a visibly separate
# ink island (for example, an unrecognised adjacent value) inside that claim.
# This is scaled to the line height so ordinary glyph/word gaps remain valid.
MIN_OCR_LINE_SEPARATE_INK_GAP = 10
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


def _boxes_overlap(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    """Return whether two half-open pixel rectangles share any pixels."""
    return left[0] < right[2] and left[2] > right[0] and left[1] < right[3] and left[3] > right[1]


def _line_ink_box(line: dict[str, Any]) -> tuple[int, int, int, int]:
    """Use the tight OCR extent when available, never a guessed text width."""
    value = line.get("ink_box", line["box"])
    return tuple(value)  # type: ignore[return-value]


def _same_column_band(left: tuple[int, int, int, int], right: tuple[int, int, int, int]) -> bool:
    """Return whether two OCR boxes materially occupy the same vertical band."""
    overlap = min(left[2], right[2]) - max(left[0], right[0])
    return overlap >= max(3, min(left[2] - left[0], right[2] - right[0]) // 2)


def _assert_unambiguous_ocr_layout(lines: list[dict[str, Any]]) -> None:
    """Reject layouts for which top-to-bottom, then left-to-right is a guess.

    This intentionally does not attempt table extraction or column ordering. OCR
    may emit a plausible linear transcript for those layouts, but repainting a
    whole line could then alter an adjacent cell or column.
    """
    for index, line in enumerate(lines):
        left = _line_ink_box(line)
        for other in lines[index + 1:]:
            right = _line_ink_box(other)
            overlap_width = min(left[2], right[2]) - max(left[0], right[0])
            overlap_height = min(left[3], right[3]) - max(left[1], right[1])
            # One or two pixels of overlap is common detector jitter at the
            # boundary between stacked lines; a material overlap is not.
            if overlap_width >= 3 and overlap_height >= 3:
                raise PayloadError("OCR layout is ambiguous for conservative visual review.")
            vertical_overlap = min(left[3], right[3]) - max(left[1], right[1])
            # A material shared vertical band with separated horizontal boxes is
            # a row of cells or concurrent columns, not a dependable text line.
            horizontal_gap = max(left[0], right[0]) - min(left[2], right[2])
            same_baseline = abs((left[1] + left[3]) - (right[1] + right[3])) <= max(
                4, min(left[3] - left[1], right[3] - right[1]) // 2)
            same_row_count = sum(
                abs((left[1] + left[3]) - (candidate["ink_box"][1] + candidate["ink_box"][3])) <= max(
                    4, min(left[3] - left[1], candidate["ink_box"][3] - candidate["ink_box"][1]) // 2)
                for candidate in lines)
            if (vertical_overlap >= max(3, min(left[3] - left[1], right[3] - right[1]) // 2)
                    and horizontal_gap >= 8 and same_baseline
                    and same_row_count >= 2):
                raise PayloadError("OCR layout is ambiguous for conservative visual review.")

    # Columns need not have matching baselines: a sidebar, a table whose rows
    # are vertically offset, or a multi-column scan can otherwise be sorted
    # into an invented alternating transcript.  Repeated, disjoint horizontal
    # bands are enough evidence of columns; do not infer their reading order.
    for index, first in enumerate(lines):
        first_box = _line_ink_box(first)
        for second in lines[index + 1:]:
            second_box = _line_ink_box(second)
            if first_box[2] <= second_box[0]:
                left, right = first_box, second_box
            elif second_box[2] <= first_box[0]:
                left, right = second_box, first_box
            else:
                continue
            left_track = [candidate for candidate in lines if _same_column_band(left, _line_ink_box(candidate))]
            right_track = [candidate for candidate in lines if _same_column_band(right, _line_ink_box(candidate))]
            # A wider gap is still required for two repeated tracks. Adjacent
            # word/token boxes are common OCR output and are not by themselves
            # proof of columns.
            if right[0] - left[2] >= 8 and len(left_track) >= 2 and len(right_track) >= 2:
                raise PayloadError("OCR layout is ambiguous for conservative visual review.")

            # A repeated text track beside one tall claim is also not safely
            # linear.  It occurs with a sidebar, a form value spanning rows,
            # or a partially detected second column.  Requiring the singleton
            # to materially overlap two stacked claims avoids treating a
            # distant note as a column while refusing to invent an order for
            # the local multi-track region. Unlike the repeated-track test,
            # this needs no arbitrary horizontal-gap floor: a tall OCR claim
            # next to two rows is already a multi-row geometry ambiguity even
            # when its edge is only a few pixels away. This does not extract
            # columns or establish that either same-engine OCR box contains
            # only its recognised text.
            repeated_track, singleton_track = (
                (left_track, right_track) if len(left_track) >= 2 and len(right_track) == 1
                else (right_track, left_track) if len(right_track) >= 2 and len(left_track) == 1
                else ([], [])
            )
            if repeated_track:
                singleton = _line_ink_box(singleton_track[0])
                material_overlaps = sum(
                    min(_line_ink_box(candidate)[3], singleton[3]) - max(_line_ink_box(candidate)[1], singleton[1])
                    >= max(3, min(_line_ink_box(candidate)[3] - _line_ink_box(candidate)[1],
                                  singleton[3] - singleton[1]) // 3)
                    for candidate in repeated_track
                )
                if material_overlaps >= 2:
                    raise PayloadError("OCR layout is ambiguous for conservative visual review.")


def _assert_repaint_is_isolated(line: dict[str, Any], lines: list[dict[str, Any]]) -> None:
    """Abstain when the actual erased rectangle could touch another OCR line.

    This guard intentionally never shrinks a repaint box: a crop can leave
    source pixels behind. Tight OCR boxes diagnose reading-order ambiguity,
    but the renderer erases the padded box, so safety must use that full area.
    """
    repaint = tuple(line["box"])
    for other in lines:
        if other is line:
            continue
        ink_box = _line_ink_box(other)
        if _boxes_overlap(repaint, ink_box):
            raise PayloadError("A visual repaint region touches another OCR line; no visual candidate was made.")


def _assert_repaint_padding_is_source_free(source_gray: Any, line: dict[str, Any]) -> None:
    """Reject a padded repaint whose source-pixel ring contains dark ink.

    The renderer erases ``line["box"]``, while OCR's reported ``ink_box`` is
    the only region claimed for that line.  An unrecognised dark mark in the
    intervening padding would be silently erased even when no other OCR line
    reports it.  This is deliberately a narrow, pixel-only fail-closed guard;
    it does not identify text or make an OCR-coverage claim.
    """
    import numpy as np

    x0, y0, x1, y1 = tuple(line["box"])
    ink_x0, ink_y0, ink_x1, ink_y1 = _line_ink_box(line)
    repaint_gray = source_gray[y0:y1, x0:x1]
    padding = np.ones(repaint_gray.shape, dtype=bool)
    # OCR-produced boxes always nest the tight ink extent in the padded repaint
    # extent. Intersect defensively so a hand-built caller cannot use an
    # out-of-bounds slice to make the padding disappear.
    inner_x0, inner_x1 = max(x0, ink_x0), min(x1, ink_x1)
    inner_y0, inner_y1 = max(y0, ink_y0), min(y1, ink_y1)
    if inner_x0 < inner_x1 and inner_y0 < inner_y1:
        padding[inner_y0 - y0:inner_y1 - y0, inner_x0 - x0:inner_x1 - x0] = False
    dark = repaint_gray <= 245
    if not np.any(dark & padding):
        return

    # Rasterization can place one antialiased edge pixel just beyond a
    # detector's half-open polygon. Permit a fringe pixel only when it is a
    # *direct* 8-neighbor of dark ink inside the OCR claim. Component-level
    # connectivity would let an arbitrarily long foreign stroke propagate
    # around the margin from a single touching point.
    import cv2
    directly_adjacent = cv2.dilate((dark & ~padding).astype(np.uint8),
                                   np.ones((3, 3), dtype=np.uint8), iterations=1).astype(bool)
    fringe = np.zeros(repaint_gray.shape, dtype=bool)
    fringe_x0, fringe_x1 = max(x0, ink_x0 - 1), min(x1, ink_x1 + 1)
    fringe_y0, fringe_y1 = max(y0, ink_y0 - 1), min(y1, ink_y1 + 1)
    fringe[fringe_y0 - y0:fringe_y1 - y0, fringe_x0 - x0:fringe_x1 - x0] = True
    permitted = fringe & directly_adjacent
    if np.any(dark & padding & ~permitted):
        raise PayloadError("A visual repaint padding region contains unrecognised source ink; no visual candidate was made.")


def _assert_ocr_line_has_raster_edge(source_gray: Any, line: dict[str, Any]) -> None:
    """Reject a source OCR line whose reported ink box is visually flat.

    OCR confidence is model output, not evidence that the source raster still
    contains a locatable text edge.  This small, fail-closed check validates
    only the latter for the already reported ink box. It cannot measure OCR
    completeness or certify readability.
    """
    import numpy as np

    x0, y0, x1, y1 = _line_ink_box(line)
    line_gray = source_gray[y0:y1, x0:x1]
    if line_gray.shape[0] < 2 or line_gray.shape[1] < 2:
        raise PayloadError("OCR line lacks measurable source-raster edge detail; inspect the source manually.")
    horizontal = np.abs(np.diff(line_gray, axis=1))
    vertical = np.abs(np.diff(line_gray, axis=0))
    horizontal_max = int(horizontal.max()) if horizontal.size else 0
    vertical_max = int(vertical.max()) if vertical.size else 0
    edge = max(horizontal_max, vertical_max)
    if edge < MIN_OCR_LINE_EDGE_DELTA:
        raise PayloadError("OCR line lacks measurable source-raster edge detail; inspect the source manually.")


def _assert_ocr_line_has_no_separate_ink_island(source_gray: Any, line: dict[str, Any]) -> None:
    """Reject one OCR box that spans visibly separate source-ink regions.

    A non-flat box is not necessarily tight. A same-engine OCR result can
    describe one value while its geometry also covers an unrecognised value;
    then no second OCR line exists for the repaint-neighbour guard to compare.
    A material blank run between substantial ink columns *or rows*, or a
    long thin rule-like ink stroke, is conservative evidence of ambiguity, so
    abstain rather than erase. This is a bounded geometry guard, not text
    recognition or an OCR-coverage claim.
    """
    import numpy as np

    x0, y0, x1, y1 = _line_ink_box(line)
    line_gray = source_gray[y0:y1, x0:x1]
    height, width = line_gray.shape
    dark = line_gray <= 245

    # Treat a *connected* long, thin horizontal/vertical component as geometry
    # ambiguity. A projection-only check can be bridged by a one- or two-pixel
    # rule. Component shape keeps ordinary tall glyph strokes and short `|`
    # punctuation from becoming rules, while a full-box width never dilutes the
    # decision. RapidOCR already requires OpenCV at runtime; use its bounded
    # in-memory connected-component primitive instead of guessing from a line
    # projection.
    import cv2
    component_count, _, stats, _ = cv2.connectedComponentsWithStats(
        dark.astype(np.uint8), connectivity=8)
    for index in range(1, component_count):
        _, _, component_width, component_height, _ = stats[index]
        if (component_width >= max(24, component_height * 12)
                and component_height <= max(2, height // 5)):
            raise PayloadError("OCR line has ambiguous rule-like source ink; inspect the source manually.")
        if (component_height >= max(24, component_width * 12)
                and component_width <= max(2, width // 5)):
            raise PayloadError("OCR line has ambiguous rule-like source ink; inspect the source manually.")

    # Substantial support avoids antialiasing/noise bridging a blank gap. An
    # uncertain raster abstains; this guard never tightens a repaint box.
    column_support = np.count_nonzero(dark, axis=0)
    active_columns = np.flatnonzero(column_support >= max(2, height // 8))
    horizontal_gap_limit = max(MIN_OCR_LINE_SEPARATE_INK_GAP, height)
    horizontal_gaps = np.diff(active_columns) - 1
    if horizontal_gaps.size and int(horizontal_gaps.max()) >= horizontal_gap_limit:
        raise PayloadError("OCR line spans separate source-ink regions; inspect the source manually.")
    # The horizontal projection alone misses two vertically stacked source
    # strings at the same x-position. Keep the row threshold small but bounded:
    # it must retain thin glyph strokes while rejecting only a material blank
    # band, never attempting to split or tighten the OCR claim.
    row_support = np.count_nonzero(dark, axis=1)
    active_rows = np.flatnonzero(row_support >= max(1, min(4, width // 20)))
    vertical_gap_limit = max(12, height // 3)
    vertical_gaps = np.diff(active_rows) - 1
    if vertical_gaps.size and int(vertical_gaps.max()) >= vertical_gap_limit:
        raise PayloadError("OCR line spans separate source-ink regions; inspect the source manually.")


@lru_cache(maxsize=1)
def _engine() -> Any:
    from rapidocr import RapidOCR

    return RapidOCR()


def _ocr_lines(image: Any, *, require_confidence: bool = True, validate_layout: bool = True) -> list[dict[str, Any]]:
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
        ink_box = (max(0, math.floor(min(xs))), max(0, math.floor(min(ys))),
                   min(image.width, math.ceil(max(xs))), min(image.height, math.ceil(max(ys))))
        bounds = (max(0, math.floor(min(xs)) - 5), max(0, math.floor(min(ys)) - 5),
                  min(image.width, math.ceil(max(xs)) + 5), min(image.height, math.ceil(max(ys)) + 5))
        if ink_box[2] <= ink_box[0] or ink_box[3] <= ink_box[1] or bounds[2] <= bounds[0] or bounds[3] <= bounds[1]:
            raise PayloadError("The demo OCR geometry is invalid.")
        lines.append({"text": text, "box": bounds, "ink_box": ink_box, "confidence": round(score, 4)})
    lines = sorted(lines, key=lambda line: (line["ink_box"][1], line["ink_box"][0]))
    if validate_layout:
        _assert_unambiguous_ocr_layout(lines)
        # A bounded full-page grayscale buffer is made once, then each guard
        # examines a small view of that buffer.  Do not reconvert the page per
        # OCR line: valid pages may contain up to MAX_OCR_LINES claims.
        source_gray = np.asarray(image.convert("L"), dtype=np.int16)
        for line in lines:
            _assert_ocr_line_has_raster_edge(source_gray, line)
            _assert_ocr_line_has_no_separate_ink_island(source_gray, line)
    return lines


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
                     coordinate_regions: dict[int, list[dict[str, Any]]] | None = None,
                     final_verifier: IndependentFinalOcrVerifier | None = None) -> dict[str, Any]:
    """Paint affected OCR lines; an independent final verifier is explicit opt-in."""
    public_pages = []
    candidate_images = []
    assigned = set()
    fallback_lines = 0
    visual_residuals = 0
    candidate_low_confidence_lines = 0
    final_pngs: list[bytes] = []
    final_sources: set[str] = set()
    coordinate_regions = coordinate_regions or {}
    for page in pages:
        source_image = page["image"]
        candidate = source_image.copy()
        source_gray = None
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
            _assert_repaint_is_isolated(line, page["lines"])
            # Only pages with a proposed repaint pay for grayscale conversion,
            # and every applied line on one page shares this source buffer.
            if source_gray is None:
                import numpy as np
                source_gray = np.asarray(source_image.convert("L"), dtype=np.int16)
            _assert_repaint_padding_is_source_free(source_gray, line)
            parts = []
            cursor = line["start"]
            for match in applied:
                parts.extend((line["text"][cursor - line["start"]:match["start"] - line["start"]],
                              match["replacement"]))
                cursor = match["end"]
                page_sources.add(match["source"])
            parts.append(line["text"][cursor - line["start"]:])
            fallback = _draw_line(candidate, line["box"], "".join(parts))
            if fallback:
                # A solid mark avoids corruption, but it is not a readable
                # replacement and must not be presented as a candidate.
                raise PayloadError("A replacement cannot fit its OCR line; no visual candidate was made.")
            fallback_lines += fallback
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
        # This OCR pass only detects residual source strings; it does not
        # drive a repaint or claim a reading order for the candidate.
        candidate_lines = _ocr_lines(candidate, require_confidence=False, validate_layout=False)
        candidate_low_confidence_lines += sum(line["confidence"] < 0.60 for line in candidate_lines)
        candidate_ocr = "\n".join(line["text"] for line in candidate_lines)
        for source in page_sources:
            if re.search(r"(?<!\w)" + re.escape(source) + r"(?!\w)", candidate_ocr, re.I):
                visual_residuals += 1
        source_png = _png_bytes(source_image)
        candidate_png = _png_bytes(candidate)
        final_pngs.append(candidate_png)
        final_sources.update(page_sources)
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
        if final_verifier is not None:
            # Verify pixels rerasterized from the exact returned PDF bytes.
            final_verifier.verify_pdf(generated, tuple(final_sources))
    elif final_verifier is not None:
        # Verify the exact PNG bytes placed in the response, after all drawing.
        final_verifier.verify_pngs(tuple(final_pngs), tuple(final_sources))
    return {"pages": public_pages, "fallback_lines": fallback_lines,
            "candidate_low_confidence_lines": candidate_low_confidence_lines,
            "self_ocr_residual_sources": visual_residuals, "pdf_raster_evidence": pdf_evidence,
            "candidate_pdf_base64": candidate_pdf_base64}
