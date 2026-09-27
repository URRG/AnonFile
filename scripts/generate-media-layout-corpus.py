"""Create a small, deterministic, entirely fictional D05 media-layout corpus.

The corpus is generated at test time (or with ``python scripts/generate-media-
layout-corpus.py --output <directory>``), so repository history contains no
binary fixtures.  It is deliberately an adversarial *layout* corpus, not an
OCR accuracy benchmark and not representative customer material.
"""
from __future__ import annotations

import argparse
import json
from io import BytesIO
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFilter, ImageFont
from reportlab.pdfgen import canvas
import reportlab


def _fonts() -> tuple[str, str]:
    base = Path(reportlab.__file__).parent / "fonts"
    return str(base / "Vera.ttf"), str(base / "VeraBd.ttf")


def _pdf(path: Path, draw: Any, *, acroform: bool = False) -> None:
    stream = BytesIO()
    page = canvas.Canvas(stream, pagesize=(612, 792), invariant=1)
    page.setTitle("Fictional D05 layout corpus")
    draw(page)
    if acroform:
        page.acroForm.textfield(name="fictional_contact", x=72, y=600, width=240, height=22,
                                value="Maya Patel", forceBorder=True)
    page.save()
    path.write_bytes(stream.getvalue())


def _page_heading(page: Any, title: str) -> None:
    page.setFillColorRGB(0.06, 0.16, 0.28)
    page.rect(0, 744, 612, 48, fill=1, stroke=0)
    page.setFillColorRGB(1, 1, 1)
    page.setFont("Helvetica-Bold", 17)
    page.drawString(48, 762, title)
    page.setFillColorRGB(0.05, 0.10, 0.16)


def build_corpus(output: Path) -> dict[str, dict[str, Any]]:
    """Write corpus files and return their intentional, stable expectations."""
    output.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, dict[str, Any]] = {}

    def single(page: Any) -> None:
        _page_heading(page, "FICTIONAL SINGLE-COLUMN NOTICE")
        page.setFont("Helvetica", 15)
        for y, line in ((690, "Public library schedule"), (654, "Monday through Friday: 09:00 to 17:00"),
                        (618, "All names and events in this corpus are invented.")):
            page.drawString(72, y, line)
    _pdf(output / "single-column.pdf", single)
    manifest["single-column.pdf"] = {"kind": "pdf", "expected": "accept", "layout": "single_column"}

    def columns(page: Any) -> None:
        _page_heading(page, "FICTIONAL TWO-COLUMN BULLETIN")
        page.setFont("Helvetica", 13)
        for index, text in enumerate(("West archive opens at nine.", "West archive closes at five.", "West notes are fictional.")):
            page.drawString(54, 690 - index * 32, text)
        for index, text in enumerate(("East archive opens at ten.", "East archive closes at six.", "East notes are fictional.")):
            page.drawString(330, 690 - index * 32, text)
    _pdf(output / "two-column.pdf", columns)
    manifest["two-column.pdf"] = {"kind": "pdf", "expected": "accept_or_abstain", "layout": "two_column"}

    def table(page: Any) -> None:
        _page_heading(page, "FICTIONAL INVENTORY TABLE")
        x, y, width, row = 64, 660, 470, 38
        page.setFont("Helvetica-Bold", 12)
        for offset, value in ((10, "Item"), (190, "Shelf"), (335, "Count")):
            page.drawString(x + offset, y + 13, value)
        page.setFont("Helvetica", 12)
        rows = (("Atlas", "North", "4"), ("Beacon", "South", "7"), ("Comet", "West", "2"))
        for index, values in enumerate(rows, 1):
            for offset, value in zip((10, 190, 335), values):
                page.drawString(x + offset, y - index * row + 13, value)
        page.setStrokeColorRGB(0.1, 0.16, 0.22)
        for n in range(5): page.line(x, y - n * row, x + width, y - n * row)
        for column in (x, x + 170, x + 315, x + width): page.line(column, y, column, y - 4 * row)
    _pdf(output / "table.pdf", table)
    manifest["table.pdf"] = {"kind": "pdf", "expected": "accept_or_abstain", "layout": "ruled_table", "rows": 4, "columns": 3}

    def static_form(page: Any) -> None:
        _page_heading(page, "FICTIONAL STATIC FORM")
        page.setFont("Helvetica", 13)
        for y, label, value in ((680, "Program:", "Orion"), (630, "Reference:", "DEMO-104"), (580, "Status:", "Example only")):
            page.drawString(72, y, label); page.rect(180, y - 7, 270, 24, fill=0, stroke=1); page.drawString(190, y, value)
    _pdf(output / "static-form.pdf", static_form)
    manifest["static-form.pdf"] = {"kind": "pdf", "expected": "accept_or_abstain", "layout": "static_form"}

    def acroform(page: Any) -> None:
        _page_heading(page, "FICTIONAL ACROFORM")
        page.setFont("Helvetica", 13); page.drawString(72, 650, "Contact (interactive field below):")
    _pdf(output / "acroform.pdf", acroform, acroform=True)
    manifest["acroform.pdf"] = {"kind": "pdf", "expected": "abstain", "reason": "interactive_pdf"}

    regular, bold = _fonts()
    screenshot = Image.new("RGB", (960, 540), (244, 247, 250))
    draw = ImageDraw.Draw(screenshot)
    draw.rectangle((0, 0, 959, 76), fill=(20, 49, 78))
    draw.text((32, 20), "FICTIONAL STATUS SCREEN", font=ImageFont.truetype(bold, 28), fill="white")
    draw.rounded_rectangle((45, 118, 915, 450), radius=12, fill="white", outline=(172, 188, 202), width=2)
    for y, text in ((155, "Example service status"), (220, "North region: available"), (285, "South region: available"),
                    (350, "Name: Maya Patel"), (405, "No real account information")):
        draw.text((82, y), text, font=ImageFont.truetype(regular, 26), fill=(22, 47, 67))
    screenshot.save(output / "screenshot.png", format="PNG", optimize=True)
    manifest["screenshot.png"] = {"kind": "png", "expected": "accept_or_abstain", "layout": "screenshot"}

    scan = Image.new("RGB", (960, 540), (220, 220, 220))
    scan_draw = ImageDraw.Draw(scan)
    faint = (185, 185, 185)
    for y, text in ((110, "FICTIONAL FAINT SCAN"), (190, "Maya Patel"), (270, "Example archival record")):
        scan_draw.text((90, y), text, font=ImageFont.truetype(regular, 32), fill=faint)
    scan.save(output / "blurred-low-contrast-scan.png", format="PNG", optimize=True)
    manifest["blurred-low-contrast-scan.png"] = {"kind": "png", "expected": "abstain", "reason": "low_confidence_or_no_text"}

    # Keep this distinct from the faint scan: it begins as a high-contrast,
    # fictional label, but the committed construction deliberately destroys
    # its local edge detail. A provider that nevertheless returns a confident
    # claim must not authorize a visual candidate.
    blur_claim = {"text": "Maya Patel", "box": [35, 42, 350, 140]}
    blurred = Image.new("RGB", (480, 180), (244, 244, 244))
    blurred_draw = ImageDraw.Draw(blurred)
    blurred_draw.text((55, 62), blur_claim["text"], font=ImageFont.truetype(bold, 38), fill=(20, 20, 20))
    blurred = blurred.filter(ImageFilter.GaussianBlur(radius=24))
    blurred.save(output / "catastrophic-blur-claim.png", format="PNG", optimize=True)
    manifest["catastrophic-blur-claim.png"] = {
        "kind": "png", "expected": "abstain", "reason": "no_measurable_raster_edge", "claim": blur_claim,
    }

    # These two small raster cases model distinct failure boundaries without
    # relying on OCR model output: a repaint overlapping an unprocessed line,
    # and two materially overlapping OCR claims. All labels are fictional.
    neighbor_lines = [
        {"text": "Maya Patel", "draw": [55, 62], "box": [40, 50, 360, 110], "ink_box": [55, 62, 240, 96]},
        {"text": "Example neighbor", "draw": [55, 108], "box": [50, 100, 350, 150], "ink_box": [55, 108, 330, 142]},
    ]
    neighbor = Image.new("RGB", (420, 190), "white")
    neighbor_draw = ImageDraw.Draw(neighbor)
    for line in neighbor_lines:
        neighbor_draw.text(tuple(line["draw"]), line["text"], font=ImageFont.truetype(regular, 28), fill=(22, 47, 67))
    neighbor.save(output / "unprocessed-neighbor.png", format="PNG", optimize=True)
    manifest["unprocessed-neighbor.png"] = {
        "kind": "png", "expected": "abstain", "reason": "repaint_touches_unprocessed_ocr_ink", "lines": neighbor_lines,
    }

    overlap_claims = [
        {"text": "Fictional left", "draw": [55, 74], "box": [45, 60, 260, 120], "source_ink_box": [55, 74, 245, 112]},
        {"text": "fictional right", "draw": [150, 90], "box": [150, 82, 375, 142], "source_ink_box": [150, 90, 370, 130]},
    ]
    overlap = Image.new("RGB", (420, 190), "white")
    overlap_draw = ImageDraw.Draw(overlap)
    for claim in overlap_claims:
        overlap_draw.text(tuple(claim["draw"]), claim["text"], font=ImageFont.truetype(regular, 28), fill=(22, 47, 67))
    overlap.save(output / "material-ocr-overlap.png", format="PNG", optimize=True)
    manifest["material-ocr-overlap.png"] = {
        "kind": "png", "expected": "abstain", "reason": "ambiguous_material_ocr_overlap", "claims": overlap_claims,
    }

    rotated = Image.new("RGB", (280, 520), "white")
    rdraw = ImageDraw.Draw(rotated)
    rdraw.text((25, 50), "FICTIONAL", font=ImageFont.truetype(bold, 31), fill="black")
    rdraw.text((25, 120), "ROTATED IMAGE", font=ImageFont.truetype(regular, 25), fill="black")
    exif = Image.Exif(); exif[274] = 6
    rotated.save(output / "exif-rotated.jpg", format="JPEG", quality=92, exif=exif)
    manifest["exif-rotated.jpg"] = {"kind": "jpeg", "expected": "accept_or_abstain", "layout": "exif_rotate", "display_size": [520, 280]}

    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".media-layout-corpus"))
    args = parser.parse_args()
    build_corpus(args.output)
    print(f"Wrote fictional D05 corpus to {args.output}")
