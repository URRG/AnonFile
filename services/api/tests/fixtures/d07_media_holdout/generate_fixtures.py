"""Regenerate the tiny fictional D07 final-raster fixtures.

Run with the media test environment.  The PDF page is first rendered by
pypdfium2, then both generated PNG byte streams must be re-pinned in
manifest.json.  This is test-fixture provenance only, not a production render
or an OCR qualification workflow.
"""
from __future__ import annotations

from pathlib import Path

import pypdfium2 as pdfium
from PIL import Image, ImageDraw, ImageFont
from reportlab.pdfgen.canvas import Canvas


HERE = Path(__file__).parent
def _font(size: int) -> ImageFont.ImageFont:
    return ImageFont.load_default(size=size)


def _pdf_page() -> None:
    source = HERE / "pdf-page-1-source.pdf"
    canvas = Canvas(str(source), pagesize=(720, 160), invariant=1)
    canvas.setFont("Helvetica-Bold", 30)
    canvas.drawString(36, 82, "D07-FINAL-ALPHA-91")
    canvas.save()
    document = pdfium.PdfDocument(source.read_bytes())
    try:
        page = document[0]
        try:
            bitmap = page.render(scale=1.0, rev_byteorder=True)
            try:
                image = bitmap.to_pil().convert("RGB")
                image.save(HERE / "pdf-page-1.png", format="PNG", optimize=False)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()


def _image() -> None:
    image = Image.new("RGB", (720, 160), "white")
    ImageDraw.Draw(image).text((36, 55), "D07-FINAL-BRAVO-27", fill="black", font=_font(30))
    image.save(HERE / "image-1.png", format="PNG", optimize=False)


if __name__ == "__main__":
    _pdf_page()
    _image()
