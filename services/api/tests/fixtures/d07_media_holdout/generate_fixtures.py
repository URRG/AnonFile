"""Regenerate the tiny fictional D07 final-raster fixtures.

Run with the media test environment.  The PDF page is first rendered by
pypdfium2, then both generated PNG byte streams must be re-pinned in
manifest.json.  This is test-fixture provenance only, not a production render
or an OCR qualification workflow.
"""
from __future__ import annotations

from pathlib import Path

import pypdfium2 as pdfium
from reportlab.pdfgen.canvas import Canvas


HERE = Path(__file__).parent
def _render_pdf(source_name: str, output_name: str, marker: str) -> None:
    source = HERE / source_name
    canvas = Canvas(str(source), pagesize=(720, 160), invariant=1)
    canvas.setFont("Helvetica-Bold", 30)
    canvas.drawString(36, 82, marker)
    canvas.save()
    document = pdfium.PdfDocument(source.read_bytes())
    try:
        page = document[0]
        try:
            bitmap = page.render(scale=1.0, rev_byteorder=True)
            try:
                image = bitmap.to_pil().convert("RGB")
                image.save(HERE / output_name, format="PNG", optimize=False)
            finally:
                bitmap.close()
        finally:
            page.close()
    finally:
        document.close()


if __name__ == "__main__":
    _render_pdf("pdf-page-1-source.pdf", "pdf-page-1.png", "D07-FINAL-ALPHA-91")
    _render_pdf("image-1-source.pdf", "image-1.png", "D07-FINAL-BRAVO-27")
