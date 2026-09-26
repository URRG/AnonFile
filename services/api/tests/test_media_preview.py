"""Synthetic raster candidate construction never copies source PDF objects."""
from io import BytesIO

from PIL import Image
from pypdf import PdfReader

from app.media_preview import _image_pdf


def test_raster_pdf_has_only_new_image_content_and_no_extracted_text():
    page = Image.new("RGB", (320, 180), "white")
    generated = _image_pdf([page])
    reader = PdfReader(BytesIO(generated), strict=True)
    assert len(reader.pages) == 1
    assert reader.pages[0].extract_text() == ""
    assert not reader.trailer["/Root"].get("/AcroForm")
    assert not reader.trailer["/Root"].get("/Names")
    assert b"/Subtype /Image" in generated
