"""Synthetic raster candidate construction never copies source PDF objects."""
import base64
import hashlib
from io import BytesIO

from PIL import Image
from pypdf import PdfReader
import pytest

from app.contracts import PayloadError
from app.media_preview import _image_pdf, _verify_pdf_text_layer, render_candidate


def test_raster_pdf_has_only_new_image_content_and_no_extracted_text():
    page = Image.new("RGB", (320, 180), "white")
    generated = _image_pdf([page])
    reader = PdfReader(BytesIO(generated), strict=True)
    assert len(reader.pages) == 1
    assert reader.pages[0].extract_text() == ""
    assert not reader.trailer["/Root"].get("/AcroForm")
    assert not reader.trailer["/Root"].get("/Names")
    assert b"/Subtype /Image" in generated


def test_render_candidate_carries_only_bounded_rebuilt_pdf_bytes(monkeypatch):
    monkeypatch.setattr("app.media_preview._ocr_lines", lambda _: [])
    image = Image.new("RGB", (320, 180), "white")
    page = {"number": 1, "image": image, "lines": [
        {"text": "Maya Patel", "box": (10, 10, 200, 40), "start": 0, "end": 10},
    ]}
    match = {"start": 0, "end": 10, "source": "Maya Patel", "replacement": "John Singh", "applied": True}

    preview = render_candidate([page], [match], "pdf")
    encoded = preview["candidate_pdf_base64"]
    candidate = base64.b64decode(encoded, validate=True)
    assert candidate.startswith(b"%PDF-")
    assert len(candidate) == preview["pdf_raster_evidence"]["bytes"]
    assert hashlib.sha256(candidate).hexdigest() == preview["pdf_raster_evidence"]["sha256"]
    assert PdfReader(BytesIO(candidate), strict=True).pages[0].extract_text() == ""

    image_preview = render_candidate([page], [match], "image")
    assert image_preview["candidate_pdf_base64"] is None
    assert image_preview["pdf_raster_evidence"] is None


def test_pdf_text_layer_check_requires_every_sensitive_occurrence():
    native = "Call +1 415 555 0148. Call +1 415 555 0148 again."
    one_phone = [{"text": "Call +1 415 555 0148."}]
    with pytest.raises(PayloadError, match="PDF text-layer and OCR disagree"):
        _verify_pdf_text_layer(native, one_phone)
    _verify_pdf_text_layer(native, one_phone * 2)


def test_pdf_text_layer_check_rejects_explicit_name_missing_from_ocr():
    native = "Name: Maya Patel\nTitle: Incident Lead\nCompany: Harborline Systems"
    with pytest.raises(PayloadError, match="PDF text-layer and OCR disagree"):
        _verify_pdf_text_layer(native, [{"text": "Title: Incident Lead"},
                                        {"text": "Company: Harborline Systems"}])
    _verify_pdf_text_layer(native, [{"text": "Name: Maya Patel"},
                                    {"text": "Title: Incident Lead"},
                                    {"text": "Company: Harborline Systems"}])


def test_pdf_text_layer_check_rejects_missing_contextual_identifier_or_url():
    native = "Employee ID: HS-EMP-1042\nReview link: https://github.example.test/private"
    with pytest.raises(PayloadError, match="PDF text-layer and OCR disagree"):
        _verify_pdf_text_layer(native, [{"text": "Employee ID: HS-EMP-1042"}])
    with pytest.raises(PayloadError, match="PDF text-layer and OCR disagree"):
        _verify_pdf_text_layer(native, [{"text": "Review link: https://github.example.test/private"}])
