"""Synthetic raster candidate construction never copies source PDF objects."""
import base64
import hashlib
from io import BytesIO

from PIL import Image
from PIL import ImageDraw, ImageFilter, ImageFont
from pypdf import PdfReader
import pytest

from app.contracts import PayloadError
from app.media_preview import _image_pdf, _ocr_lines, _verify_pdf_text_layer, render_candidate


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
    monkeypatch.setattr("app.media_preview._ocr_lines", lambda _, **kwargs: [])
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


def test_render_candidate_calls_opt_in_verifier_with_exact_final_artifact_bytes(monkeypatch):
    """The optional independent path sees response bytes, never working images."""
    monkeypatch.setattr("app.media_preview._ocr_lines", lambda _, **kwargs: [])
    image = Image.new("RGB", (320, 180), "white")
    page = {"number": 1, "image": image, "lines": [
        {"text": "Maya Patel", "box": (10, 10, 200, 40), "start": 0, "end": 10},
    ]}
    match = {"start": 0, "end": 10, "source": "Maya Patel", "replacement": "John Singh", "applied": True}

    class Verifier:
        pngs = None
        pdf = None
        values = None
        def verify_pngs(self, pngs, values):
            self.pngs, self.values = tuple(pngs), tuple(values)
        def verify_pdf(self, pdf, values):
            self.pdf, self.values = pdf, tuple(values)

    image_verifier = Verifier()
    preview = render_candidate([page], [match], "image", final_verifier=image_verifier)
    assert image_verifier.pngs == (base64.b64decode(preview["pages"][0]["candidate_png_base64"]),)
    assert image_verifier.values == ("Maya Patel",)

    pdf_verifier = Verifier()
    preview = render_candidate([page], [match], "pdf", final_verifier=pdf_verifier)
    assert pdf_verifier.pdf == base64.b64decode(preview["candidate_pdf_base64"])
    assert pdf_verifier.values == ("Maya Patel",)


def test_candidate_low_confidence_is_reported_without_weakening_input_ocr(monkeypatch):
    from types import SimpleNamespace
    from app import media_preview

    image = Image.new("RGB", (320, 180), "white")
    ImageDraw.Draw(image).text((10, 10), "John Singh", fill="black")
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=["John Singh"], boxes=[[(10, 10), (120, 10), (120, 35), (10, 35)]], scores=[0.55]))
    with pytest.raises(PayloadError, match="confidence is too low"):
        media_preview._ocr_lines(image)
    assert media_preview._ocr_lines(image, require_confidence=False)[0]["confidence"] == 0.55
    page = {"number": 1, "image": image, "lines": [
        {"text": "Maya Patel", "box": (10, 10, 200, 40), "start": 0, "end": 10},
    ]}
    match = {"start": 0, "end": 10, "source": "Maya Patel", "replacement": "John Singh", "applied": True}
    preview = render_candidate([page], [match], "image")
    assert preview["candidate_low_confidence_lines"] == 1
    assert preview["self_ocr_residual_sources"] == 0


def test_ocr_geometry_accepts_unambiguous_single_column(monkeypatch):
    from types import SimpleNamespace
    from app import media_preview

    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=["first confidential line", "second confidential line", "third confidential line"],
        boxes=[[(20, 10), (220, 10), (220, 25), (20, 25)],
               [(20, 45), (220, 45), (220, 60), (20, 60)],
               [(20, 80), (220, 80), (220, 95), (20, 95)]],
        scores=[0.99, 0.99, 0.99]))

    image = Image.new("RGB", (320, 180), "white")
    ImageDraw.Draw(image).text((20, 10), "first confidential line", fill="black")
    ImageDraw.Draw(image).text((20, 45), "second confidential line", fill="black")
    ImageDraw.Draw(image).text((20, 80), "third confidential line", fill="black")
    lines = _ocr_lines(image)
    assert [line["text"] for line in lines] == ["first confidential line", "second confidential line", "third confidential line"]


def test_ocr_line_without_measurable_raster_edge_abstains_on_catastrophic_blur(monkeypatch):
    from types import SimpleNamespace
    from app import media_preview

    image = Image.new("RGB", (320, 120), "white")
    font = ImageFont.load_default()
    ImageDraw.Draw(image).text((20, 35), "Maya Patel", font=font, fill="black")
    box = [(20, 30), (120, 30), (120, 55), (20, 55)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=["Maya Patel"], boxes=[box], scores=[0.99]))
    assert _ocr_lines(image)[0]["text"] == "Maya Patel"
    with pytest.raises(PayloadError, match="lacks measurable source-raster edge detail") as error:
        _ocr_lines(image.filter(ImageFilter.GaussianBlur(radius=12)))
    assert "Maya Patel" not in str(error.value)


def test_ocr_edge_guard_converts_the_source_once_for_many_claimed_lines(monkeypatch):
    from types import SimpleNamespace
    from app import media_preview

    image = Image.new("RGB", (320, 280), "white")
    texts = [f"fictional line {index}" for index in range(5)]
    boxes = []
    draw = ImageDraw.Draw(image)
    for index, text in enumerate(texts):
        y = 10 + index * 50
        draw.text((20, y), text, fill="black")
        boxes.append([(20, y), (220, y), (220, y + 25), (20, y + 25)])
    calls = 0
    original_convert = image.convert

    def count_grayscale_conversion(mode, *args, **kwargs):
        nonlocal calls
        if mode == "L":
            calls += 1
        return original_convert(mode, *args, **kwargs)

    monkeypatch.setattr(image, "convert", count_grayscale_conversion)
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=texts, boxes=boxes, scores=[0.99] * len(texts)))
    assert [line["text"] for line in _ocr_lines(image)] == texts
    assert calls == 1


def test_ocr_edge_guard_does_not_certify_text_from_a_graphic_edge(monkeypatch):
    """A visible rule satisfies this narrow raster sanity check, not OCR proof."""
    from types import SimpleNamespace
    from app import media_preview

    image = Image.new("RGB", (320, 120), "white")
    ImageDraw.Draw(image).rectangle((25, 35, 115, 50), fill="black")
    box = [(15, 25), (125, 25), (125, 60), (15, 60)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=["fictional OCR claim"], boxes=[box], scores=[0.99]))
    # A graphic edge is intentionally accepted here: the guard is only a
    # catastrophic-flat-raster rejection and must not be presented as text,
    # OCR-coverage, or semantic-source validation.
    assert _ocr_lines(image)[0]["text"] == "fictional OCR claim"


def test_ocr_geometry_rejects_one_overbroad_line_that_hides_adjacent_source_ink(monkeypatch):
    """A same-engine line cannot erase an unrecognised neighbouring value."""
    from types import SimpleNamespace
    from app import media_preview

    source = "Maya Patel"
    hidden = "ACCOUNT 4932"
    image = Image.new("RGB", (360, 120), "white")
    draw = ImageDraw.Draw(image)
    draw.text((20, 40), source, fill="black")
    # The old edge check passed: both regions have high-contrast edges and no
    # second OCR line exists for the repaint-neighbour guard.
    draw.text((180, 40), hidden, fill="black")
    box = [(15, 30), (330, 30), (330, 65), (15, 65)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[source], boxes=[box], scores=[0.99]))

    with pytest.raises(PayloadError, match="separate source-ink regions") as error:
        _ocr_lines(image)
    assert source not in str(error.value)
    assert hidden not in str(error.value)


def test_ocr_geometry_rejects_two_pixel_rule_between_two_source_regions(monkeypatch):
    """A two-pixel horizontal rule must not bridge separate ink components."""
    from types import SimpleNamespace
    from app import media_preview

    source = "Maya"
    hidden = "4932"
    image = Image.new("RGB", (260, 90), "white")
    draw = ImageDraw.Draw(image)
    # Compact blocks model two same-baseline source strings in an eight-pixel
    # OCR box. A two-pixel rule spans their otherwise blank horizontal gap.
    draw.rectangle((20, 35, 65, 40), fill="black")
    draw.rectangle((175, 35, 220, 40), fill="black")
    draw.line((68, 43, 172, 43), fill="black", width=2)
    box = [(15, 35), (225, 35), (225, 45), (15, 45)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[source], boxes=[box], scores=[0.99]))

    with pytest.raises(PayloadError, match="ambiguous rule-like source ink") as error:
        _ocr_lines(image)
    assert source not in str(error.value)
    assert hidden not in str(error.value)


def test_ocr_geometry_rejects_wide_box_with_material_separate_ink_regions(monkeypatch):
    """A wide OCR box cannot weaken an 80-pixel source-region gap."""
    from types import SimpleNamespace
    from app import media_preview

    source = "Maya"
    hidden = "4932"
    image = Image.new("RGB", (2500, 100), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((40, 40, 110, 58), fill="black")
    draw.rectangle((191, 40, 261, 58), fill="black")
    box = [(20, 30), (2420, 30), (2420, 65), (20, 65)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[source], boxes=[box], scores=[0.99]))

    with pytest.raises(PayloadError, match="separate source-ink regions") as error:
        _ocr_lines(image)
    assert source not in str(error.value)
    assert hidden not in str(error.value)


def test_ocr_geometry_rejects_two_pixel_vertical_rule_between_stacked_regions(monkeypatch):
    """A two-pixel vertical rule must not bridge stacked source regions."""
    from types import SimpleNamespace
    from app import media_preview

    source = "Maya"
    hidden = "4932"
    image = Image.new("RGB", (160, 180), "white")
    draw = ImageDraw.Draw(image)
    draw.rectangle((55, 20, 100, 45), fill="black")
    draw.rectangle((55, 115, 100, 140), fill="black")
    draw.line((78, 50, 78, 110), fill="black", width=2)
    box = [(45, 15), (110, 15), (110, 145), (45, 145)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[source], boxes=[box], scores=[0.99]))

    with pytest.raises(PayloadError, match="ambiguous rule-like source ink") as error:
        _ocr_lines(image)
    assert source not in str(error.value)
    assert hidden not in str(error.value)


def test_ocr_geometry_rejects_one_overbroad_line_that_hides_stacked_source_ink(monkeypatch):
    """A vertical ink island must not bypass the horizontal-gap guard."""
    from types import SimpleNamespace
    from app import media_preview

    source = "Maya Patel"
    hidden = "ACCOUNT 4932"
    image = Image.new("RGB", (260, 130), "white")
    draw = ImageDraw.Draw(image)
    draw.text((25, 25), source, fill="black")
    draw.text((25, 70), hidden, fill="black")
    # One same-engine OCR claim spans both aligned strings. There is no
    # horizontal gap between their ink extents, so only 2D geometry catches it.
    box = [(20, 15), (180, 15), (180, 90), (20, 90)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[source], boxes=[box], scores=[0.99]))

    with pytest.raises(PayloadError, match="separate source-ink regions") as error:
        _ocr_lines(image)
    assert source not in str(error.value)
    assert hidden not in str(error.value)


def test_ocr_geometry_accepts_widely_tracked_single_line_without_rule(monkeypatch):
    """Tracking alone is not mistaken for an unrecognised second region."""
    from types import SimpleNamespace
    from app import media_preview

    image = Image.new("RGB", (220, 100), "white")
    draw = ImageDraw.Draw(image)
    for index, character in enumerate("Maya"):
        draw.text((20 + index * 28, 40), character, fill="black")
    box = [(15, 30), (125, 30), (125, 65), (15, 65)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=["Maya"], boxes=[box], scores=[0.99]))

    assert _ocr_lines(image)[0]["text"] == "Maya"


def test_ocr_geometry_accepts_one_tight_line_with_ordinary_word_spacing(monkeypatch):
    from types import SimpleNamespace
    from app import media_preview

    text = "Maya Patel"
    image = Image.new("RGB", (240, 100), "white")
    ImageDraw.Draw(image).text((20, 40), text, fill="black")
    box = [(15, 30), (110, 30), (110, 65), (15, 65)]
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[text], boxes=[box], scores=[0.99]))

    assert _ocr_lines(image)[0]["text"] == text


@pytest.mark.parametrize("boxes", [
    # Adjacent cells / two columns share a vertical band. Their OCR order is
    # not proof of the intended reading order.
    [[(10, 20), (100, 20), (100, 40), (10, 40)],
     [(160, 20), (280, 20), (280, 40), (160, 40)]],
    # A third cell must not make an ambiguous row look safe by changing its count.
    [[(10, 20), (100, 20), (100, 40), (10, 40)],
     [(115, 20), (205, 20), (205, 40), (115, 40)],
     [(220, 20), (310, 20), (310, 40), (220, 40)]],
    # A narrow count cell is still a table cell; width is no reason to guess.
    [[(10, 20), (38, 20), (38, 40), (10, 40)],
     [(60, 20), (170, 20), (170, 40), (60, 40)],
     [(190, 20), (280, 20), (280, 40), (190, 40)]],
    # Columns can be vertically staggered, so matching baselines are not a
    # safe prerequisite for rejecting their invented interleaved transcript.
    [[(10, 20), (100, 20), (100, 40), (10, 40)],
     [(160, 35), (260, 35), (260, 55), (160, 55)],
     [(10, 50), (100, 50), (100, 70), (10, 70)],
     [(160, 65), (260, 65), (260, 85), (160, 85)]],
    # OCR boxes that physically overlap cannot be safely repainted separately.
    [[(10, 20), (180, 20), (180, 45), (10, 45)],
     [(120, 35), (280, 35), (280, 60), (120, 60)]],
])
def test_ocr_geometry_abstains_on_ambiguous_layout_without_source_leak(monkeypatch, boxes):
    from types import SimpleNamespace
    from app import media_preview

    secret = "Maya Patel private value"
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[secret, "ordinary adjacent value", "third cell", "fourth cell"][:len(boxes)], boxes=boxes,
        scores=[0.99] * len(boxes)))

    with pytest.raises(PayloadError, match="OCR layout is ambiguous") as error:
        _ocr_lines(Image.new("RGB", (320, 180), "white"))
    assert secret not in str(error.value)


def test_render_candidate_abstains_when_repaint_touches_unaffected_neighbor(monkeypatch):
    from app import media_preview

    monkeypatch.setattr(media_preview, "_ocr_lines", lambda _, **kwargs: [])
    image = Image.new("RGB", (320, 180), "white")
    secret = "Maya Patel"
    page = {"number": 1, "image": image, "lines": [
        {"text": secret, "box": (10, 10, 200, 40), "ink_box": (15, 15, 195, 35), "start": 0, "end": len(secret)},
        # Tight OCR boxes do not overlap: only the actual padded repaint would
        # touch the neighbour. The guard must inspect that erased rectangle.
        {"text": "unaffected neighbour", "box": (10, 42, 200, 65), "ink_box": (15, 38, 195, 60),
         "start": len(secret) + 1, "end": len(secret) + 20},
    ]}
    match = {"start": 0, "end": len(secret), "source": secret, "replacement": "John Singh", "applied": True}

    with pytest.raises(PayloadError, match="visual repaint region touches") as error:
        render_candidate([page], [match], "image")
    assert secret not in str(error.value)


def test_render_candidate_abstains_on_unrecognised_dark_ink_in_repaint_padding(monkeypatch):
    """One OCR line cannot authorize erasing an unseen glyph in its margin."""
    from app import media_preview

    monkeypatch.setattr(media_preview, "_ocr_lines", lambda _, **kwargs: [])
    image = Image.new("RGB", (180, 80), "white")
    # This deliberately lies outside the tight OCR claim but inside the
    # five-pixel padded rectangle that _draw_line would erase.
    ImageDraw.Draw(image).text((11, 24), "?", fill="black")
    secret = "Maya Patel"
    page = {"number": 1, "image": image, "lines": [
        {"text": secret, "box": (10, 10, 150, 55), "ink_box": (15, 15, 145, 50),
         "start": 0, "end": len(secret)},
    ]}
    match = {"start": 0, "end": len(secret), "source": secret, "replacement": "John Singh", "applied": True}

    with pytest.raises(PayloadError, match="padding region contains unrecognised source ink") as error:
        render_candidate([page], [match], "image")
    assert secret not in str(error.value)


def test_render_candidate_allows_blank_repaint_padding_and_grayscales_once(monkeypatch):
    """A source-free padding ring is safe and one affected page converts once."""
    from app import media_preview

    monkeypatch.setattr(media_preview, "_ocr_lines", lambda _, **kwargs: [])
    image = Image.new("RGB", (180, 130), "white")
    original_convert = image.convert
    conversions = 0

    def count_grayscale_conversion(mode, *args, **kwargs):
        nonlocal conversions
        if mode == "L":
            conversions += 1
        return original_convert(mode, *args, **kwargs)

    monkeypatch.setattr(image, "convert", count_grayscale_conversion)
    secret = "Maya Patel"
    other = "Ira Rao"
    # Dark source pixels in the claimed ink regions remain permitted; only the
    # padding ring must be source-free.
    draw = ImageDraw.Draw(image)
    draw.text((30, 25), secret, fill="black")
    draw.text((30, 75), other, fill="black")
    # This models a one-pixel antialiased descender just outside the detector's
    # half-open polygon. It is connected to claimed source ink, not a second
    # glyph in the repaint ring.
    draw.line((70, 49, 70, 50), fill="black")
    page = {"number": 1, "image": image, "lines": [
        {"text": secret, "box": (10, 10, 150, 55), "ink_box": (15, 15, 145, 50),
         "start": 0, "end": len(secret)},
        {"text": other, "box": (10, 60, 150, 105), "ink_box": (15, 65, 145, 100),
         "start": len(secret) + 1, "end": len(secret) + 1 + len(other)},
    ]}
    matches = [
        {"start": 0, "end": len(secret), "source": secret, "replacement": "John Singh", "applied": True},
        {"start": len(secret) + 1, "end": len(secret) + 1 + len(other), "source": other,
         "replacement": "Eve Fox", "applied": True},
    ]

    preview = render_candidate([page], matches, "image")
    assert preview["pages"][0]["ocr_lines"] == 2
    assert conversions == 1


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
