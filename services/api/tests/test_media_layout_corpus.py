"""D05 corpus checks: fictional layout fixtures and safe raster-preview invariants.

These deliberately avoid asserting an OCR engine's exact transcript.  OCR model
versions and CPU providers can vary; the contract here is bounded acceptance or
an explicit abstention, never silent layout invention.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace

import numpy as np
from PIL import Image, ImageDraw, ImageFont
from pypdf import PdfReader
import pytest

from app.contracts import PayloadError
from app import media_preview


REPO = Path(__file__).resolve().parents[3]
GENERATOR = REPO / "scripts" / "generate-media-layout-corpus.py"


def _generator_module():
    spec = importlib.util.spec_from_file_location("media_layout_corpus", GENERATOR)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture()
def corpus(tmp_path):
    module = _generator_module()
    output = tmp_path / "fictional-layout-corpus"
    manifest = module.build_corpus(output)
    assert json.loads((output / "manifest.json").read_text(encoding="utf-8")) == manifest
    return output, manifest


def _assert_declared_ink(image, box):
    """Require a declared source-text region to contain substantial dark ink."""
    x0, y0, x1, y1 = box
    region = np.asarray(image.convert("L"), dtype=np.int16)[y0:y1, x0:x1]
    assert region.size and np.count_nonzero(region <= 245) >= 40, "declared source geometry has no matching raster ink"


def test_corpus_is_complete_fictional_and_deterministically_described(corpus):
    output, manifest = corpus
    assert set(manifest) == {
        "single-column.pdf", "two-column.pdf", "table.pdf", "static-form.pdf", "acroform.pdf",
        "screenshot.png", "blurred-low-contrast-scan.png", "catastrophic-blur-claim.png",
        "unprocessed-neighbor.png", "material-ocr-overlap.png", "exif-rotated.jpg",
    }
    assert all((output / name).is_file() and (output / name).stat().st_size > 100 for name in manifest)
    assert manifest["table.pdf"]["rows"] == 4
    assert manifest["table.pdf"]["columns"] == 3
    # The generated source has one intentional interactive boundary case only.
    assert not PdfReader(output / "static-form.pdf", strict=True).trailer["/Root"].get("/AcroForm")
    assert PdfReader(output / "acroform.pdf", strict=True).trailer["/Root"].get("/AcroForm")


def test_corpus_build_is_byte_reproducible(corpus, tmp_path):
    """Two independent generator calls must yield the same fictional bytes."""
    output, manifest = corpus
    second = tmp_path / "fictional-layout-corpus-second-build"
    second_manifest = _generator_module().build_corpus(second)
    assert second_manifest == manifest
    for filename in [*sorted(manifest), "manifest.json"]:
        assert (second / filename).read_bytes() == (output / filename).read_bytes()


def test_single_column_control_is_accepted_and_rebuilt_with_fidelity_metrics(corpus, monkeypatch):
    output, _ = corpus
    # Keep this a structural control: it tests the bounded raster path without
    # coupling the corpus to a particular installed OCR model/transcript.
    monkeypatch.setattr(media_preview, "_ocr_lines", lambda image, **_: [
        {"text": "Public library schedule", "box": (40, 80, 340, 120), "confidence": 0.99},
    ])
    text, pages = media_preview.extract_media((output / "single-column.pdf").read_bytes(), ".pdf")
    assert text == "Public library schedule"
    preview = media_preview.render_candidate(pages, [], "pdf")
    assert preview["fallback_lines"] == 0
    assert preview["self_ocr_residual_sources"] == 0
    assert preview["candidate_low_confidence_lines"] == 0
    assert preview["pdf_raster_evidence"]["source_objects_copied"] is False
    assert PdfReader(__import__("io").BytesIO(__import__("base64").b64decode(preview["candidate_pdf_base64"])), strict=True).pages[0].extract_text() == ""


def test_acroform_is_explicitly_abstained_before_ocr(corpus, monkeypatch):
    output, _ = corpus
    monkeypatch.setattr(media_preview, "_ocr_lines", lambda *_args, **_kwargs: pytest.fail("OCR must not run"))
    with pytest.raises(PayloadError, match="PDF is unsupported for bounded raster review"):
        media_preview.extract_media((output / "acroform.pdf").read_bytes(), ".pdf")


def test_low_contrast_scan_has_explicit_low_confidence_abstention(corpus, monkeypatch):
    output, _ = corpus
    # An OCR provider may read this faint fixture differently.  Simulate its
    # documented confidence output to pin the safety response, not recognition.
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=["Maya Patel"], boxes=[[(12, 12), (220, 12), (220, 48), (12, 48)]], scores=[0.31]))
    with pytest.raises(PayloadError, match="confidence is too low"):
        media_preview.extract_media((output / "blurred-low-contrast-scan.png").read_bytes(), ".png")


def test_catastrophically_blurred_claim_fails_closed_even_when_provider_is_confident(corpus, monkeypatch):
    """Confidence cannot replace a measurable source-raster edge."""
    output, manifest = corpus
    claim = manifest["catastrophic-blur-claim.png"]["claim"]
    image = Image.open(output / "catastrophic-blur-claim.png").convert("RGB")
    x0, y0, x1, y1 = claim["box"]
    pixels = np.asarray(image.convert("L"), dtype=np.int16)[y0:y1, x0:x1]
    assert pixels.min() < pixels.max(), "catastrophic-blur fixture must remain nonblank"
    assert max(np.abs(np.diff(pixels, axis=0)).max(), np.abs(np.diff(pixels, axis=1)).max()) < media_preview.MIN_OCR_LINE_EDGE_DELTA
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[claim["text"]], boxes=[[(x0, y0), (x1, y0), (x1, y1), (x0, y1)]], scores=[0.99]))
    with pytest.raises(PayloadError, match="lacks measurable source-raster edge detail") as error:
        media_preview.extract_media((output / "catastrophic-blur-claim.png").read_bytes(), ".png")
    assert manifest["catastrophic-blur-claim.png"]["expected"] == "abstain"
    assert claim["text"] not in str(error.value)


def test_exif_rotated_jpeg_is_normalized_before_any_layout_review(corpus):
    output, manifest = corpus
    pages = media_preview._image_pages((output / "exif-rotated.jpg").read_bytes(), ".jpg")
    assert list(pages[0].size) == manifest["exif-rotated.jpg"]["display_size"]


def test_pixel_oracle_allows_changes_only_in_transformed_line_and_manual_masks(corpus, monkeypatch):
    output, _ = corpus
    source = Image.open(output / "screenshot.png").convert("RGB")
    line_box = (70, 205, 500, 255)
    manual_box = {"x0": 730, "y0": 360, "x1": 820, "y1": 410, "origin": "REVIEWER_COORDINATE"}
    monkeypatch.setattr(media_preview, "_ocr_lines", lambda _image, **_: [])
    page = {"number": 1, "image": source, "lines": [
        {"text": "North region: available", "box": line_box, "start": 0, "end": 23, "confidence": 0.99},
    ]}
    match = {"start": 0, "end": 23, "source": "North region: available", "replacement": "[REDACTED]", "applied": True}
    preview = media_preview.render_candidate([page], [match], "image", {1: [manual_box]})
    import base64
    from io import BytesIO
    candidate = Image.open(BytesIO(base64.b64decode(preview["pages"][0]["candidate_png_base64"]))).convert("RGB")
    changed = np.any(np.asarray(source) != np.asarray(candidate), axis=2)
    allowed = np.zeros(changed.shape, dtype=bool)
    for x0, y0, x1, y1 in (line_box, (manual_box["x0"], manual_box["y0"], manual_box["x1"], manual_box["y1"])):
        allowed[y0:y1, x0:x1] = True
    assert changed.any()
    assert not np.any(changed & ~allowed), "candidate mutated pixels outside OCR/manual correction masks"
    assert preview["pages"][0]["manual_regions"] == [manual_box]


def test_pixel_oracle_removes_original_fictional_sensitive_pixels(monkeypatch):
    """A successful repaint must remove, rather than merely move, source ink."""
    import reportlab

    source = Image.new("RGB", (520, 140), "white")
    box = (32, 42, 330, 98)
    font = ImageFont.truetype(str(Path(reportlab.__file__).parent / "fonts" / "Vera.ttf"), 31)
    ImageDraw.Draw(source).text((40, 50), "Maya Patel", font=font, fill="black")
    before = np.asarray(source).copy()
    page = {"number": 1, "image": source, "lines": [
        # Vera's lowercase `y` descender reaches row 84; the tight source
        # ink claim must include it rather than misclassify it as padding.
        {"text": "Maya Patel", "box": box, "ink_box": (40, 50, 215, 85), "start": 0, "end": 10, "confidence": 0.99},
    ]}
    # An empty replacement is intentional here: it gives a pixel-level oracle
    # that the original fictional name's ink is gone, independent of OCR text.
    match = {"start": 0, "end": 10, "source": "Maya Patel", "replacement": "", "applied": True}
    monkeypatch.setattr(media_preview, "_ocr_lines", lambda _image, **_: [])
    preview = media_preview.render_candidate([page], [match], "image")
    import base64
    from io import BytesIO
    candidate = Image.open(BytesIO(base64.b64decode(preview["pages"][0]["candidate_png_base64"]))).convert("RGB")
    after = np.asarray(candidate)
    x0, y0, x1, y1 = box
    assert np.any(before[y0:y1, x0:x1] != 255), "fixture must contain source name ink"
    assert np.all(after[y0:y1, x0:x1] == 255), "candidate retained pixels in the original name region"


@pytest.mark.parametrize(("filename", "boxes"), [
    ("two-column.pdf", [[(30, 30), (180, 30), (180, 55), (30, 55)],
                          [(260, 30), (450, 30), (450, 55), (260, 55)]]),
    ("table.pdf", [[(30, 30), (180, 30), (180, 55), (30, 55)],
                    [(130, 42), (320, 42), (320, 70), (130, 70)]]),
])
def test_column_and_overlap_corpus_cases_abstain_without_guessing_reading_order(corpus, monkeypatch, filename, boxes):
    output, _ = corpus
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=["fictional private record", "ordinary adjacent record"], boxes=boxes, scores=[0.99, 0.99]))
    with pytest.raises(PayloadError, match="OCR layout is ambiguous") as error:
        media_preview.extract_media((output / filename).read_bytes(), ".pdf")
    assert "fictional private record" not in str(error.value)


def test_unprocessed_neighbor_region_abstains_before_pixel_mutation(corpus, monkeypatch):
    output, manifest = corpus
    image = Image.open(output / "unprocessed-neighbor.png").convert("RGB")
    before = np.asarray(image).copy()
    lines = manifest["unprocessed-neighbor.png"]["lines"]
    for line in lines:
        _assert_declared_ink(image, line["ink_box"])
    secret = lines[0]["text"]
    page = {"number": 1, "image": image, "lines": [
        {"text": lines[0]["text"], "box": tuple(lines[0]["box"]), "ink_box": tuple(lines[0]["ink_box"]), "start": 0, "end": len(secret)},
        {"text": lines[1]["text"], "box": tuple(lines[1]["box"]), "ink_box": tuple(lines[1]["ink_box"]),
         "start": len(secret) + 1, "end": len(secret) + 1 + len(lines[1]["text"])},
    ]}
    match = {"start": 0, "end": len(secret), "source": secret, "replacement": "[REDACTED]", "applied": True}
    monkeypatch.setattr(media_preview, "_ocr_lines", lambda _image, **_: [])
    with pytest.raises(PayloadError, match="repaint region touches another OCR line") as error:
        media_preview.render_candidate([page], [match], "image")
    assert secret not in str(error.value)
    assert np.array_equal(before, np.asarray(image)), "abstention must not mutate the source page"


def test_material_ocr_overlap_fixture_fails_closed_before_reading_order_is_invented(corpus, monkeypatch):
    output, manifest = corpus
    image = Image.open(output / "material-ocr-overlap.png").convert("RGB")
    claims = manifest["material-ocr-overlap.png"]["claims"]
    for claim in claims:
        _assert_declared_ink(image, claim["source_ink_box"])
    before = np.asarray(image).copy()
    monkeypatch.setattr(media_preview, "_engine", lambda: lambda _: SimpleNamespace(
        txts=[claim["text"] for claim in claims],
        boxes=[[(claim["box"][0], claim["box"][1]), (claim["box"][2], claim["box"][1]),
                (claim["box"][2], claim["box"][3]), (claim["box"][0], claim["box"][3])] for claim in claims], scores=[0.99, 0.99]))
    with pytest.raises(PayloadError, match="OCR layout is ambiguous") as error:
        media_preview.extract_media((output / "material-ocr-overlap.png").read_bytes(), ".png")
    assert manifest["material-ocr-overlap.png"]["expected"] == "abstain"
    assert claims[0]["text"] not in str(error.value)
    assert np.array_equal(before, np.asarray(image)), "overlap abstention must not mutate the source page"


@pytest.mark.parametrize("filename", ["two-column.pdf", "table.pdf", "static-form.pdf", "screenshot.png"])
def test_complex_layout_fixtures_are_available_for_guarded_acceptance_or_abstention(corpus, filename):
    output, manifest = corpus
    # Geometry/reading-order policy is intentionally not inferred from pixels in
    # this test.  D05 callers must either retain fidelity or return a reasoned
    # abstention; this corpus supplies stable inputs for those guard tests.
    assert manifest[filename]["expected"] == "accept_or_abstain"
    assert (output / filename).stat().st_size > 100


@pytest.mark.parametrize(("filename", "extension"), [
    ("two-column.pdf", ".pdf"),
    ("table.pdf", ".pdf"),
    ("static-form.pdf", ".pdf"),
    ("screenshot.png", ".png"),
])
def test_complex_layout_real_ocr_is_bounded_or_explicitly_abstains(corpus, filename, extension):
    """Run the installed OCR provider; do not freeze its model-specific words."""
    output, _ = corpus
    try:
        text, pages = media_preview.extract_media((output / filename).read_bytes(), extension)
    except PayloadError as error:
        # Every allowed failure is a deliberate review boundary.  In particular,
        # never accept a silent partial transcript for a difficult layout.
        assert str(error) in {
            "OCR layout is ambiguous for conservative visual review.",
            "OCR confidence is too low for a visual candidate; inspect the source manually.",
            "No readable OCR text was found in a media page.",
            "PDF text-layer and OCR disagree on a sensitive value; inspect the source manually.",
        }
    else:
        assert 0 < len(text) <= media_preview.MAX_OCR_CHARS
        assert len(pages) == 1
        assert all(0 < len(page["lines"]) <= media_preview.MAX_OCR_LINES for page in pages)


def test_real_screenshot_ocr_repaint_preserves_unprocessed_pixels(corpus):
    """Exercise actual OCR, replacement rendering and pixel fidelity together."""
    import base64
    from io import BytesIO

    output, _ = corpus
    source = Image.open(output / "screenshot.png").convert("RGB")
    text, pages = media_preview.extract_media((output / "screenshot.png").read_bytes(), ".png")
    assert text.count("Name: Maya Patel") == 1, "fictional sensitive field was missed by OCR"
    line = next(line for line in pages[0]["lines"] if line["text"] == "Name: Maya Patel")
    start = text.index("Maya Patel")
    preview = media_preview.render_candidate(pages, [{
        "start": start, "end": start + len("Maya Patel"), "source": "Maya Patel",
        "replacement": "John Singh", "applied": True,
    }], "image")
    assert preview["fallback_lines"] == preview["self_ocr_residual_sources"] == 0
    candidate = Image.open(BytesIO(base64.b64decode(preview["pages"][0]["candidate_png_base64"]))).convert("RGB")
    changed = np.any(np.asarray(source) != np.asarray(candidate), axis=2)
    x0, y0, x1, y1 = line["box"]
    allowed = np.zeros(changed.shape, dtype=bool)
    allowed[y0:y1, x0:x1] = True
    assert changed[y0:y1, x0:x1].any()
    assert not np.any(changed & ~allowed), "real-OCR candidate changed an unprocessed region"
