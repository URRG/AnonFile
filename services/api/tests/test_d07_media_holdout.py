import json
import hashlib
import os
from pathlib import Path

import pytest
from PIL import Image

from app.d07_media_holdout import (EvaluationStatus, MediaKind, RenderedPixels,
                                   TesseractPixelOcr, evaluate_final_pixels)
from app.tesseract_verifier import TesseractCliVerifier


FIXTURE = Path(__file__).parent / "fixtures" / "d07_media_holdout"
LOCAL_EXECUTABLE_SHA256 = "c66f0f12ed76f6aa455dac97684bbc86756d6a732380bee09122454cfda3f420"
LOCAL_ENG_SHA256 = "7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2"
# Captured from the approved official 5.5.3.20260724 runtime's raw --version
# bytes under the v2 stdin/PSM/tessdata/English command identity.  Do not
# derive this from the executable under test.
LOCAL_RUNTIME_IDENTITY = "e92d5df1ffa4e7fb2484527902e121ea9adaabe0b99be01ff1fd28118b011e67"


def _opt_in_tesseract_paths() -> tuple[Path, Path] | None:
    """Return only explicit absolute runtime paths; default tests never probe PATH."""
    executable_raw = os.environ.get("D07_TESSERACT_EXECUTABLE")
    tessdata_raw = os.environ.get("D07_TESSDATA_DIRECTORY")
    if not executable_raw or not tessdata_raw:
        return None
    executable, tessdata = Path(executable_raw), Path(tessdata_raw)
    if not executable.is_absolute() or not tessdata.is_absolute() or not executable.is_file() or not (tessdata / "eng.traineddata").is_file():
        return None
    return executable, tessdata


class StubOcr:
    def __init__(self, text: str = "") -> None:
        self.text = text
        self.calls: list[MediaKind] = []

    def extract_text(self, *, pixels: bytes, kind: MediaKind) -> str:
        self.calls.append(kind)
        return self.text


def pixels() -> tuple[RenderedPixels, ...]:
    return (RenderedPixels("pdf-page-1", (FIXTURE / "pdf-page-1.png").read_bytes()),
            RenderedPixels("image-1", (FIXTURE / "image-1.png").read_bytes()))


def test_expected_final_canaries_are_aggregate_only_and_never_qualify() -> None:
    report = evaluate_final_pixels(rendered=pixels(), ocr=StubOcr("D07-FINAL-ALPHA-91 D07-FINAL-BRAVO-27"), fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.SYNTHETIC_CANARIES_CONFIRMED.value
    assert report["qualification"] == "NOT_QUALIFIED"
    assert report["aggregate"]["observed_final_markers"] == 2
    assert report["aggregate"]["observed_forbidden_markers"] == 0
    encoded = json.dumps(report, sort_keys=True)
    assert "D07-FINAL-ALPHA-91" not in encoded
    assert "pdf-page-1" not in encoded


def test_missing_expected_final_canary_fails_closed_not_approved() -> None:
    report = evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(), fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.BLOCKED.value
    assert report["reason"] == "SYNTHETIC_CANARY_EXPECTATION_MISMATCH"
    assert report["aggregate"]["missing_final_markers"] == 2


def test_forbidden_synthetic_canary_fails_closed_and_report_hides_it() -> None:
    marker = "D07-SOURCE-ALPHA-91"
    report = evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(f"D07-FINAL-ALPHA-91 D07-FINAL-BRAVO-27 {marker}"), fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.BLOCKED.value
    assert report["reason"] == "SYNTHETIC_CANARY_EXPECTATION_MISMATCH"
    assert report["aggregate"]["observed_forbidden_markers"] == 1
    assert marker not in json.dumps(report, sort_keys=True)


def test_ocr_exception_fails_closed_without_exception_detail() -> None:
    class ExplodingOcr:
        def extract_text(self, *, pixels: bytes, kind: MediaKind) -> str:
            raise RuntimeError("sensitive synthetic marker")

    report = evaluate_final_pixels(rendered=pixels(), ocr=ExplodingOcr(), fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.BLOCKED.value
    assert report["reason"] == "FINAL_PIXEL_EVALUATION_FAILED_CLOSED"
    assert "sensitive" not in json.dumps(report)


def test_manifest_drift_and_malformed_or_duplicate_final_pixels_fail_closed(tmp_path) -> None:
    drifted = tmp_path / "fixture"
    drifted.mkdir()
    manifest = json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))
    manifest["cases"][0]["expected_final_markers"] = ["D07-FINAL-ALTERED"]
    (drifted / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    assert evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(), fixture_directory=drifted)["status"] == "BLOCKED"
    duplicate = (RenderedPixels("pdf-page-1", b"x"), RenderedPixels("pdf-page-1", b"y"))
    assert evaluate_final_pixels(rendered=duplicate, ocr=StubOcr(), fixture_directory=FIXTURE)["status"] == "BLOCKED"


def test_manifest_whitespace_drift_and_oversized_manifest_fail_closed(tmp_path) -> None:
    whitespace = tmp_path / "whitespace"
    whitespace.mkdir()
    (whitespace / "manifest.json").write_bytes((FIXTURE / "manifest.json").read_bytes() + b"\n")
    report = evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(), fixture_directory=whitespace)
    assert report["status"] == EvaluationStatus.BLOCKED.value

    oversized = tmp_path / "oversized"
    oversized.mkdir()
    (oversized / "manifest.json").write_bytes(b"{" + b" " * 16_384)
    report = evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(), fixture_directory=oversized)
    assert report["status"] == EvaluationStatus.BLOCKED.value


def test_legacy_crlf_manifest_is_normalized_but_key_order_drift_fails_closed(tmp_path) -> None:
    crlf = tmp_path / "crlf"
    crlf.mkdir()
    raw = (FIXTURE / "manifest.json").read_bytes().replace(b"\r\n", b"\n")
    (crlf / "manifest.json").write_bytes(raw.replace(b"\n", b"\r\n"))
    assert evaluate_final_pixels(rendered=pixels(), ocr=StubOcr("D07-FINAL-ALPHA-91 D07-FINAL-BRAVO-27"), fixture_directory=crlf)["status"] == "SYNTHETIC_CANARIES_CONFIRMED"

    reordered = tmp_path / "reordered"
    reordered.mkdir()
    manifest = json.loads(raw.decode("utf-8"))
    (reordered / "manifest.json").write_text(json.dumps({"cases": manifest["cases"], "fixture_id": manifest["fixture_id"], "schema_version": manifest["schema_version"]}), encoding="utf-8")
    assert evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(), fixture_directory=reordered)["status"] == "BLOCKED"


def test_unavailable_ocr_and_oversized_ocr_result_fail_closed() -> None:
    assert evaluate_final_pixels(rendered=pixels(), ocr=None, fixture_directory=FIXTURE)["reason"] == "INDEPENDENT_PIXEL_OCR_UNAVAILABLE"
    assert evaluate_final_pixels(rendered=pixels(), ocr=StubOcr("x" * 100_001), fixture_directory=FIXTURE)["status"] == "BLOCKED"


def test_final_raster_digest_mismatch_prevents_ocr_and_fails_closed() -> None:
    ocr = StubOcr("D07-FINAL-ALPHA-91 D07-FINAL-BRAVO-27")
    changed = (RenderedPixels("pdf-page-1", b"changed-final-pixels"), pixels()[1])
    report = evaluate_final_pixels(rendered=changed, ocr=ocr, fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.BLOCKED.value
    assert report["reason"] == "FINAL_PIXEL_EVALUATION_FAILED_CLOSED"
    assert ocr.calls == []


def test_tesseract_adapter_rejects_structural_fake_verifier() -> None:
    class PinnedVerifier:
        def __init__(self) -> None:
            self.pixels: list[bytes] = []

        def extract_final_png_text(self, pixels: bytes) -> str:
            self.pixels.append(pixels)
            return "D07-FINAL-ALPHA-91 D07-FINAL-BRAVO-27"

    with pytest.raises(TypeError, match="requires a provisioned TesseractCliVerifier"):
        TesseractPixelOcr(PinnedVerifier())


def test_fixtures_are_real_decodable_pngs_with_pinned_bytes_and_pdf_provenance() -> None:
    manifest = json.loads((FIXTURE / "manifest.json").read_text(encoding="utf-8"))
    for case in manifest["cases"]:
        image_path = FIXTURE / f"{case['case_id']}.png"
        raw = image_path.read_bytes()
        assert raw.startswith(b"\x89PNG\r\n\x1a\n")
        assert hashlib.sha256(raw).hexdigest() == case["final_raster_sha256"]
        with Image.open(image_path) as image:
            assert image.format == "PNG"
            image.load()
    assert (FIXTURE / "pdf-page-1-source.pdf").read_bytes().startswith(b"%PDF-")
    assert (FIXTURE / "image-1-source.pdf").read_bytes().startswith(b"%PDF-")


def test_non_png_bytes_are_rejected_before_generic_ocr(monkeypatch) -> None:
    bad = b"not a png"
    monkeypatch.setattr("app.d07_media_holdout._load_cases", lambda _directory: (
        ("image-1", MediaKind.IMAGE, hashlib.sha256(bad).hexdigest(), ("expected",), ("forbidden",)),
    ))
    ocr = StubOcr("expected")
    report = evaluate_final_pixels(rendered=(RenderedPixels("image-1", bad),), ocr=ocr, fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.BLOCKED.value
    assert ocr.calls == []


@pytest.mark.skipif(os.environ.get("RUN_D07_TESSERACT_INTEGRATION") != "1" or _opt_in_tesseract_paths() is None,
                    reason="set RUN_D07_TESSERACT_INTEGRATION=1 and explicit pinned runtime paths")
def test_opt_in_pinned_tesseract_reads_exact_fictional_final_pngs_only() -> None:
    configured = _opt_in_tesseract_paths()
    assert configured is not None
    executable, tessdata = configured
    verifier = TesseractCliVerifier(executable=executable, allowed_executables=(executable,),
        expected_executable_sha256=LOCAL_EXECUTABLE_SHA256, expected_runtime_identity=LOCAL_RUNTIME_IDENTITY,
        tessdata_directory=tessdata, allowed_tessdata_directories=(tessdata,),
        expected_eng_traineddata_sha256=LOCAL_ENG_SHA256)
    report = evaluate_final_pixels(rendered=pixels(), ocr=TesseractPixelOcr(verifier), fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.SYNTHETIC_CANARIES_CONFIRMED.value
    assert report["qualification"] == "NOT_QUALIFIED"
