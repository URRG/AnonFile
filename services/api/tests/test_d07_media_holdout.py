import json
from pathlib import Path

from app.d07_media_holdout import EvaluationStatus, MediaKind, RenderedPixels, evaluate_final_pixels


FIXTURE = Path(__file__).parent / "fixtures" / "d07_media_holdout"


class StubOcr:
    def __init__(self, text: str = "") -> None:
        self.text = text
        self.calls: list[MediaKind] = []

    def extract_text(self, *, pixels: bytes, kind: MediaKind) -> str:
        self.calls.append(kind)
        return self.text


def pixels() -> tuple[RenderedPixels, ...]:
    return (RenderedPixels("pdf-page-1", b"pdf-final-pixels"), RenderedPixels("image-1", b"image-final-pixels"))


def test_observed_markers_are_aggregate_only_and_never_qualify() -> None:
    report = evaluate_final_pixels(rendered=pixels(), ocr=StubOcr("D07-SYNTH-ALPHA-91"), fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.SYNTHETIC_MARKERS_OBSERVED.value
    assert report["qualification"] == "NOT_QUALIFIED"
    assert report["aggregate"]["observed_markers"] == 1
    encoded = json.dumps(report, sort_keys=True)
    assert "D07-SYNTH-ALPHA-91" not in encoded
    assert "pdf-page-1" not in encoded


def test_clean_bounded_run_is_inconclusive_not_approved() -> None:
    report = evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(), fixture_directory=FIXTURE)
    assert report["status"] == EvaluationStatus.INCONCLUSIVE.value
    assert report["aggregate"]["missing_markers"] == 2


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
    manifest["cases"][0]["expected_markers"] = ["D07-SYNTH-ALTERED"]
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
    assert evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(), fixture_directory=crlf)["status"] == "INCONCLUSIVE"

    reordered = tmp_path / "reordered"
    reordered.mkdir()
    manifest = json.loads(raw.decode("utf-8"))
    (reordered / "manifest.json").write_text(json.dumps({"cases": manifest["cases"], "fixture_id": manifest["fixture_id"], "schema_version": manifest["schema_version"]}), encoding="utf-8")
    assert evaluate_final_pixels(rendered=pixels(), ocr=StubOcr(), fixture_directory=reordered)["status"] == "BLOCKED"


def test_unavailable_ocr_and_oversized_ocr_result_fail_closed() -> None:
    assert evaluate_final_pixels(rendered=pixels(), ocr=None, fixture_directory=FIXTURE)["reason"] == "INDEPENDENT_PIXEL_OCR_UNAVAILABLE"
    assert evaluate_final_pixels(rendered=pixels(), ocr=StubOcr("x" * 100_001), fixture_directory=FIXTURE)["status"] == "BLOCKED"
