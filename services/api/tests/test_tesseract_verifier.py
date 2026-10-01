"""Mock-only coverage for the opt-in independent final OCR adapter."""
from io import BytesIO
import hashlib
import os
from pathlib import Path
import subprocess

import pytest

from app.tesseract_verifier import FinalOcrVerificationError, TesseractCliVerifier


EXECUTABLE = (Path("C:/Program Files/Tesseract-OCR/tesseract.exe") if os.name == "nt"
              else Path("/opt/tesseract/bin/tesseract"))
TESSDATA = (Path("C:/Program Files/Tesseract-OCR/tessdata") if os.name == "nt"
            else Path("/opt/tesseract/tessdata"))
VERSION = "tesseract 5.4.0"
RUNTIME_IDENTITY = hashlib.sha256(f"tesseract-cli-stdin-psm6-tessdata-eng-v2\n{VERSION}".encode()).hexdigest()


class FakeProcess:
    def __init__(self, stdout=b"safe replacement\n", returncode=0):
        class RecordingInput(BytesIO):
            def close(self):
                self.was_closed = True
        self.stdin = RecordingInput()
        self.stdout = BytesIO(stdout)
        self.returncode = returncode
        self.killed = False
        self.waited = 0

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.returncode = -9

    def wait(self, timeout):
        self.waited += 1
        return self.returncode


def verifier(factory):
    def version_factory(command, **kwargs):
        assert command == [str(EXECUTABLE), "--version"]
        return FakeProcess(stdout=(VERSION + "\n").encode())
    return TesseractCliVerifier(executable=EXECUTABLE, allowed_executables=(EXECUTABLE,),
                                expected_executable_sha256="a" * 64, expected_runtime_identity=RUNTIME_IDENTITY,
                                tessdata_directory=TESSDATA, allowed_tessdata_directories=(TESSDATA,),
                                expected_eng_traineddata_sha256="b" * 64,
                                popen_factory=factory, version_popen_factory=version_factory,
                                executable_digest_reader=lambda _: "a" * 64,
                                traineddata_digest_reader=lambda _: "b" * 64)


def test_tesseract_uses_exact_final_png_bytes_without_rapidocr_or_ambient_tessdata(monkeypatch):
    monkeypatch.setenv("TESSDATA_PREFIX", "C:/ambient/unpinned/tessdata")
    calls = []
    process = FakeProcess()
    def factory(command, **kwargs):
        calls.append((command, kwargs))
        return process

    verifier(factory).verify_pngs((b"exact-final-png",), ("Maya Patel",))
    assert calls[0][0] == [str(EXECUTABLE), "stdin", "stdout", "--psm", "6", "--tessdata-dir", str(TESSDATA), "-l", "eng"]
    assert process.stdin.getvalue() == b"exact-final-png"
    assert calls[0][1]["stdin"] is subprocess.PIPE
    assert calls[0][1]["stderr"] is subprocess.DEVNULL
    assert calls[0][1]["env"]["TESSDATA_PREFIX"] == str(TESSDATA)
    assert calls[0][1]["env"]["TESSDATA_PREFIX"] != "C:/ambient/unpinned/tessdata"
    assert process.waited == 1


def test_tesseract_exposes_bounded_transcript_only_after_provisioning_gate():
    process = FakeProcess(stdout=b"fictional final canary\n")
    text = verifier(lambda *_args, **_kwargs: process).extract_final_png_text(b"exact-final-png")
    assert text == "fictional final canary\n"
    assert process.stdin.getvalue() == b"exact-final-png"


def test_transcript_unavailable_without_an_explicit_pinned_executable():
    with pytest.raises(FinalOcrVerificationError, match="verifier is unavailable"):
        TesseractCliVerifier().extract_final_png_text(b"exact-final-png")


@pytest.mark.parametrize("failure, expected", [
    (FileNotFoundError(), "verifier is unavailable"),
    (OSError(), "verification failed"),
])
def test_tesseract_failures_are_fixed_and_source_free(failure, expected):
    secret = "Maya Patel"
    checked = verifier(lambda *_args, **_kwargs: (_ for _ in ()).throw(failure))
    with pytest.raises(FinalOcrVerificationError, match=expected) as error:
        checked.verify_pngs((b"exact-final-png",), (secret,))
    assert secret not in str(error.value)


def test_tesseract_output_is_bounded_and_residual_is_source_free():
    secret = "Maya Patel"
    overflow_process = FakeProcess(stdout=b"x" * 65_537)
    oversized = verifier(lambda *_args, **_kwargs: overflow_process)
    with pytest.raises(FinalOcrVerificationError, match="verification failed"):
        oversized.verify_pngs((b"exact-final-png",), (secret,))
    assert overflow_process.killed
    assert overflow_process.waited >= 1
    residual = verifier(lambda *_args, **_kwargs: FakeProcess(stdout=secret.encode()))
    with pytest.raises(FinalOcrVerificationError, match="found residual content") as error:
        residual.verify_pngs((b"exact-final-png",), (secret,))
    assert secret not in str(error.value)


@pytest.mark.parametrize("source, transcript", [
    ("Maya Patel", "Maya   Patel"),
    ("Maya Patel", "MAYA\nPATEL"),
    ("Maya Patel", "Maya\tPatel"),
    ("Maya Patel", "Maya\u00a0Patel"),
    ("Maya Patel", "Ｍａｙａ Ｐａｔｅｌ"),
    ("José Alvarez", "Jose\u0301 Alvarez"),
    ("Straße", "STRASSE"),
])
def test_final_ocr_rejects_source_values_despite_spacing_or_unicode_variation(source, transcript):
    checked = verifier(lambda *_args, **_kwargs: FakeProcess(stdout=transcript.encode()))
    with pytest.raises(FinalOcrVerificationError, match="found residual content") as error:
        checked.verify_pngs((b"exact-final-png",), (source,))
    assert source not in str(error.value)
    assert transcript not in str(error.value)


@pytest.mark.parametrize("transcript", ["Maya Patelsson", "SuperMaya Patel", "Ｍａｙａ Ｐａｔｅｌsson"])
def test_final_ocr_normalization_preserves_source_value_word_boundaries(transcript):
    checked = verifier(lambda *_args, **_kwargs: FakeProcess(stdout=transcript.encode()))
    checked.verify_pngs((b"exact-final-png",), ("Maya Patel",))


@pytest.mark.parametrize("source", ["   ", "\u00a0"])
def test_final_ocr_rejects_whitespace_only_source_values_before_candidate_ocr(source):
    calls = []
    checked = verifier(lambda *_args, **_kwargs: calls.append(True))
    with pytest.raises(FinalOcrVerificationError, match="input is invalid"):
        checked.verify_pngs((b"exact-final-png",), (source,))
    assert calls == []


def test_final_ocr_keeps_existing_unicode_case_insensitive_matching():
    checked = verifier(lambda *_args, **_kwargs: FakeProcess(stdout="İRIS".encode()))
    with pytest.raises(FinalOcrVerificationError, match="found residual content"):
        checked.verify_pngs((b"exact-final-png",), ("Iris",))


def test_pdf_verifier_rasterizes_exact_final_pdf_bytes_before_ocr():
    received = []
    checked = TesseractCliVerifier(executable=EXECUTABLE, allowed_executables=(EXECUTABLE,),
        expected_executable_sha256="a" * 64, expected_runtime_identity=RUNTIME_IDENTITY,
        tessdata_directory=TESSDATA, allowed_tessdata_directories=(TESSDATA,),
        expected_eng_traineddata_sha256="b" * 64,
        popen_factory=lambda *_args, **_kwargs: FakeProcess(stdout=b"safe"),
        version_popen_factory=lambda *_args, **_kwargs: FakeProcess(stdout=(VERSION + "\n").encode()),
        executable_digest_reader=lambda _: "a" * 64, traineddata_digest_reader=lambda _: "b" * 64,
        pdf_rasterizer=lambda pdf: received.append(pdf) or (b"rerasterized-final-pdf-page",))
    final_pdf = b"%PDF-exact-final-bytes"
    checked.verify_pdf(final_pdf, ("Maya Patel",))
    assert received == [final_pdf]


def test_unallowlisted_or_path_based_executable_is_unavailable_without_running():
    calls = []
    for checked in (TesseractCliVerifier(),
                    TesseractCliVerifier(executable=Path("tesseract"), allowed_executables=(EXECUTABLE,),
                                         popen_factory=lambda *_args, **_kwargs: calls.append(True))):
        with pytest.raises(FinalOcrVerificationError, match="verifier is unavailable"):
            checked.verify_pngs((b"exact-final-png",), ("Maya Patel",))
    assert calls == []


@pytest.mark.parametrize("digest, version, expected", [
    ("b" * 64, VERSION, "verifier is unavailable"),
    ("a" * 64, "tesseract 5.5.0", "verifier is unavailable"),
])
def test_integrity_or_runtime_pin_mismatch_prevents_candidate_ocr(digest, version, expected):
    candidate_calls = []
    def version_factory(command, **kwargs):
        return FakeProcess(stdout=(version + "\n").encode())
    checked = TesseractCliVerifier(executable=EXECUTABLE, allowed_executables=(EXECUTABLE,),
        expected_executable_sha256="a" * 64, expected_runtime_identity=RUNTIME_IDENTITY,
        tessdata_directory=TESSDATA, allowed_tessdata_directories=(TESSDATA,),
        expected_eng_traineddata_sha256="b" * 64,
        executable_digest_reader=lambda _: digest, version_popen_factory=version_factory,
        traineddata_digest_reader=lambda _: "b" * 64,
        popen_factory=lambda command, **kwargs: candidate_calls.append(command))
    with pytest.raises(FinalOcrVerificationError, match=expected):
        checked.verify_pngs((b"exact-final-png",), ("Maya Patel",))
    assert candidate_calls == []


def test_checked_in_runtime_identity_rejects_unexpected_version_before_candidate_ocr():
    candidate_calls = []
    checked = TesseractCliVerifier(executable=EXECUTABLE, allowed_executables=(EXECUTABLE,),
        expected_executable_sha256="a" * 64,
        expected_runtime_identity="e92d5df1ffa4e7fb2484527902e121ea9adaabe0b99be01ff1fd28118b011e67",
        tessdata_directory=TESSDATA, allowed_tessdata_directories=(TESSDATA,),
        expected_eng_traineddata_sha256="b" * 64,
        executable_digest_reader=lambda _: "a" * 64, traineddata_digest_reader=lambda _: "b" * 64,
        version_popen_factory=lambda *_args, **_kwargs: FakeProcess(stdout=b"tesseract unexpected\n"),
        popen_factory=lambda command, **kwargs: candidate_calls.append(command))
    with pytest.raises(FinalOcrVerificationError, match="verifier is unavailable"):
        checked.extract_final_png_text(b"exact-final-png")
    assert candidate_calls == []


def test_model_pin_mismatch_or_ambient_tessdata_cannot_reach_candidate_ocr(monkeypatch):
    candidate_calls = []
    monkeypatch.setenv("TESSDATA_PREFIX", "C:/ambient/unpinned/tessdata")
    checked = TesseractCliVerifier(executable=EXECUTABLE, allowed_executables=(EXECUTABLE,),
        expected_executable_sha256="a" * 64, expected_runtime_identity=RUNTIME_IDENTITY,
        tessdata_directory=TESSDATA, allowed_tessdata_directories=(TESSDATA,),
        expected_eng_traineddata_sha256="b" * 64,
        executable_digest_reader=lambda _: "a" * 64,
        traineddata_digest_reader=lambda _: "c" * 64,
        version_popen_factory=lambda *_args, **_kwargs: FakeProcess(stdout=(VERSION + "\n").encode()),
        popen_factory=lambda command, **kwargs: candidate_calls.append((command, kwargs)))
    with pytest.raises(FinalOcrVerificationError, match="verifier is unavailable"):
        checked.extract_final_png_text(b"exact-final-png")
    assert candidate_calls == []


def test_tessdata_must_be_explicitly_allowlisted():
    checked = TesseractCliVerifier(executable=EXECUTABLE, allowed_executables=(EXECUTABLE,),
        expected_executable_sha256="a" * 64, expected_runtime_identity=RUNTIME_IDENTITY,
        tessdata_directory=TESSDATA, allowed_tessdata_directories=(Path("C:/other/tessdata"),),
        expected_eng_traineddata_sha256="b" * 64,
        executable_digest_reader=lambda _: "a" * 64, traineddata_digest_reader=lambda _: "b" * 64)
    with pytest.raises(FinalOcrVerificationError, match="verifier is unavailable"):
        checked.extract_final_png_text(b"exact-final-png")


def test_tesseract_timeout_kills_process_with_fixed_source_free_error(monkeypatch):
    process = FakeProcess(returncode=None)
    ticks = iter((0.0, 0.0, 6.0))
    monkeypatch.setattr("app.tesseract_verifier.time.monotonic", lambda: next(ticks))
    with pytest.raises(FinalOcrVerificationError, match="verification timed out") as error:
        verifier(lambda *_args, **_kwargs: process).verify_pngs((b"exact-final-png",), ("Maya Patel",))
    assert process.killed and "Maya Patel" not in str(error.value)
    assert process.waited >= 1
