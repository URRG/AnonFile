"""Opt-in, independent final-artifact OCR verification for the synthetic demo.

This adapter is intentionally not part of preview construction and never falls
back to RapidOCR.  A caller must explicitly supply it after candidate bytes
have been finalized.  Its result is a bounded residual check, not a release
approval or an OCR-completeness claim. In particular, it does not close the
known D05 P1: an overbroad same-engine OCR line can hide adjacent source.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from io import BytesIO
import os
from pathlib import Path
import queue
import re
import subprocess
from threading import Event, Thread
import time
import unicodedata
from typing import Any, Callable, Protocol, Sequence


MAX_FINAL_OCR_PAGES = 2
MAX_TESSERACT_OUTPUT_BYTES = 65_536
TESSERACT_TIMEOUT_SECONDS = 5
_READ_CHUNK_BYTES = 4_096
_CLEANUP_TIMEOUT_SECONDS = 1
_MAX_EXECUTABLE_BYTES = 100_000_000
_TESSERACT_CONFIG_IDENTITY = "tesseract-cli-stdin-psm6-tessdata-eng-v2"


class FinalOcrVerificationError(ValueError):
    """A fixed, source-free error from the optional final verifier."""


class IndependentFinalOcrVerifier(Protocol):
    """A final-bytes verifier; callers retain sensitive values privately."""

    def verify_pngs(self, png_pages: Sequence[bytes], absent_values: Sequence[str]) -> None:
        """Raise a fixed error if final candidate bytes cannot be verified."""

    def verify_pdf(self, pdf_bytes: bytes, absent_values: Sequence[str]) -> None:
        """Verify rerasterized final PDF bytes, not pre-PDF working pixels."""


class FinalPngTranscriptVerifier(Protocol):
    """Provisioned checker that can transcribe one exact final PNG.

    The transcript is intentionally a low-level, caller-owned value.  This
    module never log it or turn it into an authorization decision.
    """

    def extract_final_png_text(self, png_bytes: bytes) -> str:
        """Return bounded OCR text or raise a fixed verification error."""


def _reject(message: str) -> None:
    raise FinalOcrVerificationError(message)


def _normalised_values(values: Sequence[str]) -> tuple[str, ...]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)) or len(values) > 200:
        _reject("Independent final OCR verification input is invalid.")
    result = []
    for value in values:
        if not isinstance(value, str) or not value.strip() or len(value) > 500 or not value.isprintable():
            _reject("Independent final OCR verification input is invalid.")
        result.append(value)
    return tuple(result)


def _digest(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _contains_source_value(transcript: str, values: Sequence[str]) -> bool:
    """Keep matching values private: callers receive only a fixed outcome."""
    # OCR can change spacing, line breaks, or equivalent Unicode glyphs while
    # retaining the same source value. Preserve exact matching as well as this
    # conservative comparison; neither branch establishes OCR completeness.
    canonical_transcript = " ".join(unicodedata.normalize("NFKC", transcript).casefold().split())
    for value in values:
        if re.search(r"(?<!\w)" + re.escape(value) + r"(?!\w)", transcript, re.IGNORECASE):
            return True
        canonical_value = " ".join(unicodedata.normalize("NFKC", value).casefold().split())
        if re.search(r"(?<!\w)" + re.escape(canonical_value) + r"(?!\w)", canonical_transcript):
            return True
    return False


def _sha256_file(path: Path) -> str:
    """Hash a bounded executable stream without reading candidate bytes."""
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        while chunk := stream.read(65_536):
            total += len(chunk)
            if total > _MAX_EXECUTABLE_BYTES:
                raise ValueError
            digest.update(chunk)
    return digest.hexdigest()


def _runtime_identity(version_text: str) -> str:
    if not isinstance(version_text, str) or not version_text or len(version_text) > MAX_TESSERACT_OUTPUT_BYTES:
        raise ValueError
    return hashlib.sha256((f"{_TESSERACT_CONFIG_IDENTITY}\n{version_text.strip()}").encode("utf-8")).hexdigest()


def _cleanup_process(process: Any | None, threads: Sequence[Thread]) -> None:
    """Boundedly close and reap an OCR child on every success/failure path."""
    if process is not None:
        try:
            if process.poll() is None:
                process.kill()
        except (OSError, ValueError):
            pass
        try:
            process.wait(timeout=_CLEANUP_TIMEOUT_SECONDS)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            try:
                process.kill()
                process.wait(timeout=_CLEANUP_TIMEOUT_SECONDS)
            except (OSError, ValueError, subprocess.TimeoutExpired):
                pass
        for stream_name in ("stdin", "stdout"):
            try:
                stream = getattr(process, stream_name, None)
                if stream is not None:
                    stream.close()
            except (OSError, ValueError):
                pass
    for thread in threads:
        if thread is not None:
            thread.join(_CLEANUP_TIMEOUT_SECONDS)


@dataclass(frozen=True)
class TesseractCliVerifier:
    """Bounded Tesseract CLI adapter, deliberately independent of RapidOCR."""

    # No PATH lookup is permitted. The caller that installed/provisioned the
    # executable must explicitly bind one absolute allowlisted path.
    executable: Path | None = None
    allowed_executables: tuple[Path, ...] = ()
    expected_executable_sha256: str | None = None
    expected_runtime_identity: str | None = None
    tessdata_directory: Path | None = None
    allowed_tessdata_directories: tuple[Path, ...] = ()
    expected_eng_traineddata_sha256: str | None = None
    timeout_seconds: int = TESSERACT_TIMEOUT_SECONDS
    max_stdout_bytes: int = MAX_TESSERACT_OUTPUT_BYTES
    popen_factory: Callable[..., Any] = subprocess.Popen
    version_popen_factory: Callable[..., Any] = subprocess.Popen
    executable_digest_reader: Callable[[Path], str] = _sha256_file
    traineddata_digest_reader: Callable[[Path], str] = _sha256_file
    pdf_rasterizer: Callable[[bytes], Sequence[bytes]] | None = None

    def _read_version(self) -> str:
        """Read bounded version output before candidate bytes are processed."""
        process: Any | None = None
        reader: Thread | None = None
        try:
            process = self.version_popen_factory([str(self.executable), "--version"], stdout=subprocess.PIPE,
                                                 stderr=subprocess.DEVNULL, env=self._subprocess_environment())
            if process.stdout is None:
                _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
            output = bytearray()
            overflow = Event()
            done = Event()
            errors: queue.SimpleQueue[BaseException] = queue.SimpleQueue()
            def read_stdout() -> None:
                try:
                    while True:
                        chunk = process.stdout.read(min(_READ_CHUNK_BYTES, MAX_TESSERACT_OUTPUT_BYTES - len(output) + 1))
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > MAX_TESSERACT_OUTPUT_BYTES:
                            overflow.set()
                            break
                except BaseException as error:
                    errors.put(error)
                finally:
                    done.set()
            reader = Thread(target=read_stdout, daemon=True)
            reader.start()
            deadline = time.monotonic() + self.timeout_seconds
            while not (done.is_set() and process.poll() is not None):
                if overflow.is_set() or time.monotonic() >= deadline:
                    process.kill()
                    _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
                time.sleep(0.005)
            if overflow.is_set() or not errors.empty() or process.returncode != 0:
                _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
            return bytes(output).decode("utf-8", "strict")
        except FinalOcrVerificationError:
            raise
        except (OSError, UnicodeError, ValueError):
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        finally:
            _cleanup_process(process, (reader,))

    def _assert_provisioned(self) -> None:
        """Bind executable bits and runtime semantics before candidate OCR."""
        if (not isinstance(self.allowed_executables, tuple) or
                not isinstance(self.allowed_tessdata_directories, tuple) or
                self.timeout_seconds != TESSERACT_TIMEOUT_SECONDS or
                self.max_stdout_bytes != MAX_TESSERACT_OUTPUT_BYTES):
            _reject("Independent final OCR verifier configuration is invalid.")
        if (self.expected_executable_sha256 is None or self.expected_runtime_identity is None or
                self.expected_eng_traineddata_sha256 is None):
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        if (not isinstance(self.expected_executable_sha256, str) or
                not _digest(self.expected_executable_sha256) or
                not isinstance(self.expected_runtime_identity, str) or
                not _digest(self.expected_runtime_identity) or
                not isinstance(self.expected_eng_traineddata_sha256, str) or
                not _digest(self.expected_eng_traineddata_sha256)):
            _reject("Independent final OCR verifier configuration is invalid.")
        if self.executable is None or not isinstance(self.executable, Path) or not self.executable.is_absolute():
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        allowed = {str(path) for path in self.allowed_executables
                   if isinstance(path, Path) and path.is_absolute()}
        if str(self.executable) not in allowed:
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        if (self.tessdata_directory is None or not isinstance(self.tessdata_directory, Path) or
                not self.tessdata_directory.is_absolute()):
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        allowed_tessdata = {str(path) for path in self.allowed_tessdata_directories
                            if isinstance(path, Path) and path.is_absolute()}
        if str(self.tessdata_directory) not in allowed_tessdata:
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        try:
            if self.executable_digest_reader(self.executable) != self.expected_executable_sha256:
                _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
            if self.traineddata_digest_reader(self.tessdata_directory / "eng.traineddata") != self.expected_eng_traineddata_sha256:
                _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
            if _runtime_identity(self._read_version()) != self.expected_runtime_identity:
                _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        except FinalOcrVerificationError:
            raise
        except (OSError, UnicodeError, ValueError):
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")

    def _subprocess_environment(self) -> dict[str, str]:
        """Do not inherit ambient TESSDATA_PREFIX or language-model selection."""
        if self.tessdata_directory is None:
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        environment = {"TESSDATA_PREFIX": str(self.tessdata_directory)}
        if os.name == "nt":
            system_root = os.environ.get("SystemRoot")
            if not system_root:
                _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
            environment["SystemRoot"] = system_root
        return environment

    def _run_png(self, png_bytes: bytes) -> str:
        if not isinstance(png_bytes, bytes) or not png_bytes or len(png_bytes) > 2_500_000:
            _reject("Independent final OCR verification input is invalid.")
        process: Any | None = None
        writer: Thread | None = None
        reader: Thread | None = None
        try:
            process = self.popen_factory([str(self.executable), "stdin", "stdout", "--psm", "6",
                                          "--tessdata-dir", str(self.tessdata_directory), "-l", "eng"],
                                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                         env=self._subprocess_environment())
            if process.stdin is None or process.stdout is None:
                _reject("Independent final OCR verification failed; inspect the candidate manually.")
            output = bytearray()
            overflow = Event()
            reader_done = Event()
            writer_done = Event()
            writer_error: queue.SimpleQueue[BaseException] = queue.SimpleQueue()
            reader_error: queue.SimpleQueue[BaseException] = queue.SimpleQueue()

            def feed_stdin() -> None:
                try:
                    process.stdin.write(png_bytes)
                    process.stdin.close()
                except BaseException as error:  # Process failure is normalized below.
                    writer_error.put(error)
                finally:
                    writer_done.set()

            def read_stdout() -> None:
                try:
                    while True:
                        # Never retain more than the configured cap plus one
                        # byte used to prove the cap was exceeded.
                        chunk = process.stdout.read(min(_READ_CHUNK_BYTES,
                                                       self.max_stdout_bytes - len(output) + 1))
                        if not chunk:
                            break
                        output.extend(chunk)
                        if len(output) > self.max_stdout_bytes:
                            overflow.set()
                            break
                except BaseException as error:  # Process failure is normalized below.
                    reader_error.put(error)
                finally:
                    reader_done.set()

            writer = Thread(target=feed_stdin, daemon=True)
            reader = Thread(target=read_stdout, daemon=True)
            writer.start()
            reader.start()
            deadline = time.monotonic() + self.timeout_seconds
            while not (reader_done.is_set() and writer_done.is_set() and process.poll() is not None):
                if overflow.is_set():
                    process.kill()
                    _reject("Independent final OCR verification failed; inspect the candidate manually.")
                if time.monotonic() >= deadline:
                    process.kill()
                    _reject("Independent final OCR verification timed out; inspect the candidate manually.")
                time.sleep(0.005)
            if overflow.is_set():
                process.kill()
                _reject("Independent final OCR verification failed; inspect the candidate manually.")
            if (not writer_error.empty() or not reader_error.empty() or
                    process.returncode != 0 or len(output) > self.max_stdout_bytes):
                _reject("Independent final OCR verification failed; inspect the candidate manually.")
            return bytes(output).decode("utf-8", "strict")
        except FinalOcrVerificationError:
            raise
        except FileNotFoundError:
            _reject("Independent final OCR verifier is unavailable; inspect the candidate manually.")
        except (OSError, UnicodeError, ValueError):
            _reject("Independent final OCR verification failed; inspect the candidate manually.")
        finally:
            _cleanup_process(process, (writer, reader))

    def verify_pngs(self, png_pages: Sequence[bytes], absent_values: Sequence[str]) -> None:
        # Provisioning precedes parsing or sending any candidate byte.
        self._assert_provisioned()
        values = _normalised_values(absent_values)
        if (not isinstance(png_pages, Sequence) or isinstance(png_pages, (str, bytes)) or
                not 1 <= len(png_pages) <= MAX_FINAL_OCR_PAGES):
            _reject("Independent final OCR verification input is invalid.")
        for png_bytes in png_pages:
            if _contains_source_value(self._run_png(png_bytes), values):
                _reject("Independent final OCR verifier found residual content; inspect the candidate manually.")

    def extract_final_png_text(self, png_bytes: bytes) -> str:
        """Transcribe one exact final PNG after the provisioning gate.

        There is no executable discovery or RapidOCR/PATH fallback here.  A
        caller must have supplied the same absolute, allowlisted, hash-pinned
        Tesseract executable used by the final verifier.
        """
        self._assert_provisioned()
        return self._run_png(png_bytes)

    def verify_pdf(self, pdf_bytes: bytes, absent_values: Sequence[str]) -> None:
        if not isinstance(pdf_bytes, bytes) or not pdf_bytes or self.pdf_rasterizer is None:
            _reject("Independent final OCR verification input is invalid.")
        # Do not rasterize final candidate PDF bytes until the executable and
        # runtime identity have passed the provisioning gate.
        self._assert_provisioned()
        try:
            pages = self.pdf_rasterizer(pdf_bytes)
        except Exception:
            _reject("Independent final PDF raster verification failed; inspect the candidate manually.")
        # The rasterizer receives the exact finalized PDF bytes. Its output is
        # intentionally the verifier input; pre-PDF candidate PNGs are not
        # accepted as a substitute for this path.
        self.verify_pngs(pages, absent_values)


def pdf_to_png_bytes(pdf_bytes: bytes) -> tuple[bytes, ...]:
    """Boundedly rerasterize final PDF bytes for the opt-in verifier."""
    import pypdfium2 as pdfium
    from PIL import Image

    try:
        pdf = pdfium.PdfDocument(pdf_bytes)
        try:
            if not 1 <= len(pdf) <= MAX_FINAL_OCR_PAGES:
                raise ValueError
            pages = []
            for index in range(len(pdf)):
                page = pdf[index]
                try:
                    bitmap = page.render(scale=1.0, draw_annots=True, rev_byteorder=True)
                    try:
                        image = bitmap.to_pil().convert("RGB")
                        if image.width < 16 or image.height < 16 or image.width * image.height > 2_000_000:
                            raise ValueError
                        stream = BytesIO()
                        image.save(stream, format="PNG", optimize=True)
                        data = stream.getvalue()
                        if not data or len(data) > 2_500_000:
                            raise ValueError
                        pages.append(data)
                    finally:
                        bitmap.close()
                finally:
                    page.close()
            return tuple(pages)
        finally:
            pdf.close()
    except Exception:
        _reject("Independent final PDF raster verification failed; inspect the candidate manually.")
