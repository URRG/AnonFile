#!/usr/bin/env python3
"""Run bounded local review and save private JSON transcripts, not cleaned files."""
import argparse
import base64
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "api"))
from app.document_extract import DocumentError, MAX_FILE_BYTES  # noqa: E402
from app.document_review import run_document_review  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path, help="Document files or directories (not recursive)")
    parser.add_argument("--output", required=True, type=Path, help="Private directory for reports containing source text")
    parser.add_argument("--no-ocr", action="store_true", help="Skip OCR; record the resulting coverage gap")
    args = parser.parse_args()
    files = []
    for path in args.inputs:
        files.extend(sorted(child for child in path.iterdir() if child.suffix.lower() in {".pdf", ".docx", ".pptx", ".xlsx"}) if path.is_dir() else [path])
    if not files:
        parser.error("No supported document files found")
    args.output.mkdir(parents=True, exist_ok=True)
    summary = []
    for index, path in enumerate(files, 1):
        try:
            with path.open("rb") as source:
                raw = source.read(MAX_FILE_BYTES + 1)
            if len(raw) > MAX_FILE_BYTES:
                raise DocumentError("FILE_LIMIT")
            result = run_document_review({"name": path.name, "content_base64": base64.b64encode(raw).decode(),
                                          "review_only": True, "ocr": not args.no_ocr})
            filename = f"{index:02}-{path.name}.review.json"
            (args.output / filename).write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            row = {"name": path.name, "status": result["posture"], "report": filename, "sha256": result["sha256"],
                   "summary": result["summary"], "gaps": result["gaps"]}
        except DocumentError as error:
            row = {"name": path.name, "status": "FAILED", "code": str(error)}
        except OSError:
            row = {"name": path.name, "status": "FAILED", "code": "FILE_IO_ERROR"}
        summary.append(row)
        print(f"{index}/{len(files)} {path.name}: {row['status']}", flush=True)
    (args.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return int(any(row["status"] == "FAILED" for row in summary))


if __name__ == "__main__":
    raise SystemExit(main())
