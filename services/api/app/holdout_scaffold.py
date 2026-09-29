"""Freeze fictional holdout bytes before blind human annotation.

This creates an *incomplete* private manifest. It never runs a detector, reads
source values into the report, or treats empty labels as confirmed negatives.
"""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

from app.holdout_inventory import _FILE, _MAX_FILES, _MEDIA, _TEXT, HoldoutInventoryError


def scaffold_fictional_holdout(root: Path) -> dict[str, object]:
    """Create manifest.json exclusively and return source-free intake counts."""
    try:
        if root.is_symlink():
            raise HoldoutInventoryError()
        root = root.resolve(strict=True)
        files_dir = root / "files"
        manifest_path = root / "manifest.json"
        if (not files_dir.is_dir() or files_dir.is_symlink()
                or manifest_path.exists() or manifest_path.is_symlink()):
            raise HoldoutInventoryError()
        files = sorted(files_dir.iterdir(), key=lambda path: path.name)
        if not 2 <= len(files) <= _MAX_FILES:
            raise HoldoutInventoryError()
        cases: list[dict[str, object]] = []
        seen_source_hashes: set[str] = set()
        formats: Counter[str] = Counter()
        batch_count = (len(files) + 2) // 3
        base, extra = divmod(len(files), batch_count)
        batch_sizes = [base + (index < extra) for index in range(batch_count)]
        batch_ids = [f"batch-{index + 1:03d}" for index, size in enumerate(batch_sizes)
                     for _ in range(size)]
        for index, (path, batch_id) in enumerate(zip(files, batch_ids, strict=True), start=1):
            name = path.name
            kind = path.suffix.removeprefix(".").lower()
            if (not _FILE.fullmatch(name) or kind not in _TEXT | _MEDIA
                    or path.is_symlink() or not path.is_file()
                    or path.resolve(strict=True).parent != files_dir.resolve(strict=True)):
                raise HoldoutInventoryError()
            limit = 100_000 if kind in _TEXT else 500_000
            with path.open("rb") as stream:
                data = stream.read(limit + 1)
            if not 1 <= len(data) <= limit:
                raise HoldoutInventoryError()
            if kind in _TEXT and not data.decode("utf-8").strip():
                raise HoldoutInventoryError()
            source_hash = "sha256:" + hashlib.sha256(data).hexdigest()
            if source_hash in seen_source_hashes:
                raise HoldoutInventoryError()
            seen_source_hashes.add(source_hash)
            formats[kind] += 1
            cases.append({"id": f"file-{index:03d}", "batch_id": batch_id,
                          "filename": name, "format": kind,
                          "source_sha256": source_hash,
                          "labels_complete": False, "text_spans": [],
                          "media_regions": [], "protected_regions": []})
        manifest = {"schema_version": "fictional-holdout-inventory-v1", "cases": cases}
        # Exclusive creation protects any existing human-authored annotation work.
        with manifest_path.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(manifest, stream, indent=2)
            stream.write("\n")
        return {"status": "AWAITING_BLIND_ANNOTATION", "qualification": "NOT_QUALIFIED",
                "files": len(cases), "batches": batch_count,
                "formats": dict(sorted(formats.items())),
                "limitations": ["Every labels_complete field is false until a blind annotator completes review.",
                                "No detector, OCR, accuracy, or release-safety claim follows."]}
    except (OSError, ValueError, TypeError, UnicodeError, HoldoutInventoryError):
        raise HoldoutInventoryError() from None


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python -m app.holdout_scaffold <fictional-corpus-directory>", file=sys.stderr)
        raise SystemExit(2)
    try:
        print(json.dumps(scaffold_fictional_holdout(Path(sys.argv[1])), sort_keys=True))
    except HoldoutInventoryError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(2) from None
