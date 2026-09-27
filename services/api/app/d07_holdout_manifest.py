"""Bind a supplied D07 holdout manifest to supplied final artifact bytes.

This is deliberately a preflight check, not a scorer, rights verifier, or
release gate.  A caller must obtain the manifest digest from a trusted frozen
holdout custodian; supplying a digest beside a manifest does not establish
independence, annotation quality, or legal rights.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


VERSION = "d07-frozen-holdout-manifest-v1"
_MAX_MANIFEST_BYTES = 1_000_000
_MAX_ARTIFACTS = 10_000
_MAX_ARTIFACT_BYTES = 100_000_000
_MAX_TOTAL_ARTIFACT_BYTES = 500_000_000
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_FORMATS = frozenset({"text", "csv", "json", "jsonl", "pdf", "image"})
_ENTITY_TYPES = frozenset({"EMAIL", "PHONE", "PERSON", "ADDRESS", "ORGANIZATION", "OTHER"})


class D07HoldoutManifestError(ValueError):
    """Fixed error that never exposes holdout identifiers or contents."""


@dataclass(frozen=True)
class FinalArtifact:
    """Opaque artifact identifier and untouched final bytes supplied for binding."""

    artifact_id: str
    payload: bytes


def _reject() -> None:
    raise D07HoldoutManifestError("D07 frozen holdout manifest verification failed; no report was produced.")


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _reject()
        result[key] = value
    return result


def _digest(value: object) -> bool:
    return type(value) is str and _DIGEST.fullmatch(value) is not None


def _parse_manifest(raw: bytes) -> dict[str, Any]:
    try:
        if type(raw) is not bytes or not raw or len(raw) > _MAX_MANIFEST_BYTES:
            _reject()
        manifest = json.loads(raw.decode("utf-8"), object_pairs_hook=_strict_object)
        if not isinstance(manifest, dict) or set(manifest) != {"schema_version", "artifacts"}:
            _reject()
        if manifest["schema_version"] != VERSION or type(manifest["artifacts"]) is not list:
            _reject()
        return manifest
    except (UnicodeError, TypeError, ValueError, RecursionError):
        _reject()


def bind_final_artifacts(*, manifest_bytes: bytes, expected_manifest_sha256: str,
                         artifacts: tuple[FinalArtifact, ...]) -> dict[str, object]:
    """Verify complete final-byte coverage and return only aggregate corpus shape.

    ``expected_manifest_sha256`` is intentionally a required external trust
    input. This function checks a pin; it cannot establish who froze it.
    """
    try:
        if (type(manifest_bytes) is not bytes or not _digest(expected_manifest_sha256)
                or hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_sha256
                or type(artifacts) is not tuple):
            _reject()
        entries = _parse_manifest(manifest_bytes)["artifacts"]
        expected: dict[str, tuple[str, str, tuple[str, ...]]] = {}
        for entry_count, entry in enumerate(entries, start=1):
            if entry_count > _MAX_ARTIFACTS or type(entry) is not dict or set(entry) != {"artifact_id", "format", "final_sha256", "entity_types"}:
                _reject()
            artifact_id, format_name, final_sha256, entity_types = (entry["artifact_id"], entry["format"],
                                                                      entry["final_sha256"], entry["entity_types"])
            if (type(artifact_id) is not str or _ID.fullmatch(artifact_id) is None or artifact_id in expected
                    or type(format_name) is not str or format_name not in _FORMATS or not _digest(final_sha256)
                    or type(entity_types) is not list or not entity_types
                    or any(type(item) is not str or item not in _ENTITY_TYPES for item in entity_types)
                    or len(set(entity_types)) != len(entity_types)):
                _reject()
            expected[artifact_id] = (format_name, final_sha256, tuple(entity_types))
        if not expected:
            _reject()
        supplied: dict[str, bytes] = {}
        total_bytes = 0
        for artifact_count, artifact in enumerate(artifacts, start=1):
            if (artifact_count > _MAX_ARTIFACTS or type(artifact) is not FinalArtifact or type(artifact.artifact_id) is not str
                    or _ID.fullmatch(artifact.artifact_id) is None or artifact.artifact_id in supplied
                    or type(artifact.payload) is not bytes or not 1 <= len(artifact.payload) <= _MAX_ARTIFACT_BYTES):
                _reject()
            total_bytes += len(artifact.payload)
            if total_bytes > _MAX_TOTAL_ARTIFACT_BYTES:
                _reject()
            supplied[artifact.artifact_id] = artifact.payload
        if len(supplied) != len(expected) or set(supplied) != set(expected):
            _reject()
        for artifact_id, payload in supplied.items():
            if hashlib.sha256(payload).hexdigest() != expected[artifact_id][1]:
                _reject()
        by_format = {name: 0 for name in sorted(_FORMATS)}
        by_type = {name: 0 for name in sorted(_ENTITY_TYPES)}
        for format_name, _, entity_types in expected.values():
            by_format[format_name] += 1
            for entity_type in entity_types:
                by_type[entity_type] += 1
        return {
            "schema_version": VERSION,
            "classification": "FROZEN_HOLDOUT_ARTIFACT_BINDING_ONLY",
            "qualification": "NOT_QUALIFIED",
            "status": "FINAL_ARTIFACTS_BOUND",
            "aggregate": {"artifacts": len(expected),
                          "by_format": {key: value for key, value in by_format.items() if value},
                          "artifacts_by_entity_type": {key: value for key, value in by_type.items() if value}},
            "limitations": [
                "The manifest pin must be obtained from a trusted frozen-holdout custodian; this check cannot verify custody.",
                "This binds supplied final bytes only; it does not verify rights, annotation independence, annotation completeness, scoring, OCR, or pixel visibility.",
                "This report is not a qualification, release authorization, or legal determination.",
            ],
        }
    except (D07HoldoutManifestError, TypeError, ValueError, RecursionError):
        _reject()
