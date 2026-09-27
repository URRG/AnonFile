"""Deterministic, batch-local review surrogates for contextual values.

The aliases in this module are deliberately not replacements for production
identifiers or addresses.  They are bounded review labels only: the caller
must provide the original value and its batch-local index explicitly.
"""
from __future__ import annotations

import re
from urllib.parse import urlsplit


MAX_SOURCE_LENGTH = 256
MAX_INDEX = 999_999
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _safe_input(source: object, index: object) -> bool:
    return (
        isinstance(source, str)
        and 0 < len(source) <= MAX_SOURCE_LENGTH
        and _CONTROL.search(source) is None
        and type(index) is int
        and 1 <= index <= MAX_INDEX
    )


def _is_http_url(source: str) -> bool:
    """Accept only absolute HTTP(S) URLs with a host; do not normalize them."""
    try:
        parsed = urlsplit(source)
    except ValueError:
        return False
    return parsed.scheme.casefold() in {"http", "https"} and bool(parsed.hostname)


def contextual_alias(kind: str, source: str, index: int) -> tuple[str, str] | None:
    """Return a non-deliverable review surrogate for one supported context.

    ``index`` is the batch-local identity. Reusing it for the same source
    returns the same label; callers must allocate unique indices for distinct
    records. No source fragment, host, path, query, or postal component is
    emitted or hashed into the label.
    """
    if not _safe_input(source, index):
        return None
    token = f"{index:04d}"

    if kind == "EMPLOYEE_ID":
        # This is expressly a review reference, not an identifier an issuer
        # could issue or validate as an employee credential.
        return f"Employee ID [review {token}]", "CONTEXTUAL_REVIEW_REF"

    if kind == "INTERNAL_URL":
        if not _is_http_url(source):
            return None
        # A static path and RFC-reserved .invalid host ensure neither a source
        # host nor an identifier-bearing path/query becomes deliverable.
        return f"https://review-{token}.invalid/resource", "INTERNAL_URL_RESERVED_DOMAIN"

    if kind == "ADDRESS":
        # Never emit city, region, postcode, street, or a plausible address.
        return f"Postal address [review {token}]", "CONTEXTUAL_REVIEW_REF"

    return None
