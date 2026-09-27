import re

import pytest

from app.demo_contextual_surrogates import contextual_alias


def test_employee_identifier_is_an_opaque_review_reference_not_a_claimed_id():
    alias, strategy = contextual_alias("EMPLOYEE_ID", "ACME-EMP-00042", 7)

    assert strategy == "CONTEXTUAL_REVIEW_REF"
    assert alias.startswith("Employee ID [review ")
    assert "ACME" not in alias and "00042" not in alias
    assert re.fullmatch(r"Employee ID \[review 0007\]", alias)


def test_internal_url_uses_only_reserved_hostname_and_sanitizes_sensitive_parts():
    source = "https://intranet.acme.local:8443/people/EMP-42?session=secret&employee=42"
    alias, strategy = contextual_alias("INTERNAL_URL", source, 4)

    assert strategy == "INTERNAL_URL_RESERVED_DOMAIN"
    assert re.fullmatch(r"https://review-0004\.invalid/resource", alias)
    assert all(fragment not in alias for fragment in ("acme", "local", "EMP-42", "secret", "42"))


def test_address_is_a_typed_opaque_redaction_not_a_deliverable_address():
    source = "42 Example Lane, Bengaluru, Karnataka 560001, India"
    alias, strategy = contextual_alias("ADDRESS", source, 3)

    assert strategy == "CONTEXTUAL_REVIEW_REF"
    assert re.fullmatch(r"Postal address \[review 0003\]", alias)
    assert all(fragment not in alias for fragment in ("42", "Bengaluru", "560001", "India"))


@pytest.mark.parametrize("kind, source", [
    ("EMPLOYEE_ID", "EMP-9"),
    ("INTERNAL_URL", "http://private.example/path?id=9"),
    ("ADDRESS", "9 Example Road"),
])
def test_aliases_are_deterministic_and_distinct_for_distinct_batch_records(kind, source):
    first = contextual_alias(kind, source, 9)
    assert first == contextual_alias(kind, source, 9)
    assert first != contextual_alias(kind, source, 10)


@pytest.mark.parametrize("kind, source, index", [
    ("UNKNOWN", "value", 1),
    ("EMPLOYEE_ID", "", 1),
    ("EMPLOYEE_ID", "bad\nvalue", 1),
    ("EMPLOYEE_ID", "x" * 257, 1),
    ("EMPLOYEE_ID", "EMP-1", 0),
    ("EMPLOYEE_ID", "EMP-1", True),
    ("INTERNAL_URL", "mailto:employee@internal.example", 1),
    ("INTERNAL_URL", "/private/path", 1),
])
def test_unsupported_or_oversized_inputs_abstain(kind, source, index):
    assert contextual_alias(kind, source, index) is None


def test_untrusted_source_cannot_escape_alias_output():
    alias, _ = contextual_alias("ADDRESS", "<script>alert(1)</script>, 1 Main St", 11)
    assert "<" not in alias and ">" not in alias and "script" not in alias
