import pytest

from app.contracts import PayloadError
from app.demo_contextual import contextual_spans


def values(text: str):
    return [(text[start:end], kind) for start, end, kind in contextual_spans(text)]


def test_detects_explicitly_labelled_employee_ids_and_preserves_offsets():
    text = "Owner: Ana; Employee ID: HS-EMP-1042; employee-id=ACME-7"

    spans = contextual_spans(text)

    assert values(text) == [("HS-EMP-1042", "EMPLOYEE_ID"), ("ACME-7", "EMPLOYEE_ID")]
    assert all(text[start:end] == value for (start, end, _), (value, _) in zip(spans, values(text)))


def test_detects_internal_hosts_and_explicitly_labelled_links_only():
    text = (
        "See https://confluence.example.test/team/runbook, "
        "https://service.ops.internal/a and Internal URL: https://public.example.com/pr/4. "
        "Public https://openai.com/research is not a finding."
    )

    assert values(text) == [
        ("https://confluence.example.test/team/runbook", "INTERNAL_URL"),
        ("https://service.ops.internal/a", "INTERNAL_URL"),
        ("https://public.example.com/pr/4", "INTERNAL_URL"),
    ]


def test_ocr_label_on_immediately_preceding_line_and_public_review_link():
    text = (
        "Internal URL:\r\nhttps://private.acme.local/runbook\r\n"
        "Review link: https://public.example.com/pr/4\r\n"
        "Internal URL:\r\n\r\nhttps://public.example.com/unrelated\r\n"
        "Intranet link:\nhttps://intranet.acme.com/wiki"
    )
    assert values(text) == [
        ("https://private.acme.local/runbook", "INTERNAL_URL"),
        ("https://intranet.acme.com/wiki", "INTERNAL_URL"),
    ]


def test_detects_street_shaped_address_in_office_and_signature_forms():
    text = (
        "Office: Harborline Systems, 25 Sample Street, Example City, CA 90000\n"
        "Regards,\n25 Sample Street\nExample City, CA 90000"
    )

    assert values(text) == [
        ("25 Sample Street, Example City, CA 90000", "ADDRESS"),
        ("25 Sample Street\nExample City, CA 90000", "ADDRESS"),
    ]
    assert values("Bluebird Air, 100 Example Quay, Example City, CA 90000") == [
        ("100 Example Quay, Example City, CA 90000", "ADDRESS")]


def test_ocr_line_forms_duplicates_and_overlong_values_are_bounded():
    text = (
        "Employee ID\nHS-EMP-1042\nEmployee ID: HS-EMP-1042\n"
        "Runbook link:\nhttps://github.example.test/a\n"
        "Employee ID: " + "A-" + "B" * 81
    )
    with pytest.raises(PayloadError, match="employee identifier exceeds"):
        contextual_spans(text)
    assert values(text.rsplit("Employee ID:", 1)[0]) == [
        ("HS-EMP-1042", "EMPLOYEE_ID"),
        ("HS-EMP-1042", "EMPLOYEE_ID"),
        ("https://github.example.test/a", "INTERNAL_URL"),
    ]


def test_bare_numbers_public_urls_and_non_postal_streets_do_not_match():
    text = (
        "Ticket DEMO-1042, order 1042, https://example.com/help, "
        "and 25 Sample Street are ordinary text."
    )

    assert contextual_spans(text) == []


def test_employee_shape_in_signature_and_generic_id_label_is_sensitive():
    text = "Best regards, Isha Rao | BA-EMP-2041\nOwner ID: HS-EMP-1057"
    assert values(text) == [("BA-EMP-2041", "EMPLOYEE_ID"),
                            ("HS-EMP-1057", "EMPLOYEE_ID")]
