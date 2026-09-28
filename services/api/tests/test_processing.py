"""Synthetic module-level regression tests, not measured production accuracy."""
import copy
import json

import pytest

from app.contracts import PayloadError
from app.processing import MAX_BYTES, MAX_RECORDS, detect_text, process_payload


@pytest.mark.parametrize("secret", ["password=fictional-secret", '"password": "fictional secret with spaces"',
    "'api_key': 'fictional secret'", 'password="fictional \\"quoted\\" value"',
    "pass\u200bword=fictional-secret", "ｐａｓｓｗｏｒｄ=fictional-secret", "access-token: fictional-secret"])
def test_credentials_are_critical_and_suppressed(secret):
    result = process_payload(content=secret)
    assert result.critical_detected
    assert "fictional" not in result.output
    assert any(f.entity_type == "CREDENTIAL" for f in result.findings)
    assert result.actual_operations[0].action.value == "REDACT"


def test_original_unicode_offsets_and_no_values_in_findings():
    text = "🙂東京 before pass\u200bword=synthetic after"
    spans = detect_text(text)
    assert len(spans) == 1
    assert text[spans[0].start:spans[0].end] == "pass\u200bword=synthetic"
    result = process_payload(content=text)
    assert result.output == "🙂東京 before [REDACTED_CREDENTIAL] after"
    assert "synthetic" not in repr(result.findings)


@pytest.mark.parametrize(("text", "kind", "critical"), [
    ("+91 98765 43210", "PHONE", False), ("9876543210", "PHONE", False),
    ("1234 5678 9012", "AADHAAR", True), ("1234-5678-9012", "AADHAAR", True),
    ("4111 1111 1111 1111", "CARD", True), ("4111-1111-1111-1111", "CARD", True),
    ("4111111111111111111", "CARD", True), ("4111 1111 1111 1111 9999", "SENSITIVE_NUMBER", True),
])
def test_number_candidates_are_wholly_suppressed(text, kind, critical):
    result = process_payload(content=text)
    assert result.output == f"[REDACTED_{kind}]"
    assert result.critical_detected == critical
    assert not any(char.isdecimal() for char in result.output)
    assert len(detect_text(text)) == 1


def test_contextual_accounts_override_phone_and_card_length_guesses():
    text = "Pay to GB82 WEST 1234 5698 7654 32. Bank account 1234567890; routing 021000021."
    spans = detect_text(text)
    assert [(span.entity_type, text[span.start:span.end]) for span in spans] == [
        ("FINANCIAL_ACCOUNT", "GB82 WEST 1234 5698 7654 32"),
        ("FINANCIAL_ACCOUNT", "1234567890"),
        ("FINANCIAL_ACCOUNT", "021000021"),
    ]
    candidate = process_payload(content=text).output
    assert "GB82" not in candidate and "1234567890" not in candidate
    assert candidate.count("[REDACTED_FINANCIAL_ACCOUNT]") == 3


def test_bank_field_is_financial_not_phone_or_card():
    result = process_payload(records=[{"bank_account": "1234567890", "routing_number": "021000021"}])
    assert result.output == [{"bank_account": "[REDACTED_FINANCIAL_ACCOUNT]",
                              "routing_number": "[REDACTED_FINANCIAL_ACCOUNT]"}]
    assert {finding.entity_type for finding in result.findings} == {"FINANCIAL_ACCOUNT"}


@pytest.mark.parametrize(("text", "value", "kind"), [
    ("IPv6 2001:db8::1.", "2001:db8::1", "IP_ADDRESS"),
    ("IPv6 2001:db8:aa:bb:cc:dd:ee:ff", "2001:db8:aa:bb:cc:dd:ee:ff", "IP_ADDRESS"),
    ("MAC 02:42:AC:11:00:02", "02:42:AC:11:00:02", "DEVICE_ID"),
    ("VIN 1HGCM82633A004352", "1HGCM82633A004352", "VEHICLE_ID"),
    ("Username @riya.dev", "@riya.dev", "USER_ID"),
    ("Passport number K1234567", "K1234567", "GOVERNMENT_ID"),
    ("Driver's license number D87654321", "D87654321", "GOVERNMENT_ID"),
    ("Born on 1990-01-01", "1990-01-01", "DATE_OF_BIRTH"),
])
def test_bounded_personal_identifier_detection(text, value, kind):
    spans = detect_text(text)
    assert [(text[span.start:span.end], span.entity_type) for span in spans] == [(value, kind)]
    result = process_payload(content=text)
    assert value not in result.output
    assert len(result.findings) == 1


def test_bounded_identifier_rules_do_not_promote_lookalike_prose():
    text = "Visit https://example.invalid/a:bb:cc; meeting at 12:34:56; account balance is 12345."
    assert detect_text(text) == ()


def test_new_identifier_fields_are_redacted_with_explicit_taxonomy():
    record = {"mac_address": "02:42:AC:11:00:02", "vehicle_identification_number": "1HGCM82633A004352",
              "user_id": "riya.dev", "passport_number": "K1234567"}
    result = process_payload(records=[record])
    assert {finding.entity_type for finding in result.findings} == {
        "DEVICE_ID", "VEHICLE_ID", "USER_ID", "GOVERNMENT_ID"}
    assert all(value not in str(result.output) for value in record.values())


def test_overlap_union_keeps_credential_severity_and_no_fragments():
    text = 'password="4111 1111 1111 1111" and user@example.invalid'
    spans = detect_text(text)
    assert all(a.end <= b.start for a, b in zip(spans, spans[1:]))
    result = process_payload(content=text)
    assert result.output == '[REDACTED_CREDENTIAL] and [REDACTED_EMAIL]'
    assert result.changed_spans == 2


def test_authorization_bearer_value_wholly_suppressed():
    result = process_payload(content="Authorization: Bearer synthetic.token_value-123")
    assert result.output == "[REDACTED_CREDENTIAL]"
    assert result.critical_detected


def test_plus_prefixed_card_not_downgraded_to_phone():
    result = process_payload(content="+4111 1111 1111 111")
    assert result.output == "[REDACTED_CARD]"
    assert result.critical_detected


def test_nested_typed_records_preserve_non_sensitive_types_and_input():
    records = [{"password": "fictional secret", "profile": {"name": "Example Person", "address": "12 Imaginary Avenue"},
                "government_id": 123456789012, "enabled": True, "count": 4, "ratio": 1.25,
                "items": [None, {"message": "user@example.invalid"}], "empty": ""}]
    before = copy.deepcopy(records)
    result = process_payload(records=records)
    assert records == before
    assert isinstance(result.output, list)
    assert result.output[0]["government_id"] is None
    assert result.output[0]["profile"]["address"] == "[REDACTED_ADDRESS]"
    assert result.output[0]["enabled"] is True
    assert result.output[0]["count"] == 4
    assert result.output[0]["ratio"] == 1.25
    assert result.output[0]["empty"] == ""
    assert result.output[0]["items"][0] is None
    assert "fictional secret" not in json.dumps(result.output)
    assert json.loads(json.dumps(result.output, allow_nan=False)) == result.output


@pytest.mark.parametrize("record", [
    {"password": {"fictional-secret-value": True}}, {"name": {"Ada Example": True}},
    {"address": {"Imaginary Avenue": 12}}, {"password": {"name": "synthetic"}},
    {"password": [{"fictional-secret-value": True}]}, {"address": ["Imaginary Avenue"]},
    {"card_number": {}}, {"cvv": []},
])
def test_sensitive_containers_rejected_without_key_leakage(record):
    for mode in ("external_anonymized", "restricted_pseudonymized"):
        with pytest.raises(PayloadError) as caught:
            process_payload(records=[record], mode=mode)
        assert str(caught.value) == "Container-valued sensitive fields are unsupported."


def test_numeric_value_in_unknown_field_is_null_not_bare_marker():
    result = process_payload(records=[{"identifier": 123456789012}])
    assert result.output == [{"identifier": None}]


def test_hidden_and_compatibility_sensitive_field_names():
    result = process_payload(records=[{"pass\u200bword": "synthetic", "ＥＭＡＩＬ": "arbitrary"}])
    assert result.critical_detected
    assert all(value.startswith("[REDACTED_") for value in result.output[0].values())


@pytest.mark.parametrize("key", ["a@example.invalid", "password=synthetic", "4111 1111 1111 1111"])
def test_sensitive_keys_rejected_without_renaming_or_echo(key):
    with pytest.raises(PayloadError) as caught:
        process_payload(records=[{key: "value", "[REDACTED_EMAIL]": "existing"}])
    assert str(caught.value) == "Sensitive object keys are unsupported."
    assert key not in str(caught.value)


@pytest.mark.parametrize("kwargs", [{}, {"content": ""}, {"content": " \n\t"}, {"records": []},
    {"content": "text", "records": [{}]}, {"content": 123}, {"records": ["text"]},
    {"records": {"a": "b"}}, {"records": [{1: "value"}]},
    {"content": "text", "mode": "approve"}, {"content": "text", "mode": []}])
def test_invalid_payload_contract(kwargs):
    with pytest.raises(PayloadError):
        process_payload(**kwargs)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), b"bytes", {1, 2}, (1, 2), object()])
def test_non_json_rejected(value):
    with pytest.raises(PayloadError):
        process_payload(records=[{"value": value}])


def test_cycles_rejected_but_shared_references_are_allowed():
    cycle = {}
    cycle["cycle"] = cycle
    with pytest.raises(PayloadError):
        process_payload(records=[cycle])
    common = {"safe": 7}
    assert process_payload(records=[common, common]).output == [common, common]


def test_bounds_bytes_utf8_records_depth_nodes():
    with pytest.raises(PayloadError):
        process_payload(content="é" * (MAX_BYTES // 2 + 1))
    with pytest.raises(PayloadError):
        process_payload(records=[{"value": "é" * (MAX_BYTES // 2)}])
    with pytest.raises(PayloadError):
        process_payload(records=[{}] * (MAX_RECORDS + 1))
    nested = 1
    for _ in range(33):
        nested = [nested]
    with pytest.raises(PayloadError):
        process_payload(records=[{"value": nested}])
    with pytest.raises(PayloadError):
        process_payload(records=[{"value": [None] * 100_001}])


def test_lone_surrogate_rejected_safely():
    for kwargs in ({"content": "\ud800"}, {"records": [{"value": "\ud800"}]}):
        with pytest.raises(PayloadError):
            process_payload(**kwargs)


def test_restricted_aliases_exact_case_and_release_local():
    result = process_payload(content="A@example.invalid a@example.invalid A@example.invalid", mode="restricted_pseudonymized")
    assert result.output == "[EMAIL_0001] [EMAIL_0002] [EMAIL_0001]"
    assert "cryptographic" in " ".join(result.limitations)
    assert process_payload(content="a@example.invalid", mode="restricted_pseudonymized").output == "[EMAIL_0001]"
    assert process_payload(content="password=synthetic", mode="restricted_pseudonymized").output == "[REDACTED_CREDENTIAL]"


def test_actual_operations_distinguish_redaction_pseudonymization_and_nullification():
    external = process_payload(records=[{"email": "ada@example.test", "government_id": 123456789012}])
    assert {(item.entity_type, item.action.value, item.count) for item in external.actual_operations} == {
        ("EMAIL", "REDACT", 1), ("GOVERNMENT_ID", "NULLIFY", 1),
    }
    restricted = process_payload(content="ada@example.test", mode="restricted_pseudonymized")
    assert [(item.entity_type, item.action.value, item.count) for item in restricted.actual_operations] == [
        ("EMAIL", "PSEUDONYMIZE", 1),
    ]


@pytest.mark.parametrize("marker", ["[EMAIL_0001]", "[PERSON_NAME_10000]", "[email_0001]",
    "［ＥＭＡＩＬ＿０００１］", "[EMAIL_00\u200b01]", "[REDACTED_CREDENTIAL]",
    "[GENERALIZED_QUASI_IDENTIFIER]"])
@pytest.mark.parametrize("mode", ["external_anonymized", "restricted_pseudonymized"])
def test_source_marker_namespace_is_reserved_everywhere(marker, mode):
    for payload in ({"content": f"Existing {marker}, contact ada@example.invalid"},
                    {"records": [{"message": marker}, {"email": "ada@example.invalid"}]},
                    {"records": [{marker: "safe", "email": "ada@example.invalid"}]},
                    {"records": [{"password": marker}]}):
        with pytest.raises(PayloadError) as caught:
            process_payload(**payload, mode=mode)
        assert str(caught.value) == "Source transformation markers are unsupported."


@pytest.mark.parametrize("field", ["card_number", "government_id", "cvv", "name", "address", "dob"])
def test_credentials_win_equal_critical_field_precedence(field):
    result = process_payload(records=[{field: "password=fictional-secret"}], mode="restricted_pseudonymized")
    assert result.output == [{field: "[REDACTED_CREDENTIAL]"}]
    assert result.findings[0].entity_type == "CREDENTIAL"
    assert result.critical_detected


def test_payment_secret_field_not_downgraded_to_critical_card_alias():
    result = process_payload(records=[{"cvv": "4111111111111111"}], mode="restricted_pseudonymized")
    assert result.output == [{"cvv": "[REDACTED_PAYMENT_SECRET]"}]
    assert result.findings[0].entity_type == "PAYMENT_SECRET"


def test_unqualified_text_always_carries_explicit_limitations():
    result = process_payload(content="Example Person lives on Imaginary Avenue and has a condition.")
    assert not result.findings
    assert result.limitations
    assert "no privacy qualification" in " ".join(result.limitations)
    assert "health" in " ".join(result.limitations)


def test_ip_validation_and_pan_candidate():
    assert detect_text("300.400.500.600") == ()
    assert [s.entity_type for s in detect_text("192.0.2.1 ABCDE1234F")] == ["IP_ADDRESS", "PAN"]


def test_contextual_health_business_and_quasi_rules_remove_values_without_claiming_semantic_detection():
    text = "diagnosis: synthetic-condition; internal roadmap: synthetic-roadmap; age: 47"
    result = process_payload(content=text)
    assert {finding.entity_type for finding in result.findings} == {
        "HEALTH_SENSITIVE", "BUSINESS_CONFIDENTIAL", "QUASI_IDENTIFIER",
    }
    assert "synthetic-condition" not in result.output
    assert "synthetic-roadmap" not in result.output
    assert "47" not in result.output
    assert "[GENERALIZED_QUASI_IDENTIFIER]" in result.output
    assert {(item.entity_type, item.action.value) for item in result.actual_operations} == {
        ("HEALTH_SENSITIVE", "REDACT"),
        ("BUSINESS_CONFIDENTIAL", "REDACT"),
        ("QUASI_IDENTIFIER", "GENERALIZE"),
    }
    assert "not qualified category coverage" in " ".join(result.limitations)


def test_sensitive_structured_fields_apply_bounded_actions_and_preserve_input():
    records = [{"diagnosis": "synthetic-condition", "trade_secret": "synthetic-plan", "postal_code": "12345"}]
    before = copy.deepcopy(records)
    result = process_payload(records=records)
    assert records == before
    assert result.output == [{"diagnosis": "[REDACTED_HEALTH_SENSITIVE]",
                              "trade_secret": "[REDACTED_BUSINESS_CONFIDENTIAL]",
                              "postal_code": "[GENERALIZED_QUASI_IDENTIFIER]"}]
    assert {(item.entity_type, item.action.value, item.count) for item in result.actual_operations} == {
        ("HEALTH_SENSITIVE", "REDACT", 1),
        ("BUSINESS_CONFIDENTIAL", "REDACT", 1),
        ("QUASI_IDENTIFIER", "GENERALIZE", 1),
    }


def test_bare_category_words_do_not_create_contextual_findings():
    assert detect_text("Allergy and confidential planning are ordinary words here.") == ()


@pytest.mark.parametrize(("label", "kind", "marker"), [
    ("diagnosis", "HEALTH_SENSITIVE", "[REDACTED_HEALTH_SENSITIVE]"),
    ("internal roadmap", "BUSINESS_CONFIDENTIAL", "[REDACTED_BUSINESS_CONFIDENTIAL]"),
    ("age", "QUASI_IDENTIFIER", "[GENERALIZED_QUASI_IDENTIFIER]"),
])
def test_contextual_value_larger_than_legacy_rule_cap_is_wholly_transformed(label, kind, marker):
    # Regression: a bounded regex prefix once left the remaining tail as raw
    # candidate text.  The full delimited value must be consumed as one span.
    value = "x" * 300
    result = process_payload(content=f"{label}: {value}; safe")
    assert result.output == f"{marker}; safe"
    assert value not in result.output
    assert [(item.entity_type, item.count) for item in result.findings] == [(kind, 1)]
