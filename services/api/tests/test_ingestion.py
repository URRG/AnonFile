"""Synthetic parser conformance/resource tests, never anonymization accuracy."""
import csv
import hashlib
import json

import pytest

from app.ingestion import (IngestionError, MAX_BYTES, MAX_COLUMNS, MAX_FIELD_CHARS,
                           MAX_NODES, MAX_RECORDS, parse_source)


@pytest.mark.parametrize("format", ["text", "json", "jsonl", "csv"])
def test_manifest_exact_bytes_hash_and_no_sensitive_values(format):
    sources = {"text": "  私の synthetic-secret\r\n", "json": '[{"synthetic-header":"synthetic-secret é"}]',
               "jsonl": '\n{"synthetic-header":"synthetic-secret é"}\r\n',
               "csv": 'synthetic-header\r\n"synthetic-secret é"\r\n'}
    source = sources[format]
    result = parse_source(content=source, format=format)
    assert (result.content is None) != (result.records is None)
    assert result.manifest["source_sha256"] == hashlib.sha256(source.encode("utf-8")).hexdigest()
    assert result.manifest["source_bytes"] == len(source.encode("utf-8"))
    assert result.manifest["record_count"] == 1
    assert result.manifest["format"] == format
    assert result.manifest["parser_id"] == "strict-stdlib-v1"
    assert result.manifest["limitations"]
    assert "synthetic" not in json.dumps(result.manifest)
    assert "synthetic" not in json.dumps(result.provenance)


def test_text_is_not_trimmed_or_normalized_and_has_physical_provenance():
    source = "  first\r\n\r\nlast\n"
    result = parse_source(content=source, format="text")
    assert result.content == source
    assert result.provenance == ({"record_index": 0, "line_start": 1, "line_end": 3},)
    assert "blank_lines" not in result.manifest


def test_json_preserves_nested_types_and_array_position():
    records = [{"text": "0042", "items": [None, True, False, {"integer": 9007199254740993, "float": 0.1}]}, {}]
    result = parse_source(content=json.dumps(records), format="json")
    assert result.records == records
    assert result.provenance == ({"record_index": 0}, {"record_index": 1})


@pytest.mark.parametrize("source", ['{"a":1}', '[1]', '[null]', '[[]]', '[]', 'null',
    '[{"a":1,"a":2}]', '[{"a":{"password":"first","passw\\u006frd":"second"}}]',
    '[{"a":NaN}]', '[{"a":Infinity}]', '[{"a":-Infinity}]', '[{"a":1e999}]',
    '[{"a":1e-999}]', '[{"a":9007199254740993.0}]', '[{"a":0.10000000000000001}]',
    '[{"a":"\\ud800"}]', '[{"\\udfff":1}]', '[{"a":1},]', '[{"a":1}] garbage',
    '[{"a":' + '9' * 5000 + '}]'])
def test_json_invalid_unsupported_or_lossy_source_rejected(source):
    with pytest.raises(IngestionError) as error:
        parse_source(content=source, format="json")
    assert source not in str(error.value)
    assert "password" not in str(error.value)


def test_jsonl_blank_line_accounting_and_line_positions():
    source = '\r\n{"a":1}\r \t\n{"a":2}\n\n'
    result = parse_source(content=source, format="jsonl")
    assert result.records == [{"a": 1}, {"a": 2}]
    assert result.manifest["blank_lines"] == 3
    assert result.provenance == ({"record_index": 0, "line_start": 2, "line_end": 2},
                                 {"record_index": 1, "line_start": 4, "line_end": 4})


def test_jsonl_unicode_line_separator_is_a_string_character_not_a_record():
    result = parse_source(content='{"a":"one\u2028two\u2029three"}\n', format="jsonl")
    assert result.records == [{"a": "one\u2028two\u2029three"}]
    assert result.provenance[0]["line_end"] == 1


@pytest.mark.parametrize("suffix", ['not-json', '[]', '{"a":NaN}', '{"a":1,"a":2}',
                                    '{"a":"\\ud800"}', '{"a":"literal\nnewline"}'])
def test_jsonl_has_no_partial_acceptance(suffix):
    with pytest.raises(IngestionError):
        parse_source(content='{"a":"first valid record"}\n' + suffix, format="jsonl")


def test_csv_strings_formula_and_newline_provenance():
    source = 'identifier,quantity,note\r\n001,42,"first\r\nsecond"\r\n002,,"=1+1"\r\n'
    result = parse_source(content=source, format="csv")
    assert result.records == [{"identifier": "001", "quantity": "42", "note": "first\r\nsecond"},
                              {"identifier": "002", "quantity": "", "note": "=1+1"}]
    assert result.provenance == ({"record_index": 0, "line_start": 2, "line_end": 3},
                                 {"record_index": 1, "line_start": 4, "line_end": 4})
    assert "spreadsheet formulas" in " ".join(result.manifest["limitations"])


def test_csv_embedded_commas_quotes_and_blank_physical_line_inside_field():
    result = parse_source(content='left,right\n"a,b","a ""quoted"" value\n\nlast"\n', format="csv")
    assert result.records == [{"left": "a,b", "right": 'a "quoted" value\n\nlast'}]
    assert result.provenance == ({"record_index": 0, "line_start": 2, "line_end": 4},)


@pytest.mark.parametrize("source", ["a,a\n1,2", ",b\n1,2", '"",b\n1,2', " ,b\n1,2", "a\n",
    "a\n\nvalue", "a\n   \nvalue", 'a\n""\nvalue', "a,b\n,\n", "a,b\n1", "a\n1,2",
    'a\n"unterminated', 'a\nplain"quote', 'a\n"closed" garbage', 'a\n "quote"',
    '"multi\nheader",b\n1,2', "a\nbad\x00value", "\na\nvalue"])
def test_csv_strict_headers_rows_and_quoting(source):
    with pytest.raises(IngestionError):
        parse_source(content=source, format="csv")


def test_csv_preserves_distinct_untrimmed_headers():
    result = parse_source(content="a, a\nx,y", format="csv")
    assert result.records == [{"a": "x", " a": "y"}]


@pytest.mark.parametrize("kwargs", [{"format": "xml", "content": "x"}, {"format": [], "content": "x"},
    {"format": "text", "content": b"bytes"}, {"format": "text", "content": ""},
    {"format": "text", "content": " \r\n\t"}])
def test_input_contract(kwargs):
    with pytest.raises(IngestionError):
        parse_source(**kwargs)


@pytest.mark.parametrize("format", ["text", "json", "jsonl", "csv"])
def test_invalid_unicode_and_bom_rejected_without_guessing(format):
    for source in ("\ud800", "\ufeffsource"):
        with pytest.raises(IngestionError):
            parse_source(content=source, format=format)


def test_utf8_byte_limit_applies_before_parsing():
    assert len(parse_source(content="é" * (MAX_BYTES // 2), format="text").content) == MAX_BYTES // 2
    with pytest.raises(IngestionError):
        parse_source(content="é" * (MAX_BYTES // 2 + 1), format="text")
    with pytest.raises(IngestionError):
        parse_source(content="x" * (MAX_BYTES + 1), format="text")


@pytest.mark.parametrize("format", ["json", "jsonl", "csv"])
def test_record_limit(format):
    sources = {"json": "[" + ",".join("{}" for _ in range(MAX_RECORDS + 1)) + "]",
               "jsonl": "{}\n" * (MAX_RECORDS + 1), "csv": "header\n" + "value\n" * (MAX_RECORDS + 1)}
    with pytest.raises(IngestionError):
        parse_source(content=sources[format], format=format)


def test_field_limits_apply_to_values_and_keys_with_boundary_acceptance():
    for source, format in ((json.dumps([{"a": "x" * MAX_FIELD_CHARS}]), "json"),
                           ("a\n" + "x" * MAX_FIELD_CHARS, "csv")):
        assert parse_source(content=source, format=format).manifest["record_count"] == 1
    for source, format in ((json.dumps([{"a": "x" * (MAX_FIELD_CHARS + 1)}]), "json"),
                           (json.dumps([{("x" * (MAX_FIELD_CHARS + 1)): 1}]), "json"),
                           ("a\n" + "x" * (MAX_FIELD_CHARS + 1), "csv")):
        with pytest.raises(IngestionError):
            parse_source(content=source, format=format)


def test_column_limit_and_no_global_csv_setting_mutation():
    before = csv.field_size_limit()
    valid = ",".join(f"field{i}" for i in range(MAX_COLUMNS)) + "\n" + ",".join("v" for _ in range(MAX_COLUMNS))
    assert len(parse_source(content=valid, format="csv").records[0]) == MAX_COLUMNS
    invalid = valid.split("\n")[0] + ",extra\n" + valid.split("\n")[1] + ",extra"
    with pytest.raises(IngestionError):
        parse_source(content=invalid, format="csv")
    assert csv.field_size_limit() == before


def test_structure_depth_and_node_limits():
    source = '[{"a":' + '[' * 33 + '1' + ']' * 33 + '}]'
    with pytest.raises(IngestionError):
        parse_source(content=source, format="json")
    source = '[{"a":' + '[' * 2000 + '1' + ']' * 2000 + '}]'
    with pytest.raises(IngestionError):
        parse_source(content=source, format="json")
    source = json.dumps([{"a": [None] * MAX_NODES}])
    with pytest.raises(IngestionError):
        parse_source(content=source, format="json")


def test_csv_repeated_header_expansion_is_bounded_before_caller_serializes():
    source = "h" * MAX_FIELD_CHARS + "\n" + "v\n" * 100
    assert len(source.encode("utf-8")) < MAX_BYTES
    with pytest.raises(IngestionError, match="Normalized source exceeds the byte limit"):
        parse_source(content=source, format="csv")


@pytest.mark.parametrize("newline", ["\r", "\n", "\r\n"])
def test_csv_physical_newline_variants(newline):
    result = parse_source(content=f'header{newline}"first{newline}second"{newline}last{newline}', format="csv")
    assert result.provenance == ({"record_index": 0, "line_start": 2, "line_end": 3},
                                 {"record_index": 1, "line_start": 4, "line_end": 4})


def test_error_messages_do_not_echo_source_paths_headers_or_values():
    for source, format in (('secret-header,secret-header\nsecret-value,secret-value', "csv"),
                           ('[{"secret-header": "secret-value", "secret-header": null}]', "json"),
                           ('{"secret-header":"secret-value"}\nsecret-broken-value', "jsonl")):
        with pytest.raises(IngestionError) as error:
            parse_source(content=source, format=format)
        assert "secret" not in str(error.value)
