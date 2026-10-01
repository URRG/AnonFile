"""Hidden Word field sources must remain visible in the review transcript."""
import pytest

from app.document_extract import DocumentError
from app.document_review import review_document, run_document_review
from test_document_review import package


@pytest.mark.parametrize("part", ["word/document.xml", "word/header1.xml", "word/comments.xml"])
@pytest.mark.parametrize("field", [
    '<w:r><w:delInstrText>HYPERLINK "mailto:hidden@example.test"</w:delInstrText></w:r>',
    '<w:fldSimple w:instr="HYPERLINK &quot;mailto:hidden@example.test&quot;"><w:r><w:t>Open</w:t></w:r></w:fldSimple>',
    '<w:hyperlink w:tooltip="Contact hidden@example.test"><w:r><w:t>Open</w:t></w:r></w:hyperlink>',
])
def test_hidden_word_field_values_are_extracted_and_redacted(part, field):
    xml = ('<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:p><w:r><w:t>Visible text.</w:t></w:r>' + field + '</w:p></w:document>')
    result = review_document("fields.docx", package({part: xml}))
    surface = next(s for s in result["surfaces"] if s["id"] == part)
    assert "hidden@example.test" in surface["text"]
    assert "hidden@example.test" not in surface["candidate"]
    assert any(surface["text"][m["start"]:m["end"]] == "hidden@example.test"
               for m in surface["matches"])
    assert result["summary"]["known_values_remaining"] == 0
    assert result["release_eligible"] is False
    assert result["coverage"]["original_format_output"] == "NOT_PRODUCED"


def test_nested_textbox_paragraph_is_not_counted_twice_or_joined_to_outer_text():
    xml = ('<doc><p><r><t>Before</t></r><textbox><p><t>Email: hidden@example.test</t></p>'
           '</textbox><r><t>After</t></r></p></doc>')
    result = review_document("textbox.docx", package({"word/document.xml": xml}))
    surface = next(s for s in result["surfaces"] if s["id"] == "word/document.xml")
    assert surface["text"] == "Before\nAfter\nEmail: hidden@example.test"
    assert surface["text"].count("hidden@example.test") == 1
    assert result["summary"]["findings"]["EMAIL"] == 1
    assert "hidden@example.test" not in surface["candidate"]


@pytest.mark.parametrize("content", [
    '<r><delInstrText>' + 'x' * 101 + '</delInstrText></r>',
    '<fldSimple instr="' + 'x' * 101 + '"/>',
    '<hyperlink tooltip="' + 'x' * 101 + '"/>',
])
def test_new_hidden_field_sources_still_obey_text_resource_cap(monkeypatch, content):
    monkeypatch.setattr("app.document_extract.MAX_TEXT_BYTES", 100)
    raw = package({"word/document.xml": '<doc><p>' + content + '</p></doc>'})
    with pytest.raises(DocumentError, match="^TEXT_LIMIT$"):
        review_document("limited.docx", raw)


def test_hidden_field_review_through_disposable_worker_preserves_boundaries():
    import base64

    raw = package({"word/document.xml": '<doc><p><fldSimple instr="mailto:hidden@example.test"/></p></doc>'})
    result = run_document_review({"name": "field.docx", "review_only": True,
                                  "content_base64": base64.b64encode(raw).decode(), "ocr": False})
    surface = next(s for s in result["surfaces"] if s["id"] == "word/document.xml")
    assert "hidden@example.test" in surface["text"]
    assert "hidden@example.test" not in surface["candidate"]
    assert result["release_eligible"] is False
