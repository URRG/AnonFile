"""Synthetic regressions for the public-document audit; no uploaded originals."""
import asyncio
import base64
from io import BytesIO
from zipfile import ZIP_DEFLATED, ZipFile

import pytest
from pypdf import PdfWriter
from pypdf.generic import ArrayObject, DecodedStreamObject, DictionaryObject, NameObject, TextStringObject

from app.document_extract import DocumentError, extract_office, extract_pdf
from app.document_review import decode_review_payload, review_document, run_document_review
from app.independent_residual import scan_residual_candidate
from app.main import BodyLimitMiddleware
from app.processing import detect_text, process_payload
from test_access import auth, client
from test_demo_inspect_api import demo_client


def package(parts, extension="docx"):
    stream = BytesIO()
    main = {"docx": "word/document.xml", "pptx": "ppt/presentation.xml", "xlsx": "xl/workbook.xml"}[extension]
    with ZipFile(stream, "w", ZIP_DEFLATED) as archive:
        for name, value in {"[Content_Types].xml": "<Types/>", main: "<root/>", **parts}.items():
            archive.writestr(name, value)
    return stream.getvalue()


def pdf(texts, *, author=None, layers=False, signature=False):
    writer = PdfWriter()
    for text in texts:
        page = writer.add_blank_page(width=612, height=792)
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({
            NameObject("/F1"): DictionaryObject({NameObject("/Type"): NameObject("/Font"),
                NameObject("/Subtype"): NameObject("/Type1"), NameObject("/BaseFont"): NameObject("/Helvetica")})})})
        stream = DecodedStreamObject()
        stream.set_data(f"BT /F1 12 Tf 30 720 Td ({text}) Tj ET".encode())
        page[NameObject("/Contents")] = writer._add_object(stream)
    if author:
        writer.add_metadata({"/Author": author, "/CreationDate": "D:20250102030405-08'00'"})
    if layers:
        writer._root_object[NameObject("/OCProperties")] = DictionaryObject()
    if signature:
        field = DictionaryObject({NameObject("/FT"): NameObject("/Sig"), NameObject("/T"): TextStringObject("Signature1"),
                                  NameObject("/V"): DictionaryObject({NameObject("/Name"): TextStringObject("Ravi Menon")})})
        writer._root_object[NameObject("/AcroForm")] = DictionaryObject({NameObject("/Fields"): ArrayObject([writer._add_object(field)])})
    output = BytesIO()
    writer.write(output)
    return output.getvalue()


@pytest.mark.parametrize("source", ["basic operational requirements", "basic\toperational requirements", "Basic Rights", "basic needs", "age is related to onset.", "sex is to be discussed", "D:20250102030405-08'00'", "TID: 2046573692", "22       1983-1986", "660005261-5299", "1 8814 2 4972 3", "reviewed document 09:18:40\n\n 25       1000001234, which was supplied."])
def test_prose_dates_references_and_line_numbers_are_not_personal_identifiers(source):
    assert not detect_text(source)


@pytest.mark.parametrize("source", ["Authorization: Basic abcdefgh", "Basic dXNlcjpwYXNz", "Bearer some-token", "SSN: 000-00-1234", "PrimarySSN 000-00-1234", "dependent ssn: 000 | 00' 1234"])
def test_credentials_and_ocr_labelled_identifiers_are_still_removed(source):
    assert detect_text(source)
    assert process_payload(content=source).output != source


@pytest.mark.parametrize("source,value,kind", [
    ("Dr. Leena Kapoor testified.", "Leena Kapoor", "PERSON_NAME"),
    ("Name: Priya Fernandes", "Priya Fernandes", "PERSON_NAME"),
    ("Ms. Inez O’Connor", "Inez O’Connor", "PERSON_NAME"),
    ("MAYA .... APPELLANT", "MAYA", "PERSON_NAME"),
    ("Sanjay Patel, J.", "Sanjay Patel", "PERSON_NAME"),
    ("Smt. Kavya was present.", "Kavya", "PERSON_NAME"),
    ("KAVYA & ORS. ...APPELLANT(S)", "KAVYA", "PERSON_NAME"),
    ("Dr. Mara McPherson", "Mara McPherson", "PERSON_NAME"),
    ("Mail to 234 Oak Ridge Avenue tomorrow.", "234 Oak Ridge Avenue", "ADDRESS"),
])
def test_contextual_entities_preserve_source_offsets(source, value, kind):
    assert any(source[span.start:span.end] == value and span.entity_type == kind for span in detect_text(source))


def test_lowercase_name_label_prose_is_not_a_name():
    assert not detect_text("Name: basic operational requirements")


@pytest.mark.parametrize("source", ["Dr. Leena Kapoor", "Name: Priya Fernandes", "234 Oak Ridge Avenue", "PrimarySSN 000 | 00' 1234"])
def test_independent_residual_scanner_catches_contextual_pii(source, monkeypatch):
    monkeypatch.setattr("app.processing.detect_text", lambda _: pytest.fail("Must remain independent"))
    assert scan_residual_candidate(source).residual_counts["PII"] == 1


def test_metadata_seeds_propagate_across_long_document_and_original_is_unchanged():
    raw = pdf(["Leena Kapoor contributed."] * 284, author="Leena Kapoor", layers=True)
    original = bytes(raw)
    result = review_document("transcript.pdf", raw, ocr=False)
    assert result["summary"]["pages"] == 284
    bodies = [surface for surface in result["surfaces"] if surface["kind"] == "pdf-native"]
    assert len(bodies) == 284
    assert all("Leena Kapoor" not in surface["candidate"] for surface in bodies)
    assert len({surface["candidate"] for surface in bodies}) == 1
    assert result["summary"]["known_values_remaining"] == 0
    assert "PDF_OCR_INCOMPLETE" in result["gaps"]
    assert result["coverage"]["pixels"] == "UNMEASURED"
    assert not result["release_eligible"]
    assert raw == original


def test_signature_metadata_is_inspected_but_validity_and_pixels_are_unmeasured():
    result = review_document("signed.pdf", pdf(["Public judgment."], signature=True), ocr=False)
    field = next(surface for surface in result["surfaces"] if surface["kind"] == "signature-metadata")
    assert "Ravi Menon" in field["text"] and "Ravi Menon" not in field["candidate"]
    assert "SIGNATURE_VALIDITY_AND_APPEARANCE_UNMEASURED" in result["gaps"]


def test_legacy_raster_rejection_distinguishes_layers_pages_and_encryption():
    from app.contracts import PayloadError
    from app.media_preview import _pdf_pages
    for raw, reason in [(pdf(["one"], layers=True), "forms, layers, actions or attachments"),
                        (pdf(["one", "two", "three"]), "two pages maximum")]:
        with pytest.raises(PayloadError, match=reason):
            _pdf_pages(raw)
    writer = PdfWriter()
    writer.add_blank_page(width=100, height=100)
    writer.encrypt("fictional-password")
    stream = BytesIO()
    writer.write(stream)
    with pytest.raises(PayloadError, match="encrypted PDF"):
        _pdf_pages(stream.getvalue())


def test_ocr_form_ids_names_and_addresses_become_review_candidates(monkeypatch):
    transcript = "Mary Palmer 000 | 00' 1234\nSocial security number\nJohn Palmer 000 00 1235\n234 Oak Ridge Avenue"
    monkeypatch.setattr("app.document_extract._ocr_page", lambda *_: (transcript, [{"confidence": 40, "start": 0, "end": 4, "box": [1, 1, 10, 10], "scale": 2}]))
    result = review_document("form.pdf", pdf([""], layers=True))
    surface = next(s for s in result["surfaces"] if s["kind"] == "pdf-ocr")
    assert all(value not in surface["candidate"] for value in ("000 | 00' 1234", "000 00 1235", "Mary Palmer", "John Palmer", "234 Oak Ridge Avenue"))
    assert "OCR_LOW_CONFIDENCE" in result["gaps"]
    assert surface["words"][0]["box"] == [1, 1, 10, 10]


def test_ocr_budget_accounts_for_unprocessed_pages(monkeypatch):
    calls = []
    def ocr(_, index):
        calls.append(index)
        return "Scanned text.", []
    monkeypatch.setattr("app.document_extract._ocr_page", ocr)
    result = extract_pdf(pdf([""] * 12), ocr=True)
    assert len(calls) == 8
    assert sum(item.get("ocr") == "UNMEASURED" for item in result.inventory) == 4
    assert "PDF_OCR_INCOMPLETE" in result.gaps


def test_docx_auxiliary_properties_descriptions_and_embedded_parts_are_accounted_for():
    raw = package({"word/document.xml": '<doc><p><t>Leena Kapoor (LK)</t></p><drawing descr="Contact leena@example.test"/></doc>',
                   "word/comments.xml": '<comments><comment author="Devika Sen"><p><t>Review this.</t></p></comment></comments>',
                   "word/header1.xml": '<hdr><p><t>Dr. Ravi Menon</t></p></hdr>',
                   "docProps/core.xml": '<props><creator>Devika Sen</creator></props>',
                   "docProps/custom.xml": '<props><property name="Owner"><text>Internal owner path</text></property></props>',
                   "customXml/item1.xml": '<properties><owner>Fernandes, Priya</owner><path>file:///private/internal</path></properties>',
                   "word/embeddings/object.bin": b'opaque',
                   "word/_rels/document.xml.rels": '<Relationships><Relationship TargetMode="External" Target="https://example.test/private"/></Relationships>'})
    result = review_document("minutes.docx", raw)
    all_text = "\n".join(s["text"] for s in result["surfaces"])
    assert all(value in all_text for value in ("Devika Sen", "Ravi Menon", "leena@example.test", "Internal owner path"))
    assert all("Internal owner path" not in s["candidate"] for s in result["surfaces"])
    assert all("Fernandes, Priya" not in s["candidate"] and "file:///private/internal" not in s["candidate"] for s in result["surfaces"])
    assert "EXTERNAL_RELATIONSHIPS_NOT_FETCHED" in result["gaps"]
    assert next(item for item in result["inventory"] if item["id"].endswith("object.bin"))["status"] == "UNMEASURED"


def test_pptx_hidden_slide_notes_and_alt_text_are_extracted():
    raw = package({"ppt/slides/slide1.xml": '<slide show="0"><p><t>Hidden slide</t></p><cNvPr descr="leena@example.test"/></slide>',
                   "ppt/notesSlides/notesSlide1.xml": '<notes><p><t>Name: Ravi Menon</t></p></notes>'}, "pptx")
    result = review_document("talk.pptx", raw)
    slide = next(s for s in result["surfaces"] if s["id"] == "ppt/slides/slide1.xml")
    notes = next(s for s in result["surfaces"] if s["kind"] == "pptx-notes")
    assert slide["location"]["visibility"] == "hidden"
    assert "leena@example.test" not in slide["candidate"]
    assert "Ravi Menon" not in notes["candidate"]


def test_xlsx_hidden_empty_sheets_unused_strings_formula_and_inline_text():
    raw = package({"xl/workbook.xml": '<workbook xmlns:r="urn:rel"><sheets><sheet name="Roster" r:id="a"/><sheet name="Archive" r:id="b" state="hidden"/><sheet name="Empty" r:id="c" state="veryHidden"/></sheets></workbook>',
                   "xl/_rels/workbook.xml.rels": '<Relationships><Relationship Id="a" Target="worksheets/sheet1.xml"/><Relationship Id="b" Target="worksheets/sheet2.xml"/><Relationship Id="c" Target="worksheets/sheet3.xml"/></Relationships>',
                   "xl/sharedStrings.xml": '<sst><si><t>Priya Fernandes</t></si><si><t>unused@example.test</t></si></sst>',
                   "xl/worksheets/sheet1.xml": '<worksheet><sheetData><row hidden="1"><c t="s"><v>0</v></c></row></sheetData></worksheet>',
                   "xl/worksheets/sheet2.xml": '<worksheet><sheetData><row><c t="inlineStr"><is><t>private@example.test</t></is></c><c><f>HYPERLINK("https://example.test/name")</f><v>1</v></c></row></sheetData></worksheet>',
                   "xl/worksheets/sheet3.xml": '<worksheet/>'}, "xlsx")
    result = review_document("meetings.xlsx", raw)
    sheets = [s for s in result["surfaces"] if s["kind"] == "xlsx-sheet"]
    assert len(sheets) == 3
    assert [s["location"]["visibility"] for s in sheets] == ["visible", "hidden", "veryHidden"]
    assert sheets[-1]["status"] == "EMPTY"
    assert sheets[0]["location"]["hidden_rows"] == 1
    assert "Priya Fernandes" not in sheets[0]["candidate"]
    assert "HYPERLINK" in sheets[1]["text"]
    assert any("unused@example.test" in s["text"] and "unused@example.test" not in s["candidate"] for s in result["surfaces"])


@pytest.mark.parametrize("xml", ['<!DOCTYPE a [<!ENTITY x "secret">]><a>&x;</a>', '<!DOCTYPE a SYSTEM "file:///etc/passwd"><a/>', '<broken>'])
def test_unsafe_and_malformed_xml_are_rejected(xml):
    with pytest.raises(DocumentError, match="^INVALID_OFFICE_PACKAGE$"):
        extract_office(package({"word/document.xml": xml}), "docx")


def test_invalid_paths_package_expansion_and_format_mismatch_fail_closed():
    with pytest.raises(DocumentError, match="INVALID_PACKAGE_PATHS"):
        extract_office(package({"../escape.xml": "<a/>"}), "docx")
    with pytest.raises(DocumentError, match="PACKAGE_LIMIT_OR_ENCRYPTION"):
        extract_office(package({"huge.bin": b"0" * 32_000_001}), "docx")
    with pytest.raises(DocumentError, match="FORMAT_MISMATCH"):
        extract_office(package({}), "pptx")


def test_manual_values_propagate_and_unmatched_corrections_are_rejected():
    raw = pdf(["xylophone xylophone", "xylophone"])
    result = review_document("review.pdf", raw, ocr=False, reviewed_values=[{"value": "xylophone", "kind": "OTHER_SENSITIVE"}])
    assert all("xylophone" not in s["candidate"] for s in result["surfaces"])
    with pytest.raises(DocumentError, match="REVIEW_VALUE_NOT_FOUND"):
        review_document("review.pdf", raw, ocr=False, reviewed_values=[{"value": "absent", "kind": "OTHER_SENSITIVE"}])


def request(raw=None):
    return {"name": "minutes.docx", "content_base64": base64.b64encode(raw or package({})).decode(), "review_only": True, "ocr": False}


def test_disposable_worker_and_api_require_auth_and_return_no_release(demo_client):
    raw = package({"word/document.xml": '<doc><p><t>Dr. Leena Kapoor</t></p></doc>'})
    response = demo_client.post("/development/documents/review", headers=auth(), json=request(raw))
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["release_eligible"] is False
    assert response.json()["coverage"]["original_format_output"] == "NOT_PRODUCED"
    assert demo_client.post("/development/documents/review", json=request()).status_code == 401
    assert demo_client.post("/development/documents/review", headers=auth("reviewer"), json=request()).status_code == 403
    assert demo_client.post("/development/documents/review", headers=auth(), json={**request(), "review_only": False}).status_code == 422


def test_document_route_is_absent_without_demo_opt_in(client):
    assert client.post("/development/documents/review", headers=auth(), json=request()).status_code == 404


def test_document_route_is_not_registered_in_production(monkeypatch):
    from fastapi.testclient import TestClient
    from app.main import create_app
    monkeypatch.setattr("app.token_auth.load_jwt_verifier", lambda: object())
    monkeypatch.setenv("ANONFLOW_ENV", "production")
    monkeypatch.setenv("ANONFLOW_AUTH_MODE", "jwt")
    monkeypatch.setenv("ANONFLOW_STORAGE_MODE", "memory")
    monkeypatch.setenv("ANONFLOW_DEMO_MODE", "enabled")
    app = create_app()
    assert not any(getattr(route, "path", "") == "/development/documents/review" for route in app.routes)
    with TestClient(app) as http:
        assert http.post("/development/documents/review", json=request()).status_code == 503


def test_worker_does_not_inherit_credentials_and_cleans_temporary_directory(monkeypatch):
    from pathlib import Path
    observed = {}
    monkeypatch.setenv("ANONFLOW_DEV_PRINCIPALS", "private-auth-configuration")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "private-storage-credential")
    class Child:
        returncode = 0
        def __init__(self, args, **kwargs):
            observed.update(kwargs)
        def communicate(self, *_args, **_kwargs):
            return b'{"error":"INVALID_PDF"}', None
    monkeypatch.setattr("app.document_review.subprocess.Popen", Child)
    with pytest.raises(DocumentError, match="INVALID_PDF"):
        run_document_review(request())
    assert "ANONFLOW_DEV_PRINCIPALS" not in observed["env"]
    assert "AWS_SECRET_ACCESS_KEY" not in observed["env"]
    assert observed["start_new_session"] is True
    assert not Path(observed["cwd"]).exists()


def test_worker_timeout_kills_its_process_group_and_frees_review_slot(monkeypatch):
    import subprocess
    from app.document_review import _SLOT
    killed = []
    class Child:
        pid = 12345
        def __init__(self, *_args, **_kwargs):
            self.calls = 0
        def communicate(self, *_args, **_kwargs):
            self.calls += 1
            if self.calls == 1:
                raise subprocess.TimeoutExpired("review", 180)
            return b"", None
    monkeypatch.setattr("app.document_review.subprocess.Popen", Child)
    monkeypatch.setattr("app.document_review.os.killpg", lambda pid, sig: killed.append(pid))
    with pytest.raises(DocumentError, match="REVIEW_TIMEOUT"):
        run_document_review(request())
    assert killed == [12345]
    assert _SLOT.acquire(blocking=False)
    _SLOT.release()


def test_invalid_inputs_only_return_source_free_error_codes(demo_client):
    response = demo_client.post("/development/documents/review", headers=auth(), json={**request(), "content_base64": base64.b64encode(b"private-content-broken").decode()})
    assert response.status_code == 422
    assert response.json()["code"] == "INVALID_OFFICE_PACKAGE"
    assert "private-content" not in response.text
    with pytest.raises(DocumentError, match="INVALID_BASE64"):
        decode_review_payload({**request(), "content_base64": "%%%"})


def test_scoped_body_limit_handles_chunked_documents_without_widening_other_routes():
    async def exercise(path):
        sent, received = [], []
        chunks = iter([{"type": "http.request", "body": b"x" * 2_100_001, "more_body": False}])
        async def receive():
            return next(chunks)
        async def send(message):
            sent.append(message)
        async def app(scope, receive, send):
            received.append(len((await receive())["body"]))
        await BodyLimitMiddleware(app)({"type": "http", "path": path, "headers": []}, receive, send)
        return sent, received
    sent, received = asyncio.run(exercise("/datasets"))
    assert sent[0]["status"] == 413 and not received
    sent, received = asyncio.run(exercise("/development/documents/review"))
    assert not sent and received == [2_100_001]
