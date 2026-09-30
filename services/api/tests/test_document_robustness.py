"""Labelled regressions from the independent public/synthetic challenge corpus."""
from io import BytesIO

import pytest
from pypdf import PdfReader, PdfWriter
from pypdf.generic import DecodedStreamObject, DictionaryObject, NameObject, NumberObject

from app.document_extract import extract_pdf
from app.document_review import review_document
from app.processing import detect_text, process_payload
from test_document_review import package, pdf


@pytest.mark.parametrize('value,kind', [
    ('415  555  0136', 'PHONE'), ('415\t555\t0136', 'PHONE'),
    ('+44 20  7946 0958', 'PHONE'), ('4111  1111  1111  1111', 'CARD'),
    ('4111\t1111\t1111\t1111', 'CARD'), ('４１５\u00a0\u00a0５５５\u00a0\u00a0０１３６', 'PHONE'),
])
def test_numeric_spacing_preserves_complete_source_offsets(value, kind):
    for source in (value, 'Contact: '+value, '21       prior testimony\n22       '+value):
        spans = detect_text(source)
        assert any(source[s.start:s.end] == value and s.entity_type == kind for s in spans)
        assert value not in process_payload(content=source).output


@pytest.mark.parametrize('value', ['1  415  555  0136', '7  912  345  6789', '20  2123  456789'])
def test_country_code_is_not_stripped_as_a_standalone_transcript_number(value):
    assert any(s.start == 0 and s.end == len(value) for s in detect_text(value))
    assert value not in process_payload(content=value).output


@pytest.mark.parametrize('source', [
    '22       1983-1986', '1 8814 2 4972 3', 'TID: 2046573692',
    'reviewed document 09:18:40\n\n 25       1000001234, which was supplied.',
    '2 STATE OF NEVADA DISTRICT COURT', '3 UNITED STATES DISTRICT COURT',
    '12 COMMONWEALTH OF PENNSYLVANIA SUPREME COURT',
])
def test_transcript_numbers_and_court_captions_are_not_identifiers(source):
    assert not detect_text(source)


@pytest.mark.parametrize('value', ['234 Oak Ridge Court', '12 District Court', '123 State Street', '123 Court Lane'])
def test_real_street_shapes_survive_court_caption_exclusion(value):
    assert any(s.entity_type == 'ADDRESS' and value[s.start:s.end] == value for s in detect_text(value))


@pytest.mark.parametrize('caption', [
    '2 STATE OF NEVADA DISTRICT COURT', '3 UNITED STATES DISTRICT COURT',
    '12 COMMONWEALTH OF PENNSYLVANIA SUPREME COURT',
])
def test_court_caption_is_not_reintroduced_as_a_capitalization_proposal(caption):
    result = review_document('caption.pdf', pdf([caption + '\nElena Navarro']), ocr=False)
    body = next(s for s in result['surfaces'] if s['kind'] == 'pdf-native')
    assert caption in body['candidate']
    assert [body['text'][m['start']:m['end']] for m in body['matches']] == ['Elena Navarro']


@pytest.mark.parametrize('source', [
    'nationality is Canadian', 'occupation is nurse', 'race is Asian', 'ethnicity is Punjabi',
    'gender is non-binary', 'gender is nonbinary', 'gender is non binary',
    'postcode is SW1A 1AA', 'marital status is divorced', 'age is 42', 'age is "42"',
    'household size is 3', 'gender: self-described', 'occupation = nurse',
])
def test_quasi_identifier_values_follow_field_specific_context(source):
    assert any(s.entity_type == 'QUASI_IDENTIFIER' and s.start == 0 and s.end == len(source) for s in detect_text(source))
    assert process_payload(content=source).output == '[GENERALIZED_QUASI_IDENTIFIER]'


@pytest.mark.parametrize('source', ['age is related to onset.', 'sex is to be discussed', 'sex is a factor', 'birth year is relevant'])
def test_ordinary_demographic_discussion_is_not_a_value(source):
    assert not detect_text(source)


@pytest.mark.parametrize('label,value', [('SSN:', '000-00-4321'), ('Passport:', 'FICT12345'), ('Phone:', '415  555  0136')])
def test_detected_identifiers_propagate_without_a_repeated_label(label, value):
    result = review_document('repeat.pdf', pdf([f'{label} {value}', f'Carried forward: {value}']), ocr=False)
    bodies = [s for s in result['surfaces'] if s['kind'] == 'pdf-native']
    assert len(bodies) == 2
    assert all(value not in s['candidate'] for s in bodies)
    assert bodies[0]['matches'][0]['replacement'] == bodies[1]['matches'][0]['replacement']
    assert result['summary']['known_values_remaining'] == 0
    assert result['release_eligible'] is False


def test_form_context_identifier_seeds_repetition():
    raw = package({'word/document.xml': '<doc><p><t>Social security number</t></p><p><t>000 | 00’ 4321</t></p></doc>',
                   'word/header1.xml': '<header><p><t>000 | 00’ 4321</t></p></header>'})
    result = review_document('form.docx', raw)
    assert all('000 | 00’ 4321' not in s['candidate'] for s in result['surfaces'])


@pytest.mark.parametrize('separator,expected', [('<tab/>', '\t'), ('<br/>', '\n'), ('<cr/>', '\n')])
def test_word_controls_preserve_name_boundaries_and_detection(separator, expected):
    raw = package({'word/document.xml': f'<doc><p><r><t>Name: Elena</t>{separator}<t>Navarro</t></r></p><p><t>Email: elena@example.test</t></p></doc>'})
    result = review_document('controls.docx', raw)
    body = next(s for s in result['surfaces'] if s['id'] == 'word/document.xml')
    assert body['text'] == f'Name: Elena{expected}Navarro\nEmail: elena@example.test'
    assert 'Elena' not in body['candidate'] and 'Navarro' not in body['candidate']
    assert 'Email:' in body['candidate']
    assert any(body['text'][m['start']:m['end']] == f'Elena{expected}Navarro' for m in body['matches'])


def test_wrapped_name_does_not_consume_the_next_label():
    source = 'Name: Elena Navarro\nPhone: 415-555-0136'
    assert [source[s.start:s.end] for s in detect_text(source) if s.entity_type == 'PERSON_NAME'] == ['Elena Navarro']
    assert not any(s.entity_type == 'PERSON_NAME' for s in detect_text('Name: Elena\nEmail: contact@example.test'))


def test_sparse_mixed_pdf_uses_ocr_budget_and_records_omissions(monkeypatch):
    calls = []
    def ocr(_, index):
        calls.append(index)
        return 'SSN: 000-00-4321', []
    monkeypatch.setattr('app.document_extract._ocr_page', ocr)
    result = review_document('mixed.pdf', pdf(['Quarterly report'] * 8 + ['']))
    assert len(calls) == 8 and calls[0] == 8  # No native text takes precedence.
    assert 'PDF_OCR_INCOMPLETE' in result['gaps']
    assert all('000-00-4321' not in s['candidate'] for s in result['surfaces'])
    assert sum(item.get('ocr') == 'UNMEASURED' for item in result['inventory']) == 1


def test_image_resources_trigger_ocr_even_with_plentiful_native_text(monkeypatch):
    writer = PdfWriter()
    writer.append(PdfReader(BytesIO(pdf(['ordinary prose ' * 30] * 9))))
    image = DecodedStreamObject()
    image.set_data(b'\x00')
    image.update({NameObject('/Type'): NameObject('/XObject'), NameObject('/Subtype'): NameObject('/Image'),
                  NameObject('/Width'): NumberObject(1), NameObject('/Height'): NumberObject(1),
                  NameObject('/ColorSpace'): NameObject('/DeviceGray'), NameObject('/BitsPerComponent'): NumberObject(8)})
    writer.pages[-1]['/Resources'][NameObject('/XObject')] = DictionaryObject({NameObject('/Scan'): writer._add_object(image)})
    out = BytesIO(); writer.write(out)
    calls = []
    monkeypatch.setattr('app.document_extract._ocr_page', lambda _, index: (calls.append(index) or 'scan text', []))
    result = extract_pdf(out.getvalue(), ocr=True)
    assert calls == [8]
    assert 'PDF_OCR_INCOMPLETE' in result.gaps


def test_long_native_pdf_records_unmeasured_ocr_when_no_page_was_selected(monkeypatch):
    monkeypatch.setattr('app.document_extract._ocr_page', lambda *_: pytest.fail('No selected page'))
    result = extract_pdf(pdf(['ordinary prose ' * 30] * 9), ocr=True)
    assert 'PDF_OCR_INCOMPLETE' in result.gaps
    assert all(item.get('ocr') == 'UNMEASURED' for item in result.inventory if item['kind'] == 'pdf-page')
