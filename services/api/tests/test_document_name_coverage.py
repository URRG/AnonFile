"""Name coverage regressions with explicit field and weak-proposal evidence."""
from xml.sax.saxutils import escape

import pytest

from app.document_extract import DocumentError
from app.document_review import review_document
from app.processing import detect_text, process_payload
from test_document_review import package, pdf


@pytest.mark.parametrize('value', [
    'Анастасия Иванова', 'анастасия иванова', 'Анна-Мария Иванова',
    'अनन्या शर्मा', 'अनन्या\u200d शर्मा', '李小明', '山田 太郎', '김 민수', 'ليلى منصور',
    'E\u0301lodie Dubois', 'Łukasz Żółć', 'І. Петренко', 'Марія О’Коннор',
])
def test_explicit_unicode_name_preserves_original_offsets_and_complete_value(value):
    source = 'Full name: ' + value + '; Email: contact@example.test'
    spans = [s for s in detect_text(source) if s.entity_type == 'PERSON_NAME']
    assert len(spans) == 1
    assert source[spans[0].start:spans[0].end] == value
    candidate = process_payload(content=source).output
    assert value not in candidate
    assert 'Full name: ' in candidate and '; Email:' in candidate


@pytest.mark.parametrize('source', [
    'Name: Анастасия Иванова\tEmail: contact@example.test',
    'Name: अनन्या शर्मा  Phone: 415-555-0136',
    'Name: 李小明\nEmail: contact@example.test',
    'Name: Élodie Dubois  Phone: 415-555-0136',
    'Name: E\u0301lodie Dubois  Email: contact@example.test',
    'Name: Elena Navarro  Email: contact@example.test',
])
def test_unicode_field_stops_before_the_next_label(source):
    candidate = process_payload(content=source).output
    assert 'Email:' in candidate or 'Phone:' in candidate
    assert any(s.entity_type == 'PERSON_NAME' for s in detect_text(source))
    assert 'Dubois' not in candidate and 'Navarro' not in candidate


@pytest.mark.parametrize('source', [
    'Анастасия Иванова', 'Title: Годовой отчёт', 'Name: basic operational requirements',
    'Name: 李123', 'Name: 李🙂明', 'Name: 李_明', 'Name: 李/', 'Name: \u093eअनन्या',
    'Name: Анна--Мария', 'Name: 李', 'Name: ' + '李' * 151,
    'Name: ' + '李 ' * 7, 'Name: [李小明]',
])
def test_unicode_name_field_requires_bounded_letter_evidence(source):
    assert not any(s.entity_type == 'PERSON_NAME' for s in detect_text(source))


@pytest.mark.parametrize('value', ['Анастасия Иванова', 'अनन्या शर्मा', '李小明', 'E\u0301lodie Dubois'])
def test_unicode_field_repeats_into_a_header_with_consistent_markers(value):
    raw = package({'word/document.xml': '<doc><p><t>Name: '+escape(value)+'</t></p></doc>',
                   'word/header1.xml': '<header><p><t>'+escape(value.lower())+'</t></p></header>'})
    result = review_document('names.docx', raw)
    surfaces = [s for s in result['surfaces'] if s['kind'] == 'docx-part']
    assert len(surfaces) == 2
    assert all(value.casefold() not in s['candidate'].casefold() for s in surfaces)
    assert len({s['matches'][0]['replacement'] for s in surfaces}) == 1
    assert all(s['matches'][0]['basis'] in {'contextual-rule', 'document-repeat'} for s in surfaces)
    assert result['summary']['known_values_remaining'] == 0
    assert result['coverage']['names_addresses'] == 'UNQUALIFIED'
    assert result['release_eligible'] is False


def test_unicode_author_metadata_seeds_an_unlabelled_body_name():
    raw = package({'word/document.xml': '<doc><p><t>Анастасия Иванова</t></p></doc>',
                   'docProps/core.xml': '<props><creator>Анастасия Иванова</creator></props>'})
    result = review_document('author.docx', raw)
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert 'Анастасия Иванова' not in body['candidate']
    assert body['matches'][0]['basis'] == 'document-repeat'


@pytest.mark.parametrize('extension,parts,kind', [
    ('pptx', {'ppt/slides/slide1.xml': '<slide><p><t>Name: 李小明</t></p></slide>',
              'ppt/notesSlides/notesSlide1.xml': '<notes><p><t>李小明</t></p></notes>'}, 'pptx-notes'),
    ('xlsx', {'xl/workbook.xml': '<workbook xmlns:r="urn:rel"><sheets><sheet name="Roster" r:id="a"/></sheets></workbook>',
              'xl/_rels/workbook.xml.rels': '<Relationships><Relationship Id="a" Target="worksheets/sheet1.xml"/></Relationships>',
              'xl/worksheets/sheet1.xml': '<worksheet><sheetData><row><c t="inlineStr"><is><t>Name:</t></is></c>'
                  '<c t="inlineStr"><is><t>李小明</t></is></c><c t="inlineStr"><is><t>company</t></is></c></row>'
                  '<row><c t="inlineStr"><is><t>李小明</t></is></c></row></sheetData></worksheet>'}, 'xlsx-sheet'),
])
def test_unicode_names_in_other_office_formats_and_adjacent_cells(extension, parts, kind):
    result = review_document('name.'+extension, package(parts, extension))
    body = next(s for s in result['surfaces'] if s['kind'] == kind)
    assert '李小明' in body['text'] and '李小明' not in body['candidate']
    if extension == 'xlsx':
        assert 'company' in body['candidate']
        assert len(body['matches']) == 2


def test_capitalization_proposal_repeats_without_becoming_strong_evidence():
    raw = pdf(['Elena Navarro.', 'elena navarro approved.', 'elenanavarro; elena navarros'])
    result = review_document('repeat.pdf', raw, ocr=False)
    bodies = [s for s in result['surfaces'] if s['kind'] == 'pdf-native']
    assert bodies[0]['matches'][0]['basis'] == 'capitalization-review'
    assert bodies[1]['matches'][0]['basis'] == 'capitalization-repeat-review'
    assert bodies[0]['matches'][0]['replacement'] == bodies[1]['matches'][0]['replacement']
    assert 'elena navarro' not in bodies[1]['candidate']
    assert bodies[2]['matches'] == []
    assert bodies[2]['candidate'] == bodies[2]['text']
    assert 'CAPITALIZATION_REPEAT_REVIEW_REQUIRED' in result['gaps']
    assert result['coverage']['names_addresses'] == 'UNQUALIFIED'
    assert not result['release_eligible']


@pytest.mark.parametrize('kind', ['PERSON_NAME', 'OTHER_SENSITIVE'])
def test_explicit_confirmation_takes_precedence_over_weak_repetition(kind):
    result = review_document('repeat.pdf', pdf(['Elena Navarro.', 'elena navarro approved.']),
                             ocr=False, reviewed_values=[{'value': 'Elena Navarro', 'kind': kind}])
    bodies = [s for s in result['surfaces'] if s['kind'] == 'pdf-native']
    assert all(s['matches'][0]['basis'] == 'document-repeat' for s in bodies)
    assert 'CAPITALIZATION_REPEAT_REVIEW_REQUIRED' not in result['gaps']


def test_title_words_and_court_captions_do_not_seed_lowercase_repetitions():
    result = review_document('negative.pdf', pdf(['Annual Report\n2 STATE OF NEVADA DISTRICT COURT',
                                                 'annual report\nnevada district']), ocr=False)
    assert all(not s['matches'] for s in result['surfaces'] if s['kind'] == 'pdf-native')


def test_repeated_name_does_not_leave_a_combining_mark_suffix():
    raw = package({'word/document.xml': '<doc><p><t>Name: Elena Navarro</t></p><p><t>Elena Navarro\u0301</t></p></doc>'})
    result = review_document('boundary.docx', raw)
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert 'Elena Navarro\u0301' in body['candidate']
    assert len(body['matches']) == 1


def test_weak_name_repetition_respects_the_entity_budget():
    def suffix(i):
        return ''.join(chr(97 + (i // 26**power) % 26) for power in range(3))
    text = '\n'.join('Elena N'+suffix(i) for i in range(1001))
    raw = package({'word/document.xml': '<doc><p><t>'+text+'</t></p></doc>'})
    with pytest.raises(DocumentError, match='ENTITY_LIMIT'):
        review_document('many-names.docx', raw)


@pytest.mark.parametrize('names', [
    ('Straße Müller', 'Strasse Müller'), ('Strasse Müller', 'Straße Müller'),
])
@pytest.mark.parametrize('evidence', ['field', 'weak', 'metadata', 'manual'])
def test_casefold_collisions_preserve_every_observed_spelling(names, evidence):
    paragraphs = [('Name: ' if evidence == 'field' else '') + name for name in names]
    paragraphs += ['straße müller', 'strasse müller']
    parts = {'word/document.xml': '<doc>' + ''.join('<p><t>'+escape(p)+'</t></p>' for p in paragraphs) + '</doc>'}
    if evidence == 'metadata':
        parts['docProps/core.xml'] = '<props><creator>'+names[0]+'</creator></props>'
    reviewed = [{'value': name, 'kind': 'PERSON_NAME'} for name in names] if evidence == 'manual' else []
    result = review_document('variants.docx', package(parts), reviewed_values=reviewed)
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert 'straße müller' not in body['candidate']
    assert 'strasse müller' not in body['candidate']
    assert len(body['matches']) == 4
    assert len({match['replacement'] for match in body['matches']}) == 1
    assert result['summary']['known_values_remaining'] == 0
    assert result['release_eligible'] is False
    if evidence == 'weak':
        assert all(match['basis'].startswith('capitalization') for match in body['matches'])


@pytest.mark.parametrize('name', ['Анастасия Иванова', '李小明', 'Elena Navarro', 'Élodie Dubois',
                                  'Elena  Navarro', 'Élodie  Dubois'])
@pytest.mark.parametrize('label', ['Customer ID', 'Social security', 'Case Number', 'Custom account reference'])
def test_inline_multiword_labels_survive_context_and_weak_proposal_merging(name, label):
    source = f'Name: {name}  {label}: AB321'
    spans = [s for s in detect_text(source) if s.entity_type == 'PERSON_NAME']
    assert len(spans) == 1
    assert source[spans[0].start:spans[0].end] == name
    result = review_document('fields.docx', package({'word/document.xml': '<doc><p><t>'+source+'</t></p></doc>'}))
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert name not in body['candidate']
    assert f'  {label}: AB321' in body['candidate']


@pytest.mark.parametrize('prefix', ['\u0301', 'A\u0301', 'कि'])
def test_weak_proposals_cannot_start_after_a_combining_mark(prefix):
    source = 'Elena Navarro\n' + prefix + 'Elena Navarro'
    result = review_document('boundary.docx', package({'word/document.xml': '<doc><p><t>'+source+'</t></p></doc>'}))
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert prefix + 'Elena Navarro' in body['candidate']
    assert len(body['matches']) == 1


def test_observed_case_variants_cannot_bypass_the_seed_work_budget():
    # 1024 distinct spellings share one casefold identity; each still adds work.
    values = [''.join(char.upper() if mask & (1 << bit) else char for bit, char in enumerate('abcdefghij')) + ' Müller'
              for mask in range(1024)]
    source = '\n'.join('Name: ' + value for value in values)
    with pytest.raises(DocumentError, match='ENTITY_LIMIT'):
        review_document('variants.docx', package({'word/document.xml': '<doc><p><t>'+source+'</t></p></doc>'}))


def test_transcript_speaker_labels_still_seed_surname_repetitions():
    source = '19   MS. WALBURN: Roberta Walburn.\n20   MR. PERRY WILSON: Present.\nwalburn\nperry wilson'
    result = review_document('transcript.docx', package({'word/document.xml': '<doc><p><t>'+source+'</t></p></doc>'}))
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert 'walburn' not in body['candidate'].lower()
    assert 'perry wilson' not in body['candidate'].lower()
    assert any(body['text'][m['start']:m['end']] == 'WALBURN' and m['basis'] == 'contextual-rule' for m in body['matches'])


def test_long_single_paragraph_preserves_all_repeated_proposals():
    source = 'Elena Navarro. ' * 10_000
    result = review_document('long-paragraph.docx', package({'word/document.xml': '<doc><p><t>'+source+'</t></p></doc>'}))
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert len(body['matches']) == 10_000
    assert 'Elena Navarro' not in body['candidate']


@pytest.mark.parametrize('label', ['Customer ID', 'Case Number', 'Custom account reference'])
def test_wrapped_name_keeps_inline_labels_on_its_continuation_line(label):
    source = 'Name: Elena\nNavarro  ' + label + ': AB321\nMS. WALBURN: Present.\nwalburn'
    result = review_document('wrapped.docx', package({'word/document.xml': '<doc><p><t>'+source+'</t></p></doc>'}))
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert 'Elena' not in body['candidate'] and 'Navarro' not in body['candidate']
    assert label + ': AB321' in body['candidate']
    assert 'walburn' not in body['candidate'].lower()


@pytest.mark.parametrize('next_line', ['MS. WALBURN: Present.', '19   MS. WALBURN: Present.'])
def test_an_incomplete_name_field_cannot_absorb_a_transcript_speaker(next_line):
    source = 'Name: Elena\n' + next_line + '\nwalburn'
    result = review_document('speaker.docx', package({'word/document.xml': '<doc><p><t>'+source+'</t></p></doc>'}))
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert 'walburn' not in body['candidate'].lower()
    assert 'Name: Elena\n' in body['candidate']
    assert 'MS.' in body['candidate']


@pytest.mark.parametrize('label', ['Name', 'Full name'])
def test_adjacent_name_fields_keep_their_own_inline_boundaries(label):
    source = f'Name: Elena\n{label}: Alice Brown  Email: contact@example.test  Case Number: AB321'
    result = review_document('adjacent.docx', package({'word/document.xml': '<doc><p><t>'+source+'</t></p></doc>'}))
    body = next(s for s in result['surfaces'] if s['kind'] == 'docx-part')
    assert 'Name: Elena\n' in body['candidate']
    assert label + ': ' in body['candidate']
    assert 'Alice Brown' not in body['candidate']
    assert 'Email:' in body['candidate'] and 'Case Number: AB321' in body['candidate']
