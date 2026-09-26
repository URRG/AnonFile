import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const source = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { readBatchFile, readBatchReferenceManifest, inspectSyntheticBatch } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
const files = [
  { id: 'f1', name: 'a.txt', size: 4, contentBase64: Buffer.from('Riya').toString('base64') },
  { id: 'f2', name: 'b.txt', size: 4, contentBase64: Buffer.from('note').toString('base64') },
]
const request = { apiBase: 'http://127.0.0.1:8000', token: 'synthetic-token', files, manualNames: [], aliasOverrides: {} }
const valid = () => ({ posture: 'SYNTHETIC_DEMO_ONLY', release_authorized: false, export_available: false,
  documents: [
    { id: 'f1', name: 'a.txt', kind: 'text', text: 'Riya', candidate_text: 'Gita', size_bytes: 4, preview_fidelity: 'source_text', structure_check: 'not_applicable',
      matches: [{ start: 0, end: 4, source: 'Riya', entity_id: 'E1', kind: 'PERSON_NAME', replacement: 'Gita', applied: true, origin: 'AUTOMATIC' }] },
    { id: 'f2', name: 'b.txt', kind: 'text', text: 'note', candidate_text: 'note', size_bytes: 4, preview_fidelity: 'source_text', structure_check: 'not_applicable', matches: [] },
  ], entities: [{ id: 'E1', kind: 'PERSON_NAME', source: 'Riya', alias: 'Gita', mentions: 1, excluded: false }], relationships: [],
  summary: { files: 2, detected_mentions: 1, transformed_mentions: 1, suppressed_mentions: 0, linked_entities: 1, explicit_relationships: 0 },
  verification: { status: 'REVIEW_REQUIRED', known_rule_residual_matches: 0, source_value_residuals: 0, structure_failures: 0,
    checks: [{ name: 'Application', status: 'PASS', detail: 'One match applied.' }, { name: 'Residual', status: 'REVIEW', detail: 'Review.' },
      { name: 'Benchmark', status: 'NOT_MEASURED', detail: 'No ground truth.' }] }, limitations: ['Synthetic only.'] })

test('batch upload accepts bounded raster media and rejects unsupported types before reading', async () => {
  await assert.rejects(readBatchFile({ name: 'image.gif', size: 50, arrayBuffer: () => { throw new Error('must not read') } }, 'f1'), /Choose/)
  await assert.rejects(readBatchFile({ name: 'a.txt', size: 100_001, arrayBuffer: () => { throw new Error('must not read') } }, 'f1'), /100 KB/)
  await assert.rejects(readBatchFile({ name: 'large.pdf', size: 500_001, arrayBuffer: () => { throw new Error('must not read') } }, 'f1'), /500 KB/)
  const largerPdf = await readBatchFile({ name: 'larger.pdf', size: 100_001,
    arrayBuffer: async () => new Uint8Array(100_001).buffer }, 'f1')
  assert.equal(largerPdf.size, 100_001)
  const accepted = await readBatchFile({ name: 'a.pdf', size: 4, arrayBuffer: async () => Uint8Array.from([37, 80, 68, 70]).buffer }, 'f1')
  assert.equal(accepted.contentBase64, 'JVBERg==')
  const image = await readBatchFile({ name: 'photo.png', size: 4, arrayBuffer: async () => Uint8Array.from([1, 2, 3, 4]).buffer }, 'f2')
  assert.equal(image.contentBase64, 'AQIDBA==')
})

test('batch client sends one synthetic-only request and validates candidate', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(valid()))
  const result = await inspectSyntheticBatch(request)
  assert.equal(result.exportAvailable, false)
  assert.equal(result.documents[0].candidateText, 'Gita')
  const body = JSON.parse(mock.mock.calls[0].arguments[1].body)
  assert.equal(body.synthetic_only, true)
  assert.equal(body.files.length, 2)
  assert.equal(mock.mock.calls[0].arguments[1].headers.Authorization, 'Bearer synthetic-token')
})

test('batch client accepts non-deliverable email surrogates and refuses old markers', async t => {
  const emailFiles = [{ id: 'f1', name: 'a.txt', size: 17, contentBase64: Buffer.from('riya@example.test').toString('base64') }, files[1]]
  const emailRequest = { ...request, files: emailFiles }
  const response = valid()
  response.documents[0].text = 'riya@example.test'
  response.documents[0].candidate_text = 'gita@example.test'
  response.documents[0].size_bytes = 17
  response.documents[0].matches[0] = { start: 0, end: 17, source: 'riya@example.test', entity_id: 'E1',
    kind: 'EMAIL', replacement: 'gita@example.test', applied: true, origin: 'AUTOMATIC' }
  response.entities[0] = { id: 'E1', kind: 'EMAIL', source: 'riya@example.test', alias: 'gita@example.test', mentions: 1, excluded: false }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  assert.equal((await inspectSyntheticBatch(emailRequest)).entities[0].alias, 'gita@example.test')
  t.mock.restoreAll()
  for (const alias of ['[EMAIL_E1]', 'riya@example.test', 'gita@company.com']) {
    const tampered = structuredClone(response)
    tampered.entities[0].alias = alias
    tampered.documents[0].matches[0].replacement = alias
    tampered.documents[0].candidate_text = alias
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch(emailRequest), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('batch client sends bounded reviewer corrections and rejects invalid values before transport', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(valid()))
  await inspectSyntheticBatch({ ...request, manualFindings: [{ value: 'DEMO-4821', kind: 'OTHER_SENSITIVE' }] })
  assert.deepEqual(JSON.parse(mock.mock.calls[0].arguments[1].body).manual_findings,
    [{ value: 'DEMO-4821', kind: 'OTHER_SENSITIVE' }])
  await assert.rejects(inspectSyntheticBatch({ ...request, manualFindings: [{ value: 'a\nb', kind: 'OTHER_SENSITIVE' }] }), /Invalid manually reviewed/)
  await assert.rejects(inspectSyntheticBatch({ ...request, manualFindings: [{ value: 'DEMO-4821', kind: 'EMAIL' }] }), /Invalid manually reviewed/)
  assert.equal(mock.mock.calls.length, 1)
})

test('batch client binds raster image previews to staged media and PNG dimensions', async t => {
  const png = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAI0lEQVR4nGP8//8/AymAiSTVDKMaiANMRKqDg1ENxACSQwkAVW0DHeN02ZEAAAAASUVORK5CYII='
  const response = valid()
  response.documents[1].name = 'b.png'
  response.documents[1].kind = 'image'
  response.documents[1].preview_fidelity = 'raster_ocr_review'
  response.documents[1].media_preview = { pages: [{ number: 1, width: 16, height: 16,
    source_png_base64: png, candidate_png_base64: png, ocr_lines: 1 }], fallback_lines: 0,
    self_ocr_residual_sources: 0, pdf_raster_evidence: null }
  const mediaRequest = { ...request, files: [files[0], { ...files[1], name: 'b.png' }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const result = await inspectSyntheticBatch(mediaRequest)
  assert.equal(result.documents[1].mediaPreview.pages[0].width, 16)
  t.mock.restoreAll()
  for (const change of [
    value => { value.documents[1].media_preview.pages[0].width = 17 },
    value => { value.documents[1].media_preview.pages[0].candidate_png_base64 = 'not-a-png' },
    value => { value.documents[1].media_preview.pdf_raster_evidence = { sha256: '0'.repeat(64), bytes: 500, pages: 1, source_objects_copied: false } },
    value => { value.documents[1].kind = 'pdf' },
  ]) {
    const tampered = structuredClone(response); change(tampered)
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch(mediaRequest), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('Python code-point spans render correctly after an astral Unicode character', async t => {
  const response = valid()
  response.documents[0].text = '😀Riya'
  response.documents[0].candidate_text = '😀Gita'
  response.documents[0].matches[0].start = 1
  response.documents[0].matches[0].end = 5
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const result = await inspectSyntheticBatch(request)
  assert.equal(result.documents[0].matches[0].start, 2)
  assert.equal(result.documents[0].matches[0].end, 6)
  assert.equal(result.documents[0].candidateText, '😀Gita')
})

test('batch client rejects fabricated approval, mismatched content and counts', async t => {
  for (const change of [
    value => { value.release_authorized = true },
    value => { value.export_available = true },
    value => { value.documents[0].candidate_text = 'Riya' },
    value => { value.documents[0].name = 'different.txt' },
    value => { value.documents[0].size_bytes = 5 },
    value => { value.entities[0].mentions = 2 },
    value => { value.summary.detected_mentions = 0 },
    value => { value.summary.suppressed_mentions = 1 },
    value => { value.documents[0].matches[0].applied = false },
    value => { value.documents[0].matches[0].origin = 'UNVERIFIED' },
    value => { value.verification.status = 'APPROVED' },
    value => { value.verification.source_value_residuals = -1 },
  ]) {
    const item = valid(); change(item)
    t.mock.method(globalThis, 'fetch', async () => Response.json(item))
    await assert.rejects(inspectSyntheticBatch(request), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('explicit reviewer exclusion retains source and is reflected in counts', async t => {
  const response = valid()
  response.entities[0].excluded = true
  response.documents[0].matches[0].applied = false
  response.documents[0].candidate_text = 'Riya'
  response.summary.transformed_mentions = 0
  response.summary.suppressed_mentions = 1
  const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const result = await inspectSyntheticBatch({ ...request, reviewExclusions: { E1: 'FALSE_POSITIVE_CONFIRMED' } })
  assert.equal(result.documents[0].candidateText, 'Riya')
  assert.equal(result.documents[0].matches[0].applied, false)
  assert.equal(result.summary.suppressedMentions, 1)
  assert.deepEqual(JSON.parse(mock.mock.calls[0].arguments[1].body).review_exclusions, { E1: 'FALSE_POSITIVE_CONFIRMED' })
  await assert.rejects(inspectSyntheticBatch(request), /invalid review result/)
})

test('batch client rejects invalid intake and never sends data', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not send') })
  await assert.rejects(inspectSyntheticBatch({ ...request, token: '' }), /required/)
  await assert.rejects(inspectSyntheticBatch({ ...request, files: files.slice(0, 1) }), /required/)
  assert.equal(mock.mock.calls.length, 0)
})

test('reference-label JSON must cover every staged file and contain only bounded span metadata', async () => {
  const makeFile = value => ({ name: 'labels.json', size: 400, text: async () => JSON.stringify(value) })
  const good = { schema_version: 'batch-reference-v1', documents: [
    { name: 'a.txt', annotations: [{ start: 0, end: 4, entity_type: 'PERSON_NAME' }] },
    { name: 'b.txt', annotations: [] },
  ] }
  const parsed = await readBatchReferenceManifest(makeFile(good), files)
  assert.equal(parsed.basis, 'REVIEWER_ATTESTED_EXHAUSTIVE')
  assert.equal(parsed.documents[0].annotations[0].end, 4)
  await assert.rejects(readBatchReferenceManifest(makeFile({ ...good, text: 'Riya' }), files), /every staged document/)
  await assert.rejects(readBatchReferenceManifest(makeFile({ ...good, documents: [good.documents[0], good.documents[0]] }), files), /every staged document/)
  await assert.rejects(readBatchReferenceManifest(makeFile({ ...good, documents: [
    { name: 'a.txt', annotations: [{ start: 0, end: 4, entity_type: 'UNKNOWN' }] }, good.documents[1],
  ] }), files), /invalid span/)
})

test('batch client binds annotation-score counts to submitted labels and detector matches', async t => {
  const referenceManifest = { basis: 'REVIEWER_ATTESTED_EXHAUSTIVE', documents: [
    { name: 'a.txt', annotations: [{ start: 0, end: 4, entity_type: 'PERSON_NAME' }] },
    { name: 'b.txt', annotations: [{ start: 0, end: 4, entity_type: 'OTHER_SENSITIVE' }] },
  ] }
  const response = valid()
  response.verification.annotation_score = { basis: 'REVIEWER_ATTESTED_EXHAUSTIVE', status: 'OBSERVATIONAL_ONLY',
    labelled_documents: 2, gold_annotations: 2,
    exact: { true_positives: 1, false_positives: 0, false_negatives: 1 },
    automatic_exact: { true_positives: 1, false_positives: 0, false_negatives: 1 },
    per_type: { PERSON_NAME: { true_positives: 1, false_positives: 0, false_negatives: 0 },
      OTHER_SENSITIVE: { true_positives: 0, false_positives: 0, false_negatives: 1 } },
    per_document: [
      { id: 'f1', exact: { true_positives: 1, false_positives: 0, false_negatives: 0 }, missed: [] },
      { id: 'f2', exact: { true_positives: 0, false_positives: 0, false_negatives: 1 },
        missed: [{ start: 0, end: 4, entity_type: 'OTHER_SENSITIVE' }] },
    ] }
  const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const result = await inspectSyntheticBatch({ ...request, referenceManifest })
  assert.equal(result.verification.annotationScore.exact.falseNegatives, 1)
  assert.equal(result.verification.annotationScore.automaticExact.falseNegatives, 1)
  assert.deepEqual(result.verification.annotationScore.perDocument[1].missed,
    [{ start: 0, end: 4, entity_type: 'OTHER_SENSITIVE' }])
  const sent = JSON.parse(mock.mock.calls[0].arguments[1].body)
  assert.deepEqual(sent.reference_annotations.documents.map(item => item.id), ['f1', 'f2'])
  t.mock.restoreAll()
  for (const change of [
    value => { value.verification.annotation_score.exact.false_negatives = 0 },
    value => { value.verification.annotation_score.status = 'QUALIFIED' },
    value => { value.verification.annotation_score.per_type.OTHER_SENSITIVE.false_negatives = 0 },
    value => { value.verification.annotation_score.per_document[1].missed = [] },
    value => { value.verification.annotation_score.per_document[1].missed[0].end = 3 },
    value => { value.verification.annotation_score.per_document[0].exact.true_positives = 0 },
    value => { value.verification.annotation_score.automatic_exact.false_negatives = 0 },
  ]) {
    const tampered = structuredClone(response); change(tampered)
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch({ ...request, referenceManifest }), /invalid review result/)
    t.mock.restoreAll()
  }
})
