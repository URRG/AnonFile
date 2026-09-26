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
      matches: [{ start: 0, end: 4, source: 'Riya', entity_id: 'E1', kind: 'PERSON_NAME', replacement: 'Gita', applied: true }] },
    { id: 'f2', name: 'b.txt', kind: 'text', text: 'note', candidate_text: 'note', size_bytes: 4, preview_fidelity: 'source_text', structure_check: 'not_applicable', matches: [] },
  ], entities: [{ id: 'E1', kind: 'PERSON_NAME', source: 'Riya', alias: 'Gita', mentions: 1, excluded: false }], relationships: [],
  summary: { files: 2, detected_mentions: 1, transformed_mentions: 1, suppressed_mentions: 0, linked_entities: 1, explicit_relationships: 0 },
  verification: { status: 'REVIEW_REQUIRED', known_rule_residual_matches: 0, structure_failures: 0,
    checks: [{ name: 'Application', status: 'PASS', detail: 'One match applied.' }, { name: 'Residual', status: 'REVIEW', detail: 'Review.' },
      { name: 'Benchmark', status: 'NOT_MEASURED', detail: 'No ground truth.' }] }, limitations: ['Synthetic only.'] })

test('batch upload rejects image and oversized files before reading', async () => {
  await assert.rejects(readBatchFile({ name: 'image.png', size: 50, arrayBuffer: () => { throw new Error('must not read') } }, 'f1'), /OCR/)
  await assert.rejects(readBatchFile({ name: 'a.txt', size: 100_001, arrayBuffer: () => { throw new Error('must not read') } }, 'f1'), /100 KB/)
  const accepted = await readBatchFile({ name: 'a.pdf', size: 4, arrayBuffer: async () => Uint8Array.from([37, 80, 68, 70]).buffer }, 'f1')
  assert.equal(accepted.contentBase64, 'JVBERg==')
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
    value => { value.verification.status = 'APPROVED' },
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
  ]) {
    const tampered = structuredClone(response); change(tampered)
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch({ ...request, referenceManifest }), /invalid review result/)
    t.mock.restoreAll()
  }
})
