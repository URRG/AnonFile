import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('../src/document-review-api.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { inspectDocument, parseDocumentReview } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
const safe = () => ({ schema: 'document-review-v1', posture: 'REVIEW_REQUIRED', release_eligible: false,
  name: 'test.docx', sha256: 'a'.repeat(64), format: 'docx', inventory: [], surfaces: [], gaps: ['UNMEASURED'], limitations: ['Review only'],
  coverage: { text: 'PARSED_WITH_GAPS', names_addresses: 'UNQUALIFIED', pixels: 'UNMEASURED', original_format_output: 'NOT_PRODUCED' },
  summary: { surfaces: 0, nonempty_surfaces: 0, pages: 0, findings: {}, matches: 0, residual_units: 0, known_values_remaining: 0 } })
const file = () => new File(['fictional bytes'], 'test.docx')

test('document request is authenticated, ephemeral, review-only and has no synthetic attestation', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.headers.Authorization, 'Bearer test-token')
    assert.equal(options.cache, 'no-store'); assert.equal(options.credentials, 'omit'); assert.equal(options.redirect, 'error')
    const body = JSON.parse(options.body)
    assert.equal(body.review_only, true); assert.equal(body.synthetic_only, undefined)
    assert.equal(body.ocr, true)
    assert.deepEqual(body.reviewed_values, [{ value: 'Leena Kapoor', kind: 'OTHER_SENSITIVE' }])
    assert.equal(Buffer.from(body.content_base64, 'base64').toString(), 'fictional bytes')
    return Response.json(safe())
  })
  const result = await inspectDocument('http://localhost:8000/', 'test-token', file(), ['Leena Kapoor'], new AbortController().signal)
  assert.equal(result.release_eligible, false); assert.equal(mock.mock.calls.length, 1)
})

test('unsupported, oversized and empty files do not reach the network', async t => {
  const mock = t.mock.method(globalThis, 'fetch', () => assert.fail('must not fetch'))
  for (const input of [new File(['x'], 'script.exe'), new File([], 'empty.pdf'), new File([new Uint8Array(8_000_001)], 'large.pdf')]) {
    await assert.rejects(inspectDocument('http://localhost', 'token', input, [], new AbortController().signal))
  }
  assert.equal(mock.mock.calls.length, 0)
})

test('cancelled reads never submit a document', async t => {
  t.mock.method(globalThis, 'fetch', () => assert.fail('must not fetch'))
  const controller = new AbortController(); controller.abort()
  await assert.rejects(inspectDocument('http://localhost', 'token', file(), [], controller.signal), error => error.name === 'AbortError')
})

test('network and server details are not echoed as review errors', async t => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('private-server-detail') })
  await assert.rejects(inspectDocument('http://localhost', 'token', file(), [], new AbortController().signal), error => !error.message.includes('private-server-detail'))
  for (const status of [401, 403, 404, 413, 422, 429, 500]) {
    t.mock.method(globalThis, 'fetch', async () => Response.json({ detail: 'private-server-detail', code: 'private-server-detail' }, { status }))
    await assert.rejects(inspectDocument('http://localhost', 'token', file(), [], new AbortController().signal), error => !error.message.includes('private-server-detail'))
  }
})

test('clean or release-eligible responses, missing coverage, negative counts and broken offsets fail closed', () => {
  const bad = [null, { ...safe(), release_eligible: true }, { ...safe(), posture: 'CLEAN' }, { ...safe(), coverage: {} },
    { ...safe(), summary: { ...safe().summary, pages: -1 } },
    { ...safe(), surfaces: [{ id: 'page:1', kind: 'pdf-native', status: 'EXTRACTED', text: 'abc', candidate: 'x', location: {}, residual_families: {}, known_values_remaining: 0,
      matches: [{ start: 0, end: 99, kind: 'PERSON_NAME', basis: 'contextual-rule', replacement: 'x' }] }] }]
  for (const input of bad) assert.throws(() => parseDocumentReview(input), /invalid review/)
  assert.equal(parseDocumentReview(safe()).posture, 'REVIEW_REQUIRED')
})

test('document offsets use Unicode code points including non-BMP characters', () => {
  const review = safe()
  review.surfaces = [{ id: 'body', kind: 'docx-part', status: 'EXTRACTED', text: '😀a', candidate: '[X]', location: {}, residual_families: {}, known_values_remaining: 0,
    matches: [{ start: 0, end: 2, kind: 'PERSON_NAME', basis: 'contextual-rule', replacement: '[X]' }] }]
  assert.equal(parseDocumentReview(review), review)
  review.surfaces[0].matches[0].end = 3
  assert.throws(() => parseDocumentReview(review), /invalid review/)
})

test('a large valid review with 10k findings completes within the interactive budget', async () => {
  // A subprocess enforces a wall-clock bound even if validation blocks its event
  // loop. The old repeated whole-text scan takes minutes on this accepted input.
  const { spawnSync } = await import('node:child_process')
  const script = `${compiled}\nconst review = ${JSON.stringify(safe())};
    const text = ('x'.repeat(130) + ' contact@example.test\\n').repeat(10000);
    review.surfaces = [{id: 'body', kind: 'docx-part', status: 'EXTRACTED', text, candidate: '', location: {}, residual_families: {}, known_values_remaining: 0,
      matches: Array.from({length: 10000}, (_, i) => ({start: i * 152 + 131, end: i * 152 + 151, kind: 'EMAIL', basis: 'contextual-rule', replacement: '[EMAIL]'}))}];
    parseDocumentReview(review);`
  const result = spawnSync(process.execPath, ['--input-type=module', '-e', script], { timeout: 5000, encoding: 'utf8' })
  assert.equal(result.error, undefined, result.error?.message)
  assert.equal(result.status, 0, result.stderr)
})
