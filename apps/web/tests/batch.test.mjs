import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const source = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { readBatchFile, inspectSyntheticBatch } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
const files = [
  { id: 'f1', name: 'a.txt', size: 12, contentBase64: Buffer.from('Riya').toString('base64') },
  { id: 'f2', name: 'b.txt', size: 12, contentBase64: Buffer.from('note').toString('base64') },
]
const request = { apiBase: 'http://127.0.0.1:8000', token: 'synthetic-token', files, manualNames: [], aliasOverrides: {} }
const valid = () => ({ posture: 'SYNTHETIC_DEMO_ONLY', release_authorized: false, export_available: false,
  documents: [
    { id: 'f1', name: 'a.txt', kind: 'text', text: 'Riya', candidate_text: 'Gita', size_bytes: 4, preview_fidelity: 'source_text', structure_check: 'not_applicable',
      matches: [{ start: 0, end: 4, source: 'Riya', entity_id: 'E1', kind: 'PERSON_NAME', replacement: 'Gita' }] },
    { id: 'f2', name: 'b.txt', kind: 'text', text: 'note', candidate_text: 'note', size_bytes: 4, preview_fidelity: 'source_text', structure_check: 'not_applicable', matches: [] },
  ], entities: [{ id: 'E1', kind: 'PERSON_NAME', source: 'Riya', alias: 'Gita', mentions: 1 }], relationships: [],
  summary: { files: 2, detected_mentions: 1, transformed_mentions: 1, linked_entities: 1, explicit_relationships: 0 },
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

test('batch client rejects fabricated approval, mismatched content and counts', async t => {
  for (const change of [
    value => { value.release_authorized = true },
    value => { value.export_available = true },
    value => { value.documents[0].candidate_text = 'Riya' },
    value => { value.entities[0].mentions = 2 },
    value => { value.summary.detected_mentions = 0 },
    value => { value.verification.status = 'APPROVED' },
  ]) {
    const item = valid(); change(item)
    t.mock.method(globalThis, 'fetch', async () => Response.json(item))
    await assert.rejects(inspectSyntheticBatch(request), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('batch client rejects invalid intake and never sends data', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not send') })
  await assert.rejects(inspectSyntheticBatch({ ...request, token: '' }), /required/)
  await assert.rejects(inspectSyntheticBatch({ ...request, files: files.slice(0, 1) }), /required/)
  assert.equal(mock.mock.calls.length, 0)
})
