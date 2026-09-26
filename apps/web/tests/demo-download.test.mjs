import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true })
const source = readFileSync(new URL('../src/demo-download.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { prepareDemoCandidateFile, downloadDemoCandidate } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)

test('synthetic text candidate download uses candidate bytes, not source bytes', async () => {
  const candidate = await prepareDemoCandidateFile({ kind: 'text', name: 'calendar events.txt',
    text: 'Maya Patel', candidateText: 'John Singh', mediaPreview: null })
  assert.equal(candidate.name, 'calendar_events.candidate.txt')
  assert.equal(candidate.mimeType, 'text/plain;charset=utf-8')
  assert.equal(new TextDecoder().decode(candidate.bytes), 'John Singh')
})

test('image candidate is a PNG even when the source was JPEG', async () => {
  const png = Buffer.from('89504e470d0a1a0a0000000d4948445200000010000000100802000000', 'hex')
  const candidate = await prepareDemoCandidateFile({ kind: 'image', name: 'scan.jpg', mediaPreview: {
    pages: [{ candidatePngBase64: png.toString('base64'), candidatePngSha256: createHash('sha256').update(png).digest('hex') }], pdfRasterEvidence: null, candidatePdfBase64: null,
  } })
  assert.equal(candidate.name, 'scan.candidate.png')
  assert.equal(candidate.mimeType, 'image/png')
  assert.deepEqual(Buffer.from(candidate.bytes), png)
  await assert.rejects(prepareDemoCandidateFile({ kind: 'image', name: 'scan.jpg', mediaPreview: {
    pages: [{ candidatePngBase64: png.toString('base64'), candidatePngSha256: '0'.repeat(64) }], pdfRasterEvidence: null, candidatePdfBase64: null,
  } }), /integrity check/)
})

test('PDF candidate is digest-verified before browser download', async () => {
  const pdf = Buffer.from(`%PDF-1.4\n${'0'.repeat(180)}\n%%EOF\n`)
  const item = { kind: 'pdf', name: 'thread.pdf', mediaPreview: {
    pages: [{}], candidatePdfBase64: pdf.toString('base64'),
    pdfRasterEvidence: { bytes: pdf.length, pages: 1, sourceObjectsCopied: false,
      sha256: createHash('sha256').update(pdf).digest('hex') },
  } }
  const candidate = await prepareDemoCandidateFile(item)
  assert.equal(candidate.name, 'thread.candidate.pdf')
  assert.equal(candidate.mimeType, 'application/pdf')
  assert.deepEqual(Buffer.from(candidate.bytes), pdf)
  await assert.rejects(prepareDemoCandidateFile({ ...item, mediaPreview: { ...item.mediaPreview,
    pdfRasterEvidence: { ...item.mediaPreview.pdfRasterEvidence, sha256: '0'.repeat(64) } } }), /integrity check/)
  await assert.rejects(prepareDemoCandidateFile({ ...item, mediaPreview: { ...item.mediaPreview,
    pdfRasterEvidence: { ...item.mediaPreview.pdfRasterEvidence, bytes: pdf.length + 1 } } }), /declared size/)
})

test('browser download clicks candidate filename and revokes the temporary URL', async t => {
  const events = []
  const link = { hidden: false, click: () => events.push('click'), remove: () => events.push('remove') }
  t.mock.method(URL, 'createObjectURL', () => 'blob:synthetic-candidate')
  t.mock.method(URL, 'revokeObjectURL', () => events.push('revoke'))
  t.mock.method(globalThis, 'setTimeout', callback => { callback(); return 1 })
  Object.defineProperty(globalThis, 'document', { configurable: true, value: {
    createElement: () => link, body: { append: () => events.push('append') },
  } })
  t.after(() => { delete globalThis.document })
  await downloadDemoCandidate({ kind: 'text', name: 'input.txt', text: 'source', candidateText: 'candidate', mediaPreview: null })
  assert.equal(link.download, 'input.candidate.txt')
  assert.deepEqual(events, ['append', 'click', 'remove', 'revoke'])
})
