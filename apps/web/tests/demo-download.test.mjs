import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash, webcrypto } from 'node:crypto'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, 'crypto', { value: webcrypto, configurable: true })
const source = readFileSync(new URL('../src/demo-download.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { prepareDemoCandidateFile, downloadDemoCandidate, csvHasFormulaRisk, reviewCopyBlockReason } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
const review = () => ({ documents: [], summary: { suppressedMentions: 0 }, verification: {
  sourceValueResiduals: 0, structureFailures: 0, finalTextValidation: {
    residualUnitsByCategory: { CREDENTIAL: 0, PAYMENT: 0, PII: 0 }, abstainedArtifacts: 0,
  },
} })

test('synthetic text candidate download uses candidate bytes, not source bytes', async () => {
  const candidate = await prepareDemoCandidateFile({ kind: 'text', name: 'calendar events.txt',
    text: 'Maya Patel', candidateText: 'John Singh', mediaPreview: null })
  assert.equal(candidate.name, 'calendar_events.candidate.txt')
  assert.equal(candidate.mimeType, 'text/plain;charset=utf-8')
  assert.equal(new TextDecoder().decode(candidate.bytes), 'John Singh')
})

test('CSV review copy rejects formula-shaped cells, including quoted and spaced values', async () => {
  for (const candidateText of ['name,note\nGita,=1+1', 'name,note\nGita,"=1,2"',
    'name,note\nGita,"  @SUM(1)"', 'name,note\nGita,+1', 'name,note\nGita,\t=1',
    'name,note\nGita,"\n=1"', 'name,note\nGita,＝1', '\ufeff=1,note\nGita,review',
    'name,note\nGita,"safe;=1"']) {
    assert.equal(csvHasFormulaRisk(candidateText), true)
    await assert.rejects(prepareDemoCandidateFile({ kind: 'csv', name: 'people.csv', candidateText }), /spreadsheet formula/)
  }
  const safe = 'name,note\nGita,"review, then resolve"'
  assert.equal(csvHasFormulaRisk(safe), false)
  const candidate = await prepareDemoCandidateFile({ kind: 'csv', name: 'people.csv', candidateText: safe })
  assert.equal(new TextDecoder().decode(candidate.bytes), safe)
})

test('review-copy gate requires explicit flag acknowledgement and blocks scanner abstentions', async () => {
  const item = { kind: 'text', name: 'note.txt', candidateText: 'Synthetic note', mediaPreview: null }
  const flagged = review()
  flagged.verification.finalTextValidation.residualUnitsByCategory.PII = 1
  assert.match(reviewCopyBlockReason(flagged, item), /final text scan flagged/)
  await assert.rejects(downloadDemoCandidate(item, flagged), /final text scan flagged/)
  assert.equal(reviewCopyBlockReason(flagged, item, true), '')
  const abstained = review()
  abstained.verification.finalTextValidation.abstainedArtifacts = 1
  assert.match(reviewCopyBlockReason(abstained, item), /final text scan abstained/)
  await assert.rejects(downloadDemoCandidate(item, abstained), /final text scan abstained/)
  assert.match(reviewCopyBlockReason(abstained, item, true), /final text scan abstained/)
  assert.equal(reviewCopyBlockReason(review(), item), '')
  const mediaResidual = review()
  mediaResidual.documents.push({ mediaPreview: { selfOcrResidualSources: 1 } })
  assert.match(reviewCopyBlockReason(mediaResidual, item, true), /raster recheck/)
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

test('reviewed PDF is rebuilt from blacked-out candidate PNG pixels, not server PDF bytes', async t => {
  const png = Buffer.from('89504e470d0a1a0a0000000d4948445200000002000000020806000000', 'hex')
  const originalBitmap = globalThis.createImageBitmap
  const originalCanvas = globalThis.OffscreenCanvas
  const pixels = new Uint8ClampedArray([
    0, 0, 0, 255, 12, 34, 56, 255,
    78, 90, 12, 255, 34, 56, 78, 255,
  ])
  Object.defineProperty(globalThis, 'createImageBitmap', { configurable: true, value: async () => ({ width: 2, height: 2, close() {} }) })
  Object.defineProperty(globalThis, 'OffscreenCanvas', { configurable: true, value: class {
    getContext() { return { drawImage() {}, getImageData: () => ({ data: pixels }) } }
  } })
  t.after(() => {
    if (originalBitmap) Object.defineProperty(globalThis, 'createImageBitmap', { configurable: true, value: originalBitmap })
    else delete globalThis.createImageBitmap
    if (originalCanvas) Object.defineProperty(globalThis, 'OffscreenCanvas', { configurable: true, value: originalCanvas })
    else delete globalThis.OffscreenCanvas
  })
  const item = { kind: 'pdf', name: 'reviewed.pdf', mediaPreview: {
    pages: [{ width: 2, height: 2, candidatePngBase64: png.toString('base64'), candidatePngSha256: createHash('sha256').update(png).digest('hex'),
      manualRegions: [{ x0: 0, y0: 0, x1: 1, y1: 1 }] }],
    candidatePdfBase64: Buffer.from('SERVER-PDF-MUST-NOT-BE-USED').toString('base64'), pdfRasterEvidence: null,
  } }
  const candidate = await prepareDemoCandidateFile(item)
  assert.equal(candidate.mimeType, 'application/pdf')
  assert.match(new TextDecoder('ascii').decode(candidate.bytes.subarray(0, 8)), /^%PDF-1.4/)
  assert.equal(new TextDecoder().decode(candidate.bytes).includes('SERVER-PDF-MUST-NOT-BE-USED'), false)
  pixels[7] = 254
  await assert.rejects(prepareDemoCandidateFile(item), /contains transparency/)
  pixels[7] = 255
  pixels[3] = 254
  await assert.rejects(prepareDemoCandidateFile(item), /not opaque black/)
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
  const flagged = review()
  flagged.verification.finalTextValidation.residualUnitsByCategory.PII = 1
  await downloadDemoCandidate({ kind: 'text', name: 'input.txt', text: 'source', candidateText: 'candidate', mediaPreview: null }, flagged, true)
  assert.equal(link.download, 'input.candidate.txt')
  assert.deepEqual(events, ['append', 'click', 'remove', 'revoke'])
})
