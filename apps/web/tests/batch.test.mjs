import test from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
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
  ], entities: [{ id: 'E1', kind: 'PERSON_NAME', source: 'Riya', alias: 'Gita', strategy: 'NAME_LENGTH_MATCH', mentions: 1, excluded: false }], relationships: [], entity_graph: { nodes: [], edges: [] },
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
  response.entities[0] = { id: 'E1', kind: 'EMAIL', source: 'riya@example.test', alias: 'gita@example.test', strategy: 'EMAIL_TEST_ADDRESS', mentions: 1, excluded: false }
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

test('batch client binds declared PAN strategy to a deliberately invalid alias', async t => {
  const panFiles = [{ id: 'f1', name: 'a.txt', size: 10, contentBase64: Buffer.from('ABCPD1234F').toString('base64') }, files[1]]
  const response = valid()
  response.documents[0].text = 'ABCPD1234F'
  response.documents[0].candidate_text = 'TSTZA0001A'
  response.documents[0].size_bytes = 10
  response.documents[0].matches[0] = { start: 0, end: 10, source: 'ABCPD1234F', entity_id: 'E1',
    kind: 'PAN', replacement: 'TSTZA0001A', applied: true, origin: 'AUTOMATIC' }
  response.entities[0] = { id: 'E1', kind: 'PAN', source: 'ABCPD1234F', alias: 'TSTZA0001A',
    strategy: 'PAN_INVALID_TEST', mentions: 1, excluded: false }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  assert.equal((await inspectSyntheticBatch({ ...request, files: panFiles })).entities[0].strategy, 'PAN_INVALID_TEST')
  t.mock.restoreAll()
  for (const [strategy, alias] of [['PAN_INVALID_TEST', 'TSTPA0001A'], ['NAME_LENGTH_MATCH', 'TSTZA0001A']]) {
    const tampered = structuredClone(response)
    tampered.entities[0].strategy = strategy
    tampered.entities[0].alias = alias
    tampered.documents[0].matches[0].replacement = alias
    tampered.documents[0].candidate_text = alias
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch({ ...request, files: panFiles }), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('batch client accepts only bounded review references and reserved internal URLs', async t => {
  for (const [kind, source, alias, strategy] of [
    ['EMPLOYEE_ID', 'HS-EMP-1042', 'Employee ID [review 0001]', 'CONTEXTUAL_REVIEW_REF'],
    ['ADDRESS', '25 Sample Street, Example City, CA 90000', 'Postal address [review 0001]', 'CONTEXTUAL_REVIEW_REF'],
    ['INTERNAL_URL', 'https://github.example.test/private', 'https://review-0001.invalid/resource', 'INTERNAL_URL_RESERVED_DOMAIN'],
  ]) {
    const contextual = valid()
    contextual.documents[0].text = source
    contextual.documents[0].candidate_text = alias
    contextual.documents[0].size_bytes = Buffer.byteLength(source)
    contextual.documents[0].matches[0] = { start: 0, end: source.length, source, entity_id: 'E1', kind,
      replacement: alias, applied: true, origin: 'AUTOMATIC' }
    contextual.entities[0] = { id: 'E1', kind, source, alias, strategy, mentions: 1, excluded: false }
    const contextualRequest = { ...request, files: [{ ...files[0], size: Buffer.byteLength(source),
      contentBase64: Buffer.from(source).toString('base64') }, files[1]] }
    t.mock.method(globalThis, 'fetch', async () => Response.json(contextual))
    assert.equal((await inspectSyntheticBatch(contextualRequest)).entities[0].alias, alias)
    t.mock.restoreAll()
    const tampered = structuredClone(contextual)
    tampered.entities[0].alias = kind === 'INTERNAL_URL' ? 'https://review-0001.example.com/resource' : 'Employee ID [review source]'
    tampered.documents[0].matches[0].replacement = tampered.entities[0].alias
    tampered.documents[0].candidate_text = tampered.entities[0].alias
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch(contextualRequest), /invalid review result/)
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
    source_png_base64: png, candidate_png_base64: png,
    candidate_png_sha256: createHash('sha256').update(Buffer.from(png, 'base64')).digest('hex'), ocr_lines: 1 }], fallback_lines: 0,
    self_ocr_residual_sources: 0, candidate_low_confidence_lines: 0, pdf_raster_evidence: null, candidate_pdf_base64: null }
  const mediaRequest = { ...request, files: [files[0], { ...files[1], name: 'b.png' }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const result = await inspectSyntheticBatch(mediaRequest)
  assert.equal(result.documents[1].mediaPreview.pages[0].width, 16)
  t.mock.restoreAll()
  const fabricatedMediaLocator = structuredClone(response)
  fabricatedMediaLocator.entity_graph = { nodes: [{ id: 'E1', kind: 'person', label: 'Gita', document_ids: ['f1'] }, { id: 'organization_1', kind: 'organization', label: 'Organization 1', document_ids: ['f2'] }], edges: [{ id: 'edge_0123456789abcdef', type: 'works_at', source_id: 'E1', target_id: 'organization_1', evidence: [{ document_id: 'f2', rule: 'explicit_structured_field_pair', field: 'company', locator: { status: 'SUPPORTED', kind: 'text_span', start: 0, end: 1, line_start: 1, line_end: 1 } }] }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(fabricatedMediaLocator))
  await assert.rejects(inspectSyntheticBatch(mediaRequest), /invalid review result/)
  t.mock.restoreAll()
  for (const change of [
    value => { value.documents[1].media_preview.pages[0].width = 17 },
    value => { value.documents[1].media_preview.pages[0].candidate_png_base64 = 'not-a-png' },
    value => { value.documents[1].media_preview.pages[0].candidate_png_sha256 = 'bad' },
    value => { delete value.documents[1].media_preview.candidate_low_confidence_lines },
    value => { value.documents[1].media_preview.candidate_low_confidence_lines = -1 },
    value => { value.documents[1].media_preview.pdf_raster_evidence = { sha256: '0'.repeat(64), bytes: 500, pages: 1, source_objects_copied: false } },
    value => { value.documents[1].media_preview.candidate_pdf_base64 = 'JVBERi0xLjQ=' },
    value => { value.documents[1].kind = 'pdf' },
  ]) {
    const tampered = structuredClone(response); change(tampered)
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch(mediaRequest), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('graph media locators bind source, page and approximate OCR boxes before navigation', async t => {
  const png = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAI0lEQVR4nGP8//8/AymAiSTVDKMaiANMRKqDg1ENxACSQwkAVW0DHeN02ZEAAAAASUVORK5CYII='
  const blackPng = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAEUlEQVR4nGNgGAWjYBQwQAEAAxAAAXyL/2UAAAAASUVORK5CYII='
  const rasterHash = createHash('sha256').update(Buffer.from(png, 'base64')).digest('hex')
  const mediaRequest = { ...request, files: [files[0], { ...files[1], name: 'b.png' }] }
  const response = valid()
  const sourceHash = createHash('sha256').update(Buffer.from(files[1].contentBase64, 'base64')).digest('hex')
  response.documents[1].name = 'b.png'; response.documents[1].kind = 'image'; response.documents[1].preview_fidelity = 'raster_ocr_review'
  response.documents[1].source_sha256 = sourceHash
  response.documents[1].media_preview = { pages: [{ number: 1, width: 16, height: 16,
    source_png_base64: png, candidate_png_base64: png,
    source_png_sha256: rasterHash,
    candidate_png_sha256: createHash('sha256').update(Buffer.from(png, 'base64')).digest('hex'), ocr_lines: 1 }],
    fallback_lines: 0, self_ocr_residual_sources: 0, candidate_low_confidence_lines: 0,
    pdf_raster_evidence: null, candidate_pdf_base64: null }
  const locator = { status: 'SUPPORTED', kind: 'ocr_line_boxes', precision: 'OCR_LINE_BOX_APPROXIMATE',
    source_sha256: sourceHash, source_png_sha256: rasterHash, page: 1, width: 16, height: 16,
    line_boxes: [{ x0: 1, y0: 2, x1: 8, y1: 9 }] }
  response.entity_graph = { nodes: [{ id: 'E1', kind: 'person', label: 'Gita', document_ids: ['f1'] },
    { id: 'organization_1', kind: 'organization', label: 'Organization 1', document_ids: ['f2'] }],
    edges: [{ id: 'edge_0123456789abcdef', type: 'works_at', source_id: 'E1', target_id: 'organization_1',
      evidence: [{ document_id: 'f2', rule: 'explicit_structured_field_pair', field: 'company', locator }] }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const result = await inspectSyntheticBatch(mediaRequest)
  assert.deepEqual(result.entityGraph.edges[0].evidence[0].locator, { status: 'SUPPORTED', kind: 'ocr_line_boxes',
    precision: 'OCR_LINE_BOX_APPROXIMATE', sourceSha256: sourceHash, sourcePngSha256: rasterHash, page: 1, width: 16, height: 16,
    lineBoxes: [{ x0: 1, y0: 2, x1: 8, y1: 9 }] })
  t.mock.restoreAll()
  for (const change of [
    value => { value.entity_graph.edges[0].evidence[0].locator.source_sha256 = '0'.repeat(64) },
    value => { value.entity_graph.edges[0].evidence[0].locator.source_png_sha256 = '0'.repeat(64) },
    value => { value.documents[1].media_preview.pages[0].source_png_sha256 = '0'.repeat(64) },
    value => { value.documents[1].media_preview.pages[0].source_png_base64 = blackPng },
    value => { value.documents[1].source_sha256 = '0'.repeat(64); value.entity_graph.edges[0].evidence[0].locator.source_sha256 = '0'.repeat(64) },
    value => { value.entity_graph.edges[0].evidence[0].locator.page = 2 },
    value => { value.entity_graph.edges[0].evidence[0].locator.width = 17 },
    value => { value.entity_graph.edges[0].evidence[0].locator.line_boxes[0].x1 = 17 },
    value => { value.entity_graph.edges[0].evidence[0].locator.line_boxes = [] },
    value => { value.entity_graph.edges[0].evidence[0].locator.precision = 'EXACT_PIXELS' },
  ]) {
    const tampered = structuredClone(response); change(tampered)
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch(mediaRequest), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('coordinate corrections bind exact returned regions and source digests', async t => {
  const png = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAI0lEQVR4nGP8//8/AymAiSTVDKMaiANMRKqDg1ENxACSQwkAVW0DHeN02ZEAAAAASUVORK5CYII='
  const blackPng = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAEUlEQVR4nGNgGAWjYBQwQAEAAxAAAXyL/2UAAAAASUVORK5CYII='
  const oldBitmap = Object.getOwnPropertyDescriptor(globalThis, 'createImageBitmap')
  const oldDocument = Object.getOwnPropertyDescriptor(globalThis, 'document')
  Object.defineProperty(globalThis, 'createImageBitmap', { configurable: true, value: async blob => ({ width: 16, height: 16,
    black: Buffer.from(await blob.arrayBuffer()).equals(Buffer.from(blackPng, 'base64')), close() {} }) })
  Object.defineProperty(globalThis, 'document', { configurable: true, value: { createElement: () => {
    let black = false
    return { width: 0, height: 0, getContext: () => ({ drawImage: bitmap => { black = bitmap.black },
      getImageData: (_x, _y, width, height) => {
        const data = new Uint8ClampedArray(width * height * 4)
        for (let index = 0; index < data.length; index += 4) { data[index] = black ? 0 : 255; data[index + 3] = 255 }
        return { data }
      } }) }
  } } })
  t.after(() => {
    if (oldBitmap) Object.defineProperty(globalThis, 'createImageBitmap', oldBitmap); else delete globalThis.createImageBitmap
    if (oldDocument) Object.defineProperty(globalThis, 'document', oldDocument); else delete globalThis.document
  })
  const response = valid()
  response.documents[1].name = 'b.png'; response.documents[1].kind = 'image'; response.documents[1].preview_fidelity = 'raster_ocr_review'
  const correction = { documentId: 'f2', page: 1, x0: 1, y0: 2, x1: 8, y1: 9, kind: 'OTHER_SENSITIVE' }
  response.documents[0].source_sha256 = createHash('sha256').update(Buffer.from(files[0].contentBase64, 'base64')).digest('hex')
  response.documents[1].source_sha256 = createHash('sha256').update(Buffer.from(files[1].contentBase64, 'base64')).digest('hex')
  response.documents[1].media_preview = { pages: [{ number: 1, width: 16, height: 16, source_png_base64: png, candidate_png_base64: blackPng,
    source_png_sha256: createHash('sha256').update(Buffer.from(png, 'base64')).digest('hex'), candidate_png_sha256: createHash('sha256').update(Buffer.from(blackPng, 'base64')).digest('hex'),
    manual_regions: [{ document_id: 'f2', page: 1, x0: 1, y0: 2, x1: 8, y1: 9, kind: 'OTHER_SENSITIVE', origin: 'REVIEWER_COORDINATE' }], ocr_lines: 1 }], fallback_lines: 0, self_ocr_residual_sources: 0, candidate_low_confidence_lines: 0, pdf_raster_evidence: null, candidate_pdf_base64: null }
  const coordinateRequest = { ...request, files: [files[0], { ...files[1], name: 'b.png' }], coordinateCorrections: [correction] }
  const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const result = await inspectSyntheticBatch(coordinateRequest)
  assert.deepEqual(JSON.parse(mock.mock.calls[0].arguments[1].body).coordinate_corrections, [{ document_id: 'f2', page: 1, x0: 1, y0: 2, x1: 8, y1: 9, kind: 'OTHER_SENSITIVE' }])
  assert.equal(result.documents[1].mediaPreview.pages[0].manualRegions.length, 1)
  t.mock.restoreAll()
  for (const change of [value => { value.documents[1].media_preview.pages[0].manual_regions[0].x1 = 7 }, value => { value.documents[1].media_preview.pages[0].manual_regions.push(structuredClone(value.documents[1].media_preview.pages[0].manual_regions[0])) }, value => { value.documents[1].media_preview.pages[0].source_png_sha256 = '0'.repeat(64) }, value => { const page = value.documents[1].media_preview.pages[0]; page.candidate_png_base64 = png; page.candidate_png_sha256 = page.source_png_sha256 }]) {
    const tampered = structuredClone(response); change(tampered)
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch(coordinateRequest), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('batch client accepts only a typed, non-source entity graph', async t => {
  const response = valid()
  response.entity_graph = { nodes: [{ id: 'E1', kind: 'person', label: 'Gita', document_ids: ['f1'] }, { id: 'organization_1', kind: 'organization', label: 'Organization 1', document_ids: ['f2'] }], edges: [{ id: 'edge_0123456789abcdef', type: 'works_at', source_id: 'E1', target_id: 'organization_1', evidence: [{ document_id: 'f2', rule: 'explicit_structured_field_pair', field: 'company', locator: { status: 'SUPPORTED', kind: 'text_span', start: 0, end: 4, line_start: 1, line_end: 1 } }] }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  assert.equal((await inspectSyntheticBatch(request)).entityGraph.edges[0].type, 'works_at')
  t.mock.restoreAll()
  for (const change of [value => { value.entity_graph.nodes[0].label = 'Riya' }, value => { value.entity_graph.edges[0].evidence[0].field = 'raw@example.test' }, value => { value.entity_graph.edges[0].type = 'sent_to' }]) {
    const tampered = structuredClone(response); change(tampered)
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch(request), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('graph locators are bounded, line-bound to source text, and preserve Unicode navigation offsets', async t => {
  const response = valid()
  response.documents[1].text = '😀\nnote'; response.documents[1].candidate_text = '😀\nnote'; response.documents[1].size_bytes = 9
  response.entity_graph = { nodes: [{ id: 'E1', kind: 'person', label: 'Gita', document_ids: ['f1'] }, { id: 'organization_1', kind: 'organization', label: 'Organization 1', document_ids: ['f2'] }], edges: [{ id: 'edge_0123456789abcdef', type: 'works_at', source_id: 'E1', target_id: 'organization_1', evidence: [{ document_id: 'f2', rule: 'explicit_structured_field_pair', field: 'company', locator: { status: 'SUPPORTED', kind: 'text_span', start: 2, end: 6, line_start: 2, line_end: 2 } }] }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const unicodeRequest = { ...request, files: [files[0], { ...files[1], size: 9, contentBase64: Buffer.from('😀\nnote').toString('base64') }] }
  const result = await inspectSyntheticBatch(unicodeRequest)
  assert.deepEqual(result.entityGraph.edges[0].evidence[0].locator, { status: 'SUPPORTED', kind: 'text_span', start: 3, end: 7, lineStart: 2, lineEnd: 2 })
  t.mock.restoreAll()
  for (const locator of [
    { status: 'SUPPORTED', kind: 'text_span', start: 2, end: 6, line_start: 1, line_end: 1 },
    { status: 'SUPPORTED', kind: 'text_span', start: 2, end: 99, line_start: 2, line_end: 2 },
    { status: 'UNSUPPORTED', reason: 'untrusted' },
  ]) {
    const tampered = structuredClone(response); tampered.entity_graph.edges[0].evidence[0].locator = locator
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch(unicodeRequest), /invalid review result/)
    t.mock.restoreAll()
  }
})

test('batch client requires bounded candidate PDF bytes matching raster evidence', async t => {
  const png = 'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAAI0lEQVR4nGP8//8/AymAiSTVDKMaiANMRKqDg1ENxACSQwkAVW0DHeN02ZEAAAAASUVORK5CYII='
  const candidate = Buffer.from(`%PDF-1.4\n${'0'.repeat(180)}\n%%EOF\n`)
  const response = valid()
  response.documents[1].name = 'b.pdf'
  response.documents[1].kind = 'pdf'
  response.documents[1].preview_fidelity = 'raster_ocr_review'
  response.documents[1].media_preview = { pages: [{ number: 1, width: 16, height: 16,
    source_png_base64: png, candidate_png_base64: png,
    candidate_png_sha256: createHash('sha256').update(Buffer.from(png, 'base64')).digest('hex'), ocr_lines: 1 }], fallback_lines: 0,
    self_ocr_residual_sources: 0, candidate_low_confidence_lines: 0, pdf_raster_evidence: { sha256: '0'.repeat(64),
      bytes: candidate.length, pages: 1, source_objects_copied: false },
    candidate_pdf_base64: candidate.toString('base64') }
  const mediaRequest = { ...request, files: [files[0], { ...files[1], name: 'b.pdf' }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  assert.equal((await inspectSyntheticBatch(mediaRequest)).documents[1].mediaPreview.candidatePdfBase64,
    candidate.toString('base64'))
  t.mock.restoreAll()
  for (const change of [
    value => { value.documents[1].media_preview.candidate_pdf_base64 = undefined },
    value => { value.documents[1].media_preview.candidate_pdf_base64 = 'AAAA' },
    value => { value.documents[1].media_preview.pdf_raster_evidence.bytes++ },
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
  response.verification.aggregate_scorecard = { status: 'OBSERVATIONAL_ONLY', classification: 'SYNTHETIC_INTERNAL_EVALUATION_ONLY',
    qualification: 'NOT_QUALIFIED', automatic_exact: { true_positives: 1, false_positives: 0, false_negatives: 1 },
    reviewer_corrected_exact: { true_positives: 1, false_positives: 0, false_negatives: 1 },
    final_artifact_validation: { status: 'ABSTAINED', reason: 'INDEPENDENT_ENGINE_UNAVAILABLE' },
    final_text_validation: { status: 'INDEPENDENT_RULE_SCANNER_TEXT_ONLY', bound_artifacts: 2,
      assessed_categories: ['CREDENTIAL', 'PAYMENT', 'PII'], residual_units_by_category: { CREDENTIAL: 0, PAYMENT: 0, PII: 0 }, abstained_artifacts: 0 },
    relationship_review: 'NO_GRAPH_GOLD_OR_REVIEW_STATE' }
  const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const result = await inspectSyntheticBatch({ ...request, referenceManifest })
  assert.equal(result.verification.annotationScore.exact.falseNegatives, 1)
  assert.equal(result.verification.annotationScore.automaticExact.falseNegatives, 1)
  assert.equal(result.verification.aggregateScorecard.qualification, 'NOT_QUALIFIED')
  assert.equal(result.verification.aggregateScorecard.finalArtifactValidation.status, 'ABSTAINED')
  assert.equal(result.verification.aggregateScorecard.finalTextValidation.status, 'INDEPENDENT_RULE_SCANNER_TEXT_ONLY')
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
    value => { value.verification.aggregate_scorecard.qualification = 'QUALIFIED' },
    value => { value.verification.aggregate_scorecard.automatic_exact.false_negatives = 0 },
    value => { value.verification.aggregate_scorecard.relationship_review = 'SCORED' },
  ]) {
    const tampered = structuredClone(response); change(tampered)
    t.mock.method(globalThis, 'fetch', async () => Response.json(tampered))
    await assert.rejects(inspectSyntheticBatch({ ...request, referenceManifest }), /invalid review result/)
    t.mock.restoreAll()
  }
})
