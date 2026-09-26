export type Mode = 'external_anonymized' | 'restricted_pseudonymized'
export type SourceFormat = 'text' | 'json' | 'jsonl' | 'csv'
export const DEMO_MAX_BYTES = 100_000

export type DemoFinding = { entityType: string; severity: 'medium' | 'high' | 'critical'; count: number }
export type DemoOperation = { entityType: string; action: 'REDACT' | 'PSEUDONYMIZE' | 'GENERALIZE' | 'SUPPRESS' | 'NULLIFY'; count: number }
export type DemoInspection = {
  posture: 'SYNTHETIC_DEMO_ONLY'
  format: SourceFormat
  findings: readonly DemoFinding[]
  operations: readonly DemoOperation[]
  transformedPreview: string
  limitations: readonly string[]
  releaseAuthorized: false
}

export class DemoInspectionFailure extends Error {
  constructor(message: string) { super(message); this.name = 'DemoInspectionFailure' }
}

const DEMO_ENTITY = /^[A-Z][A-Z0-9_]{0,63}$/
const DEMO_SEVERITIES = new Set(['medium', 'high', 'critical'])
const DEMO_ACTIONS = new Set(['REDACT', 'PSEUDONYMIZE', 'GENERALIZE', 'SUPPRESS', 'NULLIFY'])

function demoInvalid(): never { throw new DemoInspectionFailure('The demo service returned an invalid inspection result. Nothing was approved or exported.') }

/** Decode only supported synthetic-demo files; no browser upload occurs here. */
export function decodeDemoUpload(name: string, bytes: Uint8Array): { format: SourceFormat; content: string } {
  const extension = name.trim().toLowerCase().match(/\.([a-z0-9]+)$/)?.[1]
  const format = extension === 'txt' ? 'text' : extension
  if (format !== 'text' && format !== 'csv' && format !== 'json' && format !== 'jsonl') {
    throw new DemoInspectionFailure('Choose a .txt, .csv, .json, or .jsonl file.')
  }
  if (bytes.byteLength === 0 || bytes.byteLength > DEMO_MAX_BYTES) {
    throw new DemoInspectionFailure('Demo files must be between 1 byte and 100 KB.')
  }
  let content: string
  try { content = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false }).decode(bytes) } catch {
    throw new DemoInspectionFailure('The selected file is not valid UTF-8 text.')
  }
  if (!content.trim()) throw new DemoInspectionFailure('Demo files cannot be blank.')
  return { format, content }
}

function demoInspection(value: unknown, expectedFormat: SourceFormat): DemoInspection {
  if (!object(value) || Object.keys(value).length !== 7 || value.posture !== 'SYNTHETIC_DEMO_ONLY' || value.format !== expectedFormat ||
      value.release_authorized !== false || typeof value.transformed_preview !== 'string' ||
      new TextEncoder().encode(value.transformed_preview).byteLength > DEMO_MAX_BYTES ||
      !Array.isArray(value.findings) || !Array.isArray(value.operations) || !Array.isArray(value.limitations)) demoInvalid()
  const findings = value.findings.map(item => {
    if (!object(item) || Object.keys(item).length !== 3 || typeof item.entity_type !== 'string' || !DEMO_ENTITY.test(item.entity_type) ||
        typeof item.severity !== 'string' || !DEMO_SEVERITIES.has(item.severity) || !Number.isSafeInteger(item.count) || (item.count as number) < 1) demoInvalid()
    return { entityType: item.entity_type, severity: item.severity as DemoFinding['severity'], count: item.count as number }
  })
  const operations = value.operations.map(item => {
    if (!object(item) || Object.keys(item).length !== 3 || typeof item.entity_type !== 'string' || !DEMO_ENTITY.test(item.entity_type) ||
        typeof item.action !== 'string' || !DEMO_ACTIONS.has(item.action) || !Number.isSafeInteger(item.count) || (item.count as number) < 1) demoInvalid()
    return { entityType: item.entity_type, action: item.action as DemoOperation['action'], count: item.count as number }
  })
  if (!value.limitations.every(item => typeof item === 'string' && item.length > 0 && item.length <= 600 && !/[\r\n\u0000]/.test(item))) demoInvalid()
  return { posture: 'SYNTHETIC_DEMO_ONLY', format: expectedFormat, findings, operations, transformedPreview: value.transformed_preview,
    limitations: value.limitations as string[], releaseAuthorized: false }
}

export async function inspectSyntheticDemo(request: { apiBase: string; token: string; format: SourceFormat; content: string; signal?: AbortSignal }): Promise<DemoInspection> {
  const token = request.token.trim()
  if (!['text', 'json', 'jsonl', 'csv'].includes(request.format)) throw new DemoInspectionFailure('Unsupported demo source format.')
  if (!token || !request.content.trim()) throw new DemoInspectionFailure('A processor token and non-empty synthetic demo input are required.')
  if (new TextEncoder().encode(request.content).byteLength > DEMO_MAX_BYTES) throw new DemoInspectionFailure('Demo input exceeds the 100 KB limit.')
  const controller = new AbortController()
  let timedOut = false
  const cancel = () => controller.abort()
  request.signal?.addEventListener('abort', cancel, { once: true })
  if (request.signal?.aborted) cancel()
  const timer = setTimeout(() => { if (!controller.signal.aborted) { timedOut = true; controller.abort() } }, REQUEST_TIMEOUT_MS)
  try {
    return await abortable(async () => {
      let response: Response
      try {
        response = await fetch(request.apiBase.replace(/\/$/, '') + '/demo/inspect', {
          method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store', signal: controller.signal,
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
          body: JSON.stringify({ format: request.format, content: request.content, synthetic_only: true }),
        })
      } catch {
        throw new DemoInspectionFailure('Cannot reach the demo inspection service. No result was produced.')
      }
      if (!response.ok) {
        const messages: Record<number, string> = { 401: 'Authentication required.', 403: 'Synthetic demo inspection is not enabled or permitted.', 413: 'Demo input exceeds the 100 KB limit.', 422: 'The demo input did not pass validation.', 503: 'Synthetic demo inspection is unavailable.' }
        throw new DemoInspectionFailure((messages[response.status] || 'The demo inspection request failed.') + ' No result was approved or exported.')
      }
      try { return demoInspection(await response.json(), request.format) } catch (cause) {
        if (cause instanceof DemoInspectionFailure) throw cause
        throw new DemoInspectionFailure('The demo service returned an invalid inspection result. Nothing was approved or exported.')
      }
    }, controller.signal)
  } catch (cause) {
    if (controller.signal.aborted) throw new DemoInspectionFailure((timedOut ? 'Demo inspection timed out after 30 seconds.' : 'Demo inspection was cancelled.') + ' It does not undo data already received by the server.')
    if (cause instanceof DemoInspectionFailure) throw cause
    throw new DemoInspectionFailure('Cannot reach the demo inspection service. No result was produced.')
  } finally {
    clearTimeout(timer)
    request.signal?.removeEventListener('abort', cancel)
  }
}

// A separate, opt-in synthetic batch preview. It does not use release/control-
// plane endpoints or return a qualified artifact or anonymity verdict. A local
// demo copy can be downloaded, but never as an authorized buyer release.
export type BatchUpload = { id: string; name: string; contentBase64: string; size: number }
export type BatchManualFinding = { value: string; kind: 'OTHER_SENSITIVE' | 'BUSINESS_CONFIDENTIAL' | 'QUASI_IDENTIFIER' | 'GOVERNMENT_ID' | 'DATE_OF_BIRTH' }
export type BatchMatch = { start: number; end: number; source: string; entityId: string; kind: string; replacement: string; applied: boolean;
  origin: 'AUTOMATIC' | 'MANUAL' }
export type BatchMediaPage = { number: number; width: number; height: number; sourcePngBase64: string;
  candidatePngBase64: string; candidatePngSha256: string; ocrLines: number }
export type BatchMediaPreview = { pages: BatchMediaPage[]; fallbackLines: number; selfOcrResidualSources: number;
  pdfRasterEvidence: { sha256: string; bytes: number; pages: number; sourceObjectsCopied: false } | null;
  candidatePdfBase64: string | null }
export type BatchDocument = { id: string; name: string; kind: 'text' | 'csv' | 'json' | 'jsonl' | 'pdf' | 'image';
  text: string; candidateText: string; sizeBytes: number; previewFidelity: 'source_text' | 'raster_ocr_review';
  structureCheck: 'pass' | 'fail' | 'not_applicable'; matches: BatchMatch[]; mediaPreview: BatchMediaPreview | null }
export type BatchAliasStrategy = 'NAME_LENGTH_MATCH' | 'EMAIL_TEST_ADDRESS' | 'PAN_INVALID_TEST' |
  'US_SSN_INVALID' | 'NANP_FICTIONAL' | 'OPAQUE_REDACTION'
export type BatchEntity = { id: string; kind: string; source: string; alias: string; strategy: BatchAliasStrategy;
  mentions: number; excluded: boolean }
export type BatchRelationship = { sourceId: string; targetId: string; type: 'EMAILED' | 'ACCOUNT_OWNER_OF'; documentId: string; basis: string }
export type EntityGraphNode = { id: string; kind: 'person' | 'organization' | 'project'; label: string; documentIds: string[] }
export type EntityGraphEdgeType = 'assistant_to' | 'assistant_for' | 'works_at' | 'client_of' | 'works_on' | 'assigned_to' | 'sent_to'
export type EntityGraphEvidence = { documentId: string; rule: string; field?: string }
export type EntityGraphEdge = { id: string; type: EntityGraphEdgeType; sourceId: string; targetId: string; evidence: EntityGraphEvidence[] }
export type EntityGraph = { nodes: EntityGraphNode[]; edges: EntityGraphEdge[] }
export type BatchCheck = { name: string; status: 'PASS' | 'FAIL' | 'REVIEW' | 'NOT_TESTED' | 'NOT_APPLICABLE' | 'NOT_MEASURED'; detail: string }
export type BatchReferenceSpan = { start: number; end: number; entity_type: string }
export type BatchReferenceManifest = { basis: 'REVIEWER_ATTESTED_EXHAUSTIVE' | 'CURATED_SYNTHETIC_SAMPLE';
  documents: { name: string; annotations: BatchReferenceSpan[] }[] }
export type BatchAnnotationCounts = { truePositives: number; falsePositives: number; falseNegatives: number }
export type BatchFileScore = { id: string; exact: BatchAnnotationCounts; missed: BatchReferenceSpan[] }
export type BatchAnnotationScore = { basis: BatchReferenceManifest['basis']; status: 'OBSERVATIONAL_ONLY';
  labelledDocuments: number; goldAnnotations: number; exact: BatchAnnotationCounts; automaticExact: BatchAnnotationCounts;
  perType: Record<string, BatchAnnotationCounts>;
  perDocument: BatchFileScore[] }
export type BatchInspection = { posture: 'SYNTHETIC_DEMO_ONLY'; releaseAuthorized: false; exportAvailable: false;
  documents: BatchDocument[]; entities: BatchEntity[]; relationships: BatchRelationship[]; entityGraph: EntityGraph;
  summary: { files: number; detectedMentions: number; transformedMentions: number; suppressedMentions: number;
    linkedEntities: number; explicitRelationships: number };
  verification: { status: 'REVIEW_REQUIRED'; knownRuleResidualMatches: number; sourceValueResiduals: number; structureFailures: number;
    annotationScore: BatchAnnotationScore | null; checks: BatchCheck[] };
  limitations: string[] }

const BATCH_EXTENSIONS = new Set(['txt', 'csv', 'json', 'jsonl', 'pdf', 'png', 'jpg', 'jpeg'])
export const BATCH_MAX_MEDIA_BYTES = 500_000
export const BATCH_MAX_TOTAL_BYTES = 1_500_000
const BATCH_KIND = new Set(['text', 'csv', 'json', 'jsonl', 'pdf', 'image'])
const BATCH_KIND_BY_EXTENSION: Record<string, BatchDocument['kind']> = {
  txt: 'text', csv: 'csv', json: 'json', jsonl: 'jsonl', pdf: 'pdf', png: 'image', jpg: 'image', jpeg: 'image',
}
const BATCH_CHECK = new Set(['PASS', 'FAIL', 'REVIEW', 'NOT_TESTED', 'NOT_APPLICABLE', 'NOT_MEASURED'])
const MANUAL_FINDING_KINDS = new Set(['OTHER_SENSITIVE', 'BUSINESS_CONFIDENTIAL', 'QUASI_IDENTIFIER', 'GOVERNMENT_ID', 'DATE_OF_BIRTH'])
const REFERENCE_TYPES = new Set(['CREDENTIAL', 'EMAIL', 'PHONE', 'AADHAAR', 'PAN', 'CARD', 'IP', 'PERSON', 'ADDRESS',
  'DATE', 'LOCATION', 'ORGANIZATION', 'PASSPORT', 'GOVERNMENT_ID', 'HEALTH', 'PAYMENT', 'BUSINESS_SECRET', 'USER_ID',
  'OTHER_SENSITIVE', 'IP_ADDRESS', 'SENSITIVE_NUMBER', 'PAYMENT_SECRET', 'PERSON_NAME', 'DATE_OF_BIRTH',
  'HEALTH_SENSITIVE', 'BUSINESS_CONFIDENTIAL', 'QUASI_IDENTIFIER'])
const safeCount = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0
const safeText = (value: unknown, max = 120_000): value is string => typeof value === 'string' && value.length <= max
function pngHeaderMatches(value: string, width: number, height: number): boolean {
  try {
    const header = atob(value.slice(0, 32))
    if (header.length !== 24 || !header.startsWith('\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR')) return false
    const dimension = (start: number) => ((header.charCodeAt(start) * 2 ** 24) +
      (header.charCodeAt(start + 1) << 16) + (header.charCodeAt(start + 2) << 8) + header.charCodeAt(start + 3))
    return dimension(16) === width && dimension(20) === height
  } catch { return false }
}
function pdfEnvelopeMatches(value: unknown, byteCount: number): value is string {
  if (typeof value !== 'string' || value.length > 13_333_336 || value.length % 4 !== 0 ||
      !/^[A-Za-z0-9+/]+={0,2}$/.test(value)) return false
  const padding = value.endsWith('==') ? 2 : value.endsWith('=') ? 1 : 0
  if (value.length / 4 * 3 - padding !== byteCount) return false
  try {
    return atob(value.slice(0, 12)).startsWith('%PDF-') && atob(value.slice(-128)).includes('%%EOF')
  } catch { return false }
}

export async function readBatchFile(file: File, id: string): Promise<BatchUpload> {
  const extension = file.name.toLowerCase().match(/\.([a-z0-9]+)$/)?.[1]
  if (!extension || !BATCH_EXTENSIONS.has(extension)) throw new DemoInspectionFailure('Choose TXT, CSV, JSON, JSONL, PDF, PNG, or JPEG for this synthetic demo.')
  if (!/^[A-Za-z0-9_-]{1,48}$/.test(id) || !file.name || file.name.length > 160 || /[/\\]/.test(file.name)) throw new DemoInspectionFailure('Invalid demo filename.')
  const maximum = ['pdf', 'png', 'jpg', 'jpeg'].includes(extension) ? BATCH_MAX_MEDIA_BYTES : DEMO_MAX_BYTES
  if (file.size < 1 || file.size > maximum) throw new DemoInspectionFailure(`Each synthetic ${maximum === BATCH_MAX_MEDIA_BYTES ? 'PDF/image' : 'text'} file must be between 1 byte and ${maximum === BATCH_MAX_MEDIA_BYTES ? '500' : '100'} KB.`)
  const bytes = new Uint8Array(await file.arrayBuffer())
  let binary = ''
  for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192))
  return { id, name: file.name, contentBase64: btoa(binary), size: bytes.length }
}

export async function readBatchReferenceManifest(file: File, uploads: BatchUpload[]): Promise<BatchReferenceManifest> {
  if (!file.name.toLowerCase().endsWith('.json') || file.size < 1 || file.size > 40_000) {
    throw new DemoInspectionFailure('Reference labels must be a JSON file of 40 KB or less.')
  }
  let value: unknown
  try { value = JSON.parse(await file.text()) } catch { throw new DemoInspectionFailure('Reference labels must be valid UTF-8 JSON.') }
  if (!object(value) || Object.keys(value).sort().join(',') !== 'documents,schema_version' || value.schema_version !== 'batch-reference-v1' ||
      !Array.isArray(value.documents) || value.documents.length !== uploads.length) {
    throw new DemoInspectionFailure('Reference labels must list every staged document exactly once.')
  }
  const names = new Set(uploads.map(upload => upload.name))
  const documents = value.documents.map(raw => {
    if (!object(raw) || Object.keys(raw).sort().join(',') !== 'annotations,name' || !names.has(String(raw.name)) ||
        !Array.isArray(raw.annotations) || raw.annotations.length > 200) throw new DemoInspectionFailure('Reference labels contain an invalid document.')
    const annotations: BatchReferenceSpan[] = raw.annotations.map(span => {
      if (!object(span) || Object.keys(span).sort().join(',') !== 'end,entity_type,start' || !safeCount(span.start) ||
          !safeCount(span.end) || (span.end as number) <= (span.start as number) || !REFERENCE_TYPES.has(String(span.entity_type))) {
        throw new DemoInspectionFailure('Reference labels contain an invalid span or category.')
      }
      return { start: span.start as number, end: span.end as number, entity_type: span.entity_type as string }
    })
    return { name: raw.name as string, annotations }
  })
  if (new Set(documents.map(document => document.name)).size !== uploads.length) {
    throw new DemoInspectionFailure('Reference labels must list every staged document exactly once.')
  }
  return { basis: 'REVIEWER_ATTESTED_EXHAUSTIVE', documents }
}

function batchInvalid(): never { throw new DemoInspectionFailure('The batch service returned an invalid review result. Nothing was approved or exported.') }

function entityGraph(raw: unknown, documentIds: Set<string>, entities: BatchEntity[]): EntityGraph {
  // This graph is deliberately aliases and rule names only: no source spans, filenames, or mail addresses.
  if (!object(raw) || !Array.isArray(raw.nodes) || !Array.isArray(raw.edges)) batchInvalid()
  if (raw.nodes.length > 100 || raw.edges.length > 200) batchInvalid()
  const aliases = new Map(entities.filter(entity => entity.kind === 'PERSON_NAME').map(entity => [entity.id, entity.excluded ? 'Source retained' : entity.alias]))
  const nodes: EntityGraphNode[] = raw.nodes.map(node => {
    if (!object(node) || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(String(node.id)) ||
        !['person', 'organization', 'project'].includes(String(node.kind)) || !safeText(node.label, 80) ||
        !node.label.trim() || !Array.isArray(node.document_ids) || node.document_ids.length > 3 ||
        !node.document_ids.every(id => typeof id === 'string' && documentIds.has(id))) batchInvalid()
    if ((node.kind === 'person' && aliases.get(node.id as string) !== node.label) ||
        (node.kind === 'organization' && !/^Organization [1-9][0-9]{0,2}$/.test(node.label)) ||
        (node.kind === 'project' && !/^Project [1-9][0-9]{0,2}$/.test(node.label))) batchInvalid()
    return { id: node.id as string, kind: node.kind as EntityGraphNode['kind'], label: node.label as string,
      documentIds: [...new Set(node.document_ids as string[])] }
  })
  const nodeIds = new Set(nodes.map(node => node.id))
  if (nodeIds.size !== nodes.length) batchInvalid()
  const allowedTypes = new Set<EntityGraphEdgeType>(['assistant_to', 'assistant_for', 'works_at', 'client_of', 'works_on', 'assigned_to', 'sent_to'])
  const rules = new Set(['explicit_mail_header', 'explicit_structured_field_pair', 'explicit_signature_block', 'explicit_signature_title', 'explicit_role_statement'])
  const fields = new Set(['From/To/Cc', 'assistant,assistant_to', 'assistant,assistant_for', 'person_name,works_at', 'employee_name,works_at', 'company', 'employer', 'client_name,client_for', 'person_name,works_on', 'employee_name,works_on', 'project_name,assigned_to', 'Name,Title,Company', 'Title', 'client_of_statement', 'assistant_to_statement', 'assistant_for_statement', 'works_on_statement', 'assigned_to_statement'])
  const validKinds: Record<EntityGraphEdgeType, [EntityGraphNode['kind'], EntityGraphNode['kind']]> = {
    assistant_to: ['person', 'person'], assistant_for: ['person', 'organization'], sent_to: ['person', 'person'], works_at: ['person', 'organization'], client_of: ['person', 'organization'], works_on: ['person', 'project'], assigned_to: ['project', 'person'],
  }
  const kindsById = new Map(nodes.map(node => [node.id, node.kind]))
  const edges: EntityGraphEdge[] = raw.edges.map(edge => {
    if (!object(edge) || !/^relationship_[1-9][0-9]{0,3}$/.test(String(edge.id)) || !allowedTypes.has(edge.type as EntityGraphEdgeType) ||
        !nodeIds.has(String(edge.source_id)) || !nodeIds.has(String(edge.target_id)) || edge.source_id === edge.target_id || !Array.isArray(edge.evidence) || !edge.evidence.length || edge.evidence.length > 20) batchInvalid()
    const expectedKinds = validKinds[edge.type as EntityGraphEdgeType]
    if (kindsById.get(String(edge.source_id)) !== expectedKinds[0] || kindsById.get(String(edge.target_id)) !== expectedKinds[1]) batchInvalid()
    const evidence = edge.evidence.map(item => {
      if (!object(item) || typeof item.document_id !== 'string' || !documentIds.has(item.document_id) ||
          typeof item.rule !== 'string' || !rules.has(item.rule) || typeof item.field !== 'string' || !fields.has(item.field)) batchInvalid()
      return { documentId: item.document_id, rule: item.rule, field: item.field } as EntityGraphEvidence
    })
    return { id: edge.id as string, type: edge.type as EntityGraphEdgeType, sourceId: edge.source_id as string,
      targetId: edge.target_id as string, evidence }
  })
  if (new Set(edges.map(edge => edge.id)).size !== edges.length) batchInvalid()
  return { nodes, edges }
}

function batchInspection(value: unknown, expectedUploads: BatchUpload[], reference: BatchReferenceManifest | null,
  expectedExclusions: Record<string, 'FALSE_POSITIVE_CONFIRMED'>): BatchInspection {
  const expectedIds = expectedUploads.map(file => file.id)
  if (!object(value) || value.posture !== 'SYNTHETIC_DEMO_ONLY' || value.release_authorized !== false || value.export_available !== false ||
      !Array.isArray(value.documents) || value.documents.length !== expectedIds.length || !Array.isArray(value.entities) ||
      !Array.isArray(value.relationships) || !object(value.summary) || !object(value.verification) || !Array.isArray(value.limitations)) batchInvalid()
  const entities: BatchEntity[] = value.entities.map(raw => {
    if (!object(raw) || typeof raw.id !== 'string' || !/^E\d{1,4}$/.test(raw.id) || !safeText(raw.kind, 64) || !safeText(raw.source, 120) || !safeText(raw.alias, 120) || !safeCount(raw.mentions) || typeof raw.excluded !== 'boolean') batchInvalid()
    if (!['NAME_LENGTH_MATCH', 'EMAIL_TEST_ADDRESS', 'PAN_INVALID_TEST', 'US_SSN_INVALID', 'NANP_FICTIONAL', 'OPAQUE_REDACTION'].includes(String(raw.strategy))) batchInvalid()
    if (raw.strategy === 'NAME_LENGTH_MATCH' && (raw.kind !== 'PERSON_NAME' || (raw.alias as string).length !== (raw.source as string).length)) batchInvalid()
    if (raw.strategy === 'EMAIL_TEST_ADDRESS' && raw.kind !== 'EMAIL') batchInvalid()
    if (raw.strategy === 'PAN_INVALID_TEST' && (raw.kind !== 'PAN' || !/^[A-Z]{3}Z[A-Z][0-9]{4}[A-Z]$/.test(raw.alias as string))) batchInvalid()
    if (raw.strategy === 'US_SSN_INVALID' && (raw.kind !== 'GOVERNMENT_ID' || !/^000([- ]?)01\1[0-9]{4}$/.test(raw.alias as string))) batchInvalid()
    if (raw.strategy === 'NANP_FICTIONAL' && (raw.kind !== 'PHONE' || !/^\+1[ .()\-]*202[ .()\-]*555[ .()\-]*01[0-9]{2}$/.test(raw.alias as string))) batchInvalid()
    if (raw.strategy === 'OPAQUE_REDACTION' && raw.alias !== `[${raw.kind}_${raw.id}]`) batchInvalid()
    if (raw.kind === 'EMAIL' && (!/^[a-z0-9][a-z0-9._+-]*@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.test$/.test(raw.alias as string) ||
        (raw.alias as string).toLowerCase() === (raw.source as string).toLowerCase())) batchInvalid()
    return { id: raw.id, kind: raw.kind, source: raw.source, alias: raw.alias,
      strategy: raw.strategy as BatchAliasStrategy, mentions: raw.mentions as number, excluded: raw.excluded }
  })
  const entityIds = new Set(entities.map(item => item.id))
  const entitiesById = new Map(entities.map(item => [item.id, item]))
  if (entityIds.size !== entities.length || Object.keys(expectedExclusions).some(id => !entityIds.has(id)) ||
      entities.some(entity => entity.excluded !== Object.hasOwn(expectedExclusions, entity.id))) batchInvalid()
  const documents: BatchDocument[] = value.documents.map((raw, index) => {
    const extension = expectedUploads[index].name.toLowerCase().match(/\.([a-z0-9]+)$/)?.[1] || ''
    if (!object(raw) || raw.id !== expectedIds[index] || raw.name !== expectedUploads[index].name ||
        !BATCH_KIND.has(String(raw.kind)) || raw.kind !== BATCH_KIND_BY_EXTENSION[extension] ||
        !safeText(raw.text) || !safeText(raw.candidate_text) || raw.size_bytes !== expectedUploads[index].size ||
        !['source_text', 'raster_ocr_review'].includes(String(raw.preview_fidelity)) ||
        !['pass', 'fail', 'not_applicable'].includes(String(raw.structure_check)) || !Array.isArray(raw.matches)) batchInvalid()
    // The Python API reports Unicode code-point offsets. Browser string.slice
    // uses UTF-16 code units, so map offsets before rendering emoji-containing
    // documents; otherwise a valid span after an emoji appears corrupted.
    const codePoints = Array.from(raw.text as string)
    const unitOffsets = [0]
    for (const point of codePoints) unitOffsets.push(unitOffsets[unitOffsets.length - 1] + point.length)
    const matches: BatchMatch[] = raw.matches.map(match => {
      if (!object(match) || !safeCount(match.start) || !safeCount(match.end) || (match.end as number) <= (match.start as number) ||
          (match.end as number) > codePoints.length || !safeText(match.source, 100_000) ||
          codePoints.slice(match.start as number, match.end as number).join('') !== match.source ||
          !entityIds.has(String(match.entity_id)) || !safeText(match.kind, 64) || !safeText(match.replacement, 120) ||
          typeof match.applied !== 'boolean' || !['AUTOMATIC', 'MANUAL'].includes(String(match.origin))) batchInvalid()
      return { start: unitOffsets[match.start as number], end: unitOffsets[match.end as number], source: match.source, entityId: match.entity_id as string,
        kind: match.kind, replacement: match.replacement, applied: match.applied, origin: match.origin as BatchMatch['origin'] }
    })
    for (let i = 1; i < matches.length; i++) if (matches[i].start < matches[i - 1].end) batchInvalid()
    const rebuilt: string[] = []
    let offset = 0
    for (const match of matches) {
      const entity = entitiesById.get(match.entityId)
      if (!entity || entity.kind !== match.kind || entity.alias !== match.replacement || entity.excluded === match.applied) batchInvalid()
      rebuilt.push((raw.text as string).slice(offset, match.start), match.applied ? match.replacement : match.source)
      offset = match.end
    }
    rebuilt.push((raw.text as string).slice(offset))
    if (rebuilt.join('') !== raw.candidate_text) batchInvalid()
    let mediaPreview: BatchMediaPreview | null = null
    if (raw.kind === 'pdf' || raw.kind === 'image') {
      const media = raw.media_preview
      if (raw.preview_fidelity !== 'raster_ocr_review' || !object(media) || !Array.isArray(media.pages) ||
          media.pages.length < 1 || media.pages.length > 2 || !safeCount(media.fallback_lines) ||
          !safeCount(media.self_ocr_residual_sources)) batchInvalid()
      const pages: BatchMediaPage[] = media.pages.map((page, pageIndex) => {
        if (!object(page) || page.number !== pageIndex + 1 || !safeCount(page.width) || !safeCount(page.height) ||
            (page.width as number) < 16 || (page.height as number) < 16 ||
            (page.width as number) * (page.height as number) > 2_000_000 || !safeCount(page.ocr_lines) ||
            (page.ocr_lines as number) > 200 || typeof page.source_png_base64 !== 'string' ||
            typeof page.candidate_png_base64 !== 'string' || typeof page.candidate_png_sha256 !== 'string' ||
            !/^[0-9a-f]{64}$/.test(page.candidate_png_sha256) ||
            ![page.source_png_base64, page.candidate_png_base64].every(value => value.length < 3_400_000 &&
              /^[A-Za-z0-9+/]+={0,2}$/.test(value) && pngHeaderMatches(value, page.width as number, page.height as number))) batchInvalid()
        return { number: page.number as number, width: page.width as number, height: page.height as number,
          sourcePngBase64: page.source_png_base64 as string, candidatePngBase64: page.candidate_png_base64 as string,
          candidatePngSha256: page.candidate_png_sha256 as string, ocrLines: page.ocr_lines as number }
      })
      if (pages.reduce((sum, page) => sum + page.width * page.height, 0) > 3_000_000) batchInvalid()
      let pdfRasterEvidence: BatchMediaPreview['pdfRasterEvidence'] = null
      let candidatePdfBase64: string | null = null
      if (raw.kind === 'pdf') {
        const evidence = media.pdf_raster_evidence
        if (!object(evidence) || typeof evidence.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(evidence.sha256) ||
            !safeCount(evidence.bytes) || evidence.bytes < 100 || evidence.bytes > 10_000_000 ||
            evidence.pages !== pages.length || evidence.source_objects_copied !== false ||
            !pdfEnvelopeMatches(media.candidate_pdf_base64, evidence.bytes as number)) batchInvalid()
        pdfRasterEvidence = { sha256: evidence.sha256, bytes: evidence.bytes as number,
          pages: pages.length, sourceObjectsCopied: false }
        candidatePdfBase64 = media.candidate_pdf_base64 as string
      } else if (media.pdf_raster_evidence !== null || media.candidate_pdf_base64 !== null) batchInvalid()
      mediaPreview = { pages, fallbackLines: media.fallback_lines as number,
        selfOcrResidualSources: media.self_ocr_residual_sources as number, pdfRasterEvidence, candidatePdfBase64 }
    } else if (raw.media_preview !== undefined || raw.preview_fidelity !== 'source_text') batchInvalid()
    return { id: raw.id as string, name: raw.name as string, kind: raw.kind as BatchDocument['kind'], text: raw.text as string,
      candidateText: raw.candidate_text as string, sizeBytes: raw.size_bytes as number,
      previewFidelity: raw.preview_fidelity as BatchDocument['previewFidelity'], structureCheck: raw.structure_check as BatchDocument['structureCheck'], matches,
      mediaPreview }
  })
  const relationships: BatchRelationship[] = value.relationships.map(raw => {
    const documentKind = object(raw) ? documents.find(doc => doc.id === raw.document_id)?.kind : undefined
    const roleBasis = documentKind === 'json' || documentKind === 'jsonl' || documentKind === 'csv'
      ? `same ${documentKind.toUpperCase()} record account_owner/client_name` : null
    if (!object(raw) || !entityIds.has(String(raw.source_id)) || !entityIds.has(String(raw.target_id)) ||
        !['EMAILED', 'ACCOUNT_OWNER_OF'].includes(String(raw.type)) ||
        raw.source_id === raw.target_id || entitiesById.get(String(raw.source_id))?.kind !== 'PERSON_NAME' ||
        entitiesById.get(String(raw.target_id))?.kind !== 'PERSON_NAME' ||
        !expectedIds.includes(String(raw.document_id)) ||
        (raw.type === 'EMAILED' ? raw.basis !== 'explicit From/To or Cc header' : raw.basis !== roleBasis)) batchInvalid()
    return { sourceId: raw.source_id as string, targetId: raw.target_id as string,
      type: raw.type as BatchRelationship['type'], documentId: raw.document_id as string, basis: raw.basis as string }
  })
  const graph = entityGraph(value.entity_graph, new Set(documents.map(document => document.id)), entities)
  const summary = value.summary
  if (summary.files !== documents.length || !safeCount(summary.detected_mentions) || !safeCount(summary.transformed_mentions) ||
      !safeCount(summary.suppressed_mentions) ||
      !safeCount(summary.linked_entities) || !safeCount(summary.explicit_relationships) ||
      summary.detected_mentions !== documents.reduce((total, doc) => total + doc.matches.length, 0) ||
      summary.transformed_mentions !== documents.reduce((total, doc) => total + doc.matches.filter(match => match.applied).length, 0) ||
      summary.suppressed_mentions !== summary.detected_mentions - summary.transformed_mentions ||
      summary.explicit_relationships !== relationships.length ||
      summary.linked_entities !== entities.filter(item => item.mentions > 0).length ||
      entities.some(entity => entity.mentions !== documents.reduce((total, doc) => total + doc.matches.filter(match => match.entityId === entity.id).length, 0))) batchInvalid()
  const verification = value.verification
  if (verification.status !== 'REVIEW_REQUIRED' || !safeCount(verification.known_rule_residual_matches) ||
      !safeCount(verification.source_value_residuals) || !safeCount(verification.structure_failures) ||
      !Array.isArray(verification.checks) || verification.checks.length < 3 || verification.checks.length > 10) batchInvalid()
  const rawScore = verification.annotation_score
  if (reference === null && rawScore != null) batchInvalid()
  if (reference !== null && !object(rawScore)) batchInvalid()
  let annotationScore: BatchAnnotationScore | null = null
  if (object(rawScore)) {
    const countTriple = (raw: unknown): BatchAnnotationCounts => {
      if (!object(raw) || !safeCount(raw.true_positives) || !safeCount(raw.false_positives) || !safeCount(raw.false_negatives)) batchInvalid()
      return { truePositives: raw.true_positives as number, falsePositives: raw.false_positives as number,
        falseNegatives: raw.false_negatives as number }
    }
    if (rawScore.basis !== reference?.basis || rawScore.status !== 'OBSERVATIONAL_ONLY' ||
        rawScore.labelled_documents !== documents.length || !safeCount(rawScore.gold_annotations) ||
        !object(rawScore.per_type) || !Array.isArray(rawScore.per_document) || rawScore.per_document.length !== documents.length) batchInvalid()
    const exact = countTriple(rawScore.exact)
    const automaticExact = countTriple(rawScore.automatic_exact)
    const perType: Record<string, BatchAnnotationCounts> = {}
    for (const [kind, counts] of Object.entries(rawScore.per_type)) {
      if (!REFERENCE_TYPES.has(kind)) batchInvalid()
      perType[kind] = countTriple(counts)
    }
    if (exact.truePositives + exact.falseNegatives !== rawScore.gold_annotations ||
        exact.truePositives + exact.falsePositives !== summary.transformed_mentions ||
        Object.values(perType).reduce((sum, item) => sum + item.truePositives, 0) !== exact.truePositives ||
        Object.values(perType).reduce((sum, item) => sum + item.falsePositives, 0) !== exact.falsePositives ||
        Object.values(perType).reduce((sum, item) => sum + item.falseNegatives, 0) !== exact.falseNegatives) batchInvalid()
    const automaticTotals: BatchAnnotationCounts = { truePositives: 0, falsePositives: 0, falseNegatives: 0 }
    const perDocument: BatchFileScore[] = rawScore.per_document.map((item, index) => {
      const doc = documents[index]
      const labels = reference!.documents.find(entry => entry.name === doc.name)?.annotations
      if (!object(item) || item.id !== doc.id || !Array.isArray(item.missed) || !labels) batchInvalid()
      const counts = countTriple(item.exact)
      const codePoints = Array.from(doc.text)
      const offsets = [0]
      for (const point of codePoints) offsets.push(offsets[offsets.length - 1] + point.length)
      const key = (start: number, end: number, kind: string) => `${start}:${end}:${kind}`
      const expected = new Set(labels.map(span => {
        if (!safeCount(span.start) || !safeCount(span.end) || span.end <= span.start || span.end > codePoints.length || !REFERENCE_TYPES.has(span.entity_type)) batchInvalid()
        return key(offsets[span.start], offsets[span.end], span.entity_type)
      }))
      if (expected.size !== labels.length) batchInvalid()
      const actual = new Set(doc.matches.filter(match => match.applied).map(match => key(match.start, match.end, match.kind)))
      const automatic = new Set(doc.matches.filter(match => match.origin === 'AUTOMATIC').map(match => key(match.start, match.end, match.kind)))
      const automaticMatched = [...expected].filter(entry => automatic.has(entry)).length
      automaticTotals.truePositives += automaticMatched
      automaticTotals.falsePositives += [...automatic].filter(entry => !expected.has(entry)).length
      automaticTotals.falseNegatives += expected.size - automaticMatched
      const missedKeys = [...expected].filter(entry => !actual.has(entry))
      const missed: BatchReferenceSpan[] = item.missed.map(span => {
        if (!object(span) || !safeCount(span.start) || !safeCount(span.end) || span.end <= span.start ||
            span.end > codePoints.length || !REFERENCE_TYPES.has(String(span.entity_type))) batchInvalid()
        return { start: span.start as number, end: span.end as number, entity_type: span.entity_type as string }
      })
      const returnedMissed = new Set(missed.map(span => key(offsets[span.start], offsets[span.end], span.entity_type)))
      if (returnedMissed.size !== missed.length || returnedMissed.size !== missedKeys.length ||
          missedKeys.some(entry => !returnedMissed.has(entry)) ||
          counts.truePositives !== expected.size - missedKeys.length ||
          counts.falsePositives !== [...actual].filter(entry => !expected.has(entry)).length ||
          counts.falseNegatives !== missedKeys.length) batchInvalid()
      return { id: doc.id, exact: counts, missed }
    })
    if (perDocument.reduce((sum, item) => sum + item.exact.truePositives, 0) !== exact.truePositives ||
        perDocument.reduce((sum, item) => sum + item.exact.falsePositives, 0) !== exact.falsePositives ||
        perDocument.reduce((sum, item) => sum + item.exact.falseNegatives, 0) !== exact.falseNegatives ||
        automaticTotals.truePositives !== automaticExact.truePositives ||
        automaticTotals.falsePositives !== automaticExact.falsePositives ||
        automaticTotals.falseNegatives !== automaticExact.falseNegatives) batchInvalid()
    annotationScore = { basis: rawScore.basis as BatchReferenceManifest['basis'], status: 'OBSERVATIONAL_ONLY',
      labelledDocuments: documents.length, goldAnnotations: rawScore.gold_annotations as number, exact, automaticExact,
      perType, perDocument }
  }
  const checks: BatchCheck[] = verification.checks.map(raw => {
    if (!object(raw) || !safeText(raw.name, 100) || !BATCH_CHECK.has(String(raw.status)) || !safeText(raw.detail, 600)) batchInvalid()
    return { name: raw.name, status: raw.status as BatchCheck['status'], detail: raw.detail }
  })
  if (!value.limitations.every(item => safeText(item, 600))) batchInvalid()
  return { posture: 'SYNTHETIC_DEMO_ONLY', releaseAuthorized: false, exportAvailable: false, documents, entities, relationships, entityGraph: graph,
    summary: { files: summary.files as number, detectedMentions: summary.detected_mentions as number,
      transformedMentions: summary.transformed_mentions as number, suppressedMentions: summary.suppressed_mentions as number,
      linkedEntities: summary.linked_entities as number, explicitRelationships: summary.explicit_relationships as number },
    verification: { status: 'REVIEW_REQUIRED', knownRuleResidualMatches: verification.known_rule_residual_matches as number,
      sourceValueResiduals: verification.source_value_residuals as number,
      structureFailures: verification.structure_failures as number, annotationScore, checks }, limitations: value.limitations as string[] }
}

export async function inspectSyntheticBatch(request: { apiBase: string; token: string; files: BatchUpload[]; manualNames: string[];
  manualFindings?: BatchManualFinding[];
  aliasOverrides: Record<string, string>; reviewExclusions?: Record<string, 'FALSE_POSITIVE_CONFIRMED'>;
  referenceManifest?: BatchReferenceManifest | null; signal?: AbortSignal }): Promise<BatchInspection> {
  if (!request.token.trim() || request.files.length < 2 || request.files.length > 3 ||
      request.files.some(file => file.size < 1 || file.size > (/\.(pdf|png|jpe?g)$/i.test(file.name) ? BATCH_MAX_MEDIA_BYTES : DEMO_MAX_BYTES)) ||
      request.files.reduce((sum, file) => sum + file.size, 0) > BATCH_MAX_TOTAL_BYTES) {
    throw new DemoInspectionFailure('A processor token and two or three bounded synthetic files are required.')
  }
  if (request.reviewExclusions && (Object.keys(request.reviewExclusions).length > 100 ||
      Object.entries(request.reviewExclusions).some(([id, reason]) => !/^E\d{1,4}$/.test(id) || reason !== 'FALSE_POSITIVE_CONFIRMED'))) {
    throw new DemoInspectionFailure('Invalid synthetic reviewer exclusions.')
  }
  if (request.manualFindings && (request.manualFindings.length > 20 ||
      request.manualFindings.some(item => !item || typeof item.value !== 'string' || !MANUAL_FINDING_KINDS.has(item.kind) || item.value !== item.value.trim() ||
        Array.from(item.value).length < 2 || Array.from(item.value).length > 80 || /[\p{C}\p{Zl}\p{Zp}]/u.test(item.value)) ||
      new Set(request.manualFindings.map(item => `${item.kind}:${item.value.toLocaleLowerCase()}`)).size !== request.manualFindings.length)) {
    throw new DemoInspectionFailure('Invalid manually reviewed sensitive findings.')
  }
  const controller = new AbortController()
  const reference = request.referenceManifest
  if (reference && (reference.documents.length !== request.files.length ||
      new Set(reference.documents.map(document => document.name)).size !== request.files.length ||
      reference.documents.some(document => !request.files.some(file => file.name === document.name)))) {
    throw new DemoInspectionFailure('Reference labels must match every staged document.')
  }
  let timedOut = false
  const cancel = () => controller.abort()
  request.signal?.addEventListener('abort', cancel, { once: true })
  if (request.signal?.aborted) cancel()
  const timer = setTimeout(() => { timedOut = true; controller.abort() }, REQUEST_TIMEOUT_MS)
  try {
    return await abortable(async () => {
      let response: Response
      try {
        response = await fetch(request.apiBase.replace(/\/$/, '') + '/demo/batch/inspect', {
          method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store', signal: controller.signal,
          headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${request.token.trim()}` },
          body: JSON.stringify({ synthetic_only: true, files: request.files.map(file => ({ id: file.id, name: file.name, content_base64: file.contentBase64 })),
            manual_names: request.manualNames, manual_findings: request.manualFindings || [], alias_overrides: request.aliasOverrides,
            review_exclusions: request.reviewExclusions || {},
            ...(reference ? { reference_annotations: { basis: reference.basis, documents: reference.documents.map(document => ({
              id: request.files.find(file => file.name === document.name)!.id, annotations: document.annotations })) } } : {}) }),
        })
      } catch { throw new DemoInspectionFailure('Cannot reach the synthetic batch service. No result was produced.') }
      if (!response.ok) {
        const messages: Record<number, string> = { 401: 'Authentication required.', 403: 'Synthetic batch mode is not enabled or permitted.',
          413: 'The batch exceeds the service limit.', 422: 'A file or correction is invalid. Check media size, OCR readability, format, and alias length.', 503: 'Synthetic batch mode is unavailable.' }
        throw new DemoInspectionFailure(messages[response.status] || 'The synthetic batch request failed.')
      }
      try { return batchInspection(await response.json(), request.files, reference || null,
        request.reviewExclusions || {}) } catch (cause) {
        if (cause instanceof DemoInspectionFailure) throw cause
        return batchInvalid()
      }
    }, controller.signal)
  } catch (cause) {
    if (controller.signal.aborted) throw new DemoInspectionFailure(timedOut ? 'Batch inspection timed out after 30 seconds.' : 'Batch inspection was cancelled.')
    throw cause
  } finally { clearTimeout(timer); request.signal?.removeEventListener('abort', cancel) }
}
export type ReleaseView = {
  id: string; dataset_id: string; status: string;
  eligibility: 'BLOCKED' | 'REVIEW_REQUIRED'; output: null;
  card: { release_id: string; dataset_id: string; eligibility: 'BLOCKED' | 'REVIEW_REQUIRED'; policy_version: string; release_mode: Mode; evidence_status: 'INSUFFICIENT_EVIDENCE'; scores: null;
    findings: { entity_type: string; severity: string; count: number }[]; gates: string[]; limitations: string[] }
}
type Request = { apiBase: string; token: string; content: string; mode: Mode; recipient: string; format?: SourceFormat; signal?: AbortSignal }
export const REQUEST_TIMEOUT_MS = 30_000
// Bound the entire workflow, including response bodies and both POST requests.
// Abort also wins if a transport ignores the signal or settles late.
function abortable<T>(operation: () => Promise<T>, signal: AbortSignal): Promise<T> {
  return new Promise((resolve, reject) => {
    const abort = () => reject(new DOMException('Request aborted', 'AbortError'))
    if (signal.aborted) { abort(); return }
    signal.addEventListener('abort', abort, { once: true })
    Promise.resolve().then(() => {
      signal.throwIfAborted()
      return operation()
    }).then(resolve, reject).finally(() => signal.removeEventListener('abort', abort))
  })
}
const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => typeof x === 'string')
const invalid = () => new Error('The API returned an invalid or unsafe response. No release was authorized.')
export function validateRelease(value: unknown): ReleaseView {
  if (!object(value) || typeof value.id !== 'string' || !value.id || typeof value.dataset_id !== 'string' || !value.dataset_id || value.status !== 'evaluation_incomplete' ||
      value.output !== null || typeof value.eligibility !== 'string' || !['BLOCKED', 'REVIEW_REQUIRED'].includes(value.eligibility) || !object(value.card)) throw invalid()
  const card = value.card
  if (card.release_id !== value.id || card.dataset_id !== value.dataset_id || card.eligibility !== value.eligibility ||
      card.evidence_status !== 'INSUFFICIENT_EVIDENCE' || card.scores !== null || typeof card.policy_version !== 'string' ||
      typeof card.release_mode !== 'string' || !['external_anonymized', 'restricted_pseudonymized'].includes(card.release_mode) ||
      !strings(card.gates) || !card.gates.includes('EXPORT_DISABLED') || !card.gates.includes('QUALIFICATION_REQUIRED') || !strings(card.limitations) ||
      !Array.isArray(card.findings) || !card.findings.every(f => object(f) && typeof f.entity_type === 'string' && typeof f.severity === 'string' && typeof f.count === 'number' && Number.isSafeInteger(f.count) && f.count >= 0)) throw invalid()
  return value as ReleaseView
}
async function post(base: string, path: string, token: string, body: unknown, signal?: AbortSignal): Promise<unknown> {
  signal?.throwIfAborted()
  let response: Response
  try { response = await fetch(base.replace(/\/$/, '') + path, {
    method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store', signal,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body),
  }) } catch { throw new Error('Cannot reach the API. No local fallback or release was produced.') }
  if (!response.ok) {
    const messages: Record<number, string> = { 401: 'Authentication required.', 403: 'This action is not permitted.', 409: 'The request conflicts with release controls.', 413: 'Input exceeds the processing limit.', 422: 'The request did not pass validation.', 429: 'Development capacity reached.', 503: 'The development service is not configured or is unavailable.' }
    throw new Error((messages[response.status] || 'The API request failed.') + ' No release was authorized.')
  }
  try {
    const value: unknown = await response.json()
    signal?.throwIfAborted()
    return value
  } catch { throw invalid() }
}
export async function requestRelease(request: Request): Promise<ReleaseView> {
  const { apiBase, content, mode, recipient } = request
  const format = request.format ?? 'text'
  if (!['text', 'json', 'jsonl', 'csv'].includes(format)) throw new Error('Unsupported source format.')
  const token = request.token.trim()
  if (!token || !content.trim() || !recipient.trim() || !['external_anonymized', 'restricted_pseudonymized'].includes(mode)) throw new Error('A token, synthetic input, recipient and valid mode are required.')
  if (new TextEncoder().encode(content).length > 2_000_000) throw new Error('Input exceeds the processing limit. No release was authorized.')
  const policy = mode === 'external_anonymized' ? 'external-release-v1' : 'restricted-pseudonymized-v1'
  const controller = new AbortController()
  let timedOut = false
  const cancel = () => controller.abort()
  request.signal?.addEventListener('abort', cancel, { once: true })
  if (request.signal?.aborted) cancel()
  const timer = setTimeout(() => {
    if (!controller.signal.aborted) { timedOut = true; controller.abort() }
  }, REQUEST_TIMEOUT_MS)
  try {
    return await abortable(async () => {
      const signal = controller.signal
      const dataset = await post(apiBase, '/ingestions', token, { format, name: 'synthetic-workbench', content, owner: 'development', jurisdiction: 'unspecified', intended_use: 'synthetic-evaluation-only', recipient: recipient.trim(), retention_days: 1 }, signal)
      if (!object(dataset) || typeof dataset.id !== 'string') throw invalid()
      const release = validateRelease(await post(apiBase, '/releases', token, { dataset_id: dataset.id, release_mode: mode, policy_version: policy, allow_review: true }, signal))
      if (release.dataset_id !== dataset.id || release.card.release_mode !== mode || release.card.policy_version !== policy) throw invalid()
      return release
    }, controller.signal)
  } catch (cause) {
    if (controller.signal.aborted) throw new Error((timedOut ? 'Request timed out after 30 seconds.' : 'Request cancelled.') + ' No release was authorized. Cancellation does not undo data already received or stop server-side processing.')
    throw cause
  } finally {
    clearTimeout(timer)
    request.signal?.removeEventListener('abort', cancel)
  }
}

// M6 control-plane workbench -------------------------------------------------
//
// This path is deliberately separate from the legacy, non-exporting M1 demo
// above.  It only talks to the provenance/rights/policy/run APIs and returns a
// freshly-built metadata view.  In particular, it never requests an artifact
// body and it never calls the legacy /releases endpoint.

export type ControlPlaneRequest = {
  apiBase: string
  token: string
  content: string
  recipient: string
  purpose: string
  mode: Mode
  format?: SourceFormat
  language?: 'en' | 'und'
  signal?: AbortSignal
}

export type CandidateLedgerMetadata = {
  entityType: string
  action: string
  reason: string
  count: number
}

export type CandidateMetadataView = {
  artifactDigest: string
  schemaDigest: string
  payloadKind: 'text' | 'structured'
  mediaType: 'text/plain' | 'application/json'
  byteCount: number
  ledger: readonly CandidateLedgerMetadata[]
}

export type ControlPlaneView = {
  datasetId: string
  runId: string
  state: 'REGISTERED' | 'RUNNING' | 'CANDIDATE' | 'QUARANTINED' | 'FAILED'
  attempts: number
  policy: { id: string; key: string; digest: string }
  rights: { id: string; profileId: string; digest: string; expiresAt: string }
  candidate: CandidateMetadataView | null
  message: string
}

/** A source-independent, UI-safe failure from the metadata-only workflow. */
export class ControlPlaneFailure extends Error {
  constructor(message: string) { super(message); this.name = 'ControlPlaneFailure' }
}

export const DEFAULT_POLICY_NOTICE = 'The comprehensive policy covers PII, health-sensitive, payment, credential, business-confidential, and quasi-identifier data. rules-v1 only covers PII, payment, and credentials, so this workflow is expected to quarantine rather than produce an eligible candidate.'

const CONTROL_POLICY = {
  policy_id: 'workbench-baseline',
  version: 'v1',
  release_modes: ['external_anonymized', 'restricted_pseudonymized'],
  formats: ['csv', 'json', 'jsonl', 'text'],
  languages: ['en', 'und'],
  rules: [
    { category: 'CREDENTIAL', action: 'block', priority: 0 },
    { category: 'PAYMENT', action: 'suppress', priority: 10 },
    { category: 'HEALTH_SENSITIVE', action: 'suppress', priority: 20 },
    { category: 'PII', action: 'suppress', priority: 30 },
    { category: 'BUSINESS_CONFIDENTIAL', action: 'review', priority: 40 },
    { category: 'QUASI_IDENTIFIER', action: 'generalize', priority: 50 },
  ],
} as const

const CONTROL_STATES = new Set<ControlPlaneView['state']>(['REGISTERED', 'RUNNING', 'CANDIDATE', 'QUARANTINED', 'FAILED'])
// Candidate, policy and request identities are explicitly algorithm-labelled.
// The pre-existing rights-profile contract uses a bare SHA-256 hex digest;
// retain that distinction rather than silently accepting either form everywhere.
const DIGEST = /^sha256:[0-9a-f]{64}$/
const RIGHTS_DIGEST = /^[0-9a-f]{64}$/
const LABEL = /^[a-z0-9][a-z0-9._:-]{0,127}$/
const LEDGER_ENTITY = /^[A-Z][A-Z0-9_]{0,63}$/
const LEDGER_ACTIONS = new Set(['REDACT', 'PSEUDONYMIZE', 'GENERALIZE', 'SUPPRESS', 'NULLIFY'])
const LEDGER_REASONS = new Set(['POLICY_RULE', 'DETECTOR_FINDING', 'SCHEMA_SAFE_NULL'])
// Python's canonical ``datetime.isoformat`` may retain six fractional digits;
// accept only that RFC 3339 UTC representation (not arbitrary date strings).
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$/

const controlInvalid = () => new ControlPlaneFailure('The API returned invalid control-plane metadata. No candidate body was returned or released.')
const nonEmpty = (value: unknown): value is string => typeof value === 'string' && value.length > 0 && value.length <= 160
const sameStrings = (actual: unknown, expected: readonly string[]) => Array.isArray(actual) && actual.length === expected.length && actual.every((value, index) => value === expected[index])

function safeControlId(value: unknown): value is string {
  return typeof value === 'string' && /^[A-Za-z0-9-]{1,128}$/.test(value)
}

function metadataPostPath(runId: string): string { return `/processing-runs/${encodeURIComponent(runId)}/execute` }

async function postControl(base: string, path: string, token: string, body: unknown, signal: AbortSignal, idempotencyKey?: string): Promise<unknown> {
  signal.throwIfAborted()
  let response: Response
  try {
    response = await fetch(base.replace(/\/$/, '') + path, {
      method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store', signal,
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}`, ...(idempotencyKey ? { 'Idempotency-Key': idempotencyKey } : {}) },
      body: JSON.stringify(body),
    })
  } catch {
    throw new ControlPlaneFailure('Cannot reach the API. No local fallback, candidate body, or release was produced.')
  }
  if (!response.ok) {
    const messages: Record<number, string> = { 401: 'Authentication required.', 403: 'This action is not permitted.', 409: 'The request conflicts with control-plane safeguards.', 413: 'Input exceeds the processing limit.', 422: 'The request did not pass validation.', 429: 'Development capacity reached.', 503: 'The development service is not configured or is unavailable.' }
    throw new ControlPlaneFailure((messages[response.status] || 'The control-plane request failed.') + ' No candidate body was returned or released.')
  }
  try {
    const value: unknown = await response.json()
    signal.throwIfAborted()
    return value
  } catch {
    throw controlInvalid()
  }
}

function candidateMetadata(value: unknown): CandidateMetadataView | null {
  if (value === null) return null
  if (!object(value) || Object.keys(value).length !== 6 || !DIGEST.test(String(value.artifact_digest)) || !DIGEST.test(String(value.schema_digest)) ||
      (value.payload_kind !== 'text' && value.payload_kind !== 'structured') ||
      (value.media_type !== 'text/plain' && value.media_type !== 'application/json') ||
      !Number.isSafeInteger(value.byte_count) || (value.byte_count as number) < 0 || !Array.isArray(value.ledger)) throw controlInvalid()
  const ledger = value.ledger.map(entry => {
    // The private artifact contract has a fixed source-free ledger vocabulary.
    // Do not display arbitrary server strings here: those could carry source
    // content if an upstream service were misconfigured or compromised.
    if (!object(entry) || Object.keys(entry).length !== 4 || typeof entry.entity_type !== 'string' || !LEDGER_ENTITY.test(entry.entity_type) ||
        typeof entry.action !== 'string' || !LEDGER_ACTIONS.has(entry.action) ||
        typeof entry.reason !== 'string' || !LEDGER_REASONS.has(entry.reason) ||
        !Number.isSafeInteger(entry.count) || (entry.count as number) < 1) throw controlInvalid()
    return { entityType: entry.entity_type, action: entry.action, reason: entry.reason, count: entry.count as number }
  })
  return {
    artifactDigest: value.artifact_digest as string, schemaDigest: value.schema_digest as string,
    payloadKind: value.payload_kind, mediaType: value.media_type,
    byteCount: value.byte_count as number, ledger,
  }
}

function controlRunView(value: unknown, expected: { datasetId: string; policyDigest: string; rightsDigest: string; recipient: string; purpose: string }): Omit<ControlPlaneView, 'policy' | 'rights' | 'message'> {
  if (!object(value) || !safeControlId(value.id) || value.dataset_id !== expected.datasetId || !CONTROL_STATES.has(value.state as ControlPlaneView['state']) ||
      !Number.isSafeInteger(value.attempts) || (value.attempts as number) < 0 || (value.attempts as number) > 3 ||
      !DIGEST.test(String(value.request_digest)) || value.method_id !== 'rules-v1' || (value.language !== 'en' && value.language !== 'und') ||
      value.policy_digest !== expected.policyDigest || value.rights_digest !== expected.rightsDigest || value.recipient !== expected.recipient || value.purpose !== expected.purpose ||
      !Array.isArray(value.events)) throw controlInvalid()
  // Validate events but intentionally do not return them: an API event stream
  // is not part of the compact workbench contract.
  for (const event of value.events) {
    if (!object(event) || !Number.isSafeInteger(event.sequence) || !nonEmpty(event.state) || !nonEmpty(event.action) ||
        !nonEmpty(event.occurred_at) || !Number.isSafeInteger(event.attempt)) throw controlInvalid()
  }
  return { datasetId: expected.datasetId, runId: value.id, state: value.state as ControlPlaneView['state'], attempts: value.attempts as number, candidate: candidateMetadata(value.candidate) }
}

function newIdempotencyKey(): string {
  const id = globalThis.crypto?.randomUUID?.()
  if (typeof id !== 'string' || !id) throw new ControlPlaneFailure('Secure browser randomness is required to register a processing run.')
  return id
}

/**
 * Create a strict ingestion, a resale rights profile, a comprehensive policy,
 * a processing run, and execute it. This is metadata-only: it neither fetches
 * candidate bytes nor creates a release/export request.
 */
export async function runControlPlane(request: ControlPlaneRequest): Promise<ControlPlaneView> {
  const format = request.format ?? 'text'
  const language = request.language ?? 'en'
  const token = request.token.trim()
  const recipient = request.recipient.trim()
  const purpose = request.purpose.trim()
  if (!['text', 'json', 'jsonl', 'csv'].includes(format)) throw new ControlPlaneFailure('Unsupported source format.')
  if (!token || !request.content.trim() || !recipient || !purpose || !['external_anonymized', 'restricted_pseudonymized'].includes(request.mode)) throw new ControlPlaneFailure('A token, synthetic input, recipient, purpose, and valid mode are required.')
  if (!LABEL.test(recipient) || !LABEL.test(purpose)) throw new ControlPlaneFailure('Recipient and purpose must be lowercase control-plane labels.')
  if (new TextEncoder().encode(request.content).length > 2_000_000) throw new ControlPlaneFailure('Input exceeds the processing limit. No candidate body was returned or released.')

  const controller = new AbortController()
  let timedOut = false
  const cancel = () => controller.abort()
  request.signal?.addEventListener('abort', cancel, { once: true })
  if (request.signal?.aborted) cancel()
  const timer = setTimeout(() => { if (!controller.signal.aborted) { timedOut = true; controller.abort() } }, REQUEST_TIMEOUT_MS)
  try {
    return await abortable(async () => {
      const signal = controller.signal
      const ingestion = await postControl(request.apiBase, '/ingestions', token, {
        format, name: 'synthetic-workbench', content: request.content, owner: 'development', jurisdiction: 'unspecified',
        intended_use: purpose, recipient, retention_days: 1,
      }, signal)
      if (!object(ingestion) || !safeControlId(ingestion.id)) throw controlInvalid()
      const datasetId = ingestion.id
      const rights = await postControl(request.apiBase, '/rights-profiles', token, {
      profile_id: 'workbench-rights', version: 'v1', permitted_purposes: [purpose], permitted_recipients: [recipient],
        expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(), resale_allowed: true,
      }, signal)
  if (!object(rights) || !safeControlId(rights.id) || rights.profile_id !== 'workbench-rights' || rights.version !== 'v1' || !RIGHTS_DIGEST.test(String(rights.digest)) ||
          typeof rights.expires_at !== 'string' || !ISO_TIME.test(rights.expires_at) || rights.resale_allowed !== true ||
          !sameStrings(rights.permitted_purposes, [purpose]) || !sameStrings(rights.permitted_recipients, [recipient])) throw controlInvalid()
      const policy = await postControl(request.apiBase, '/policy-snapshots', token, CONTROL_POLICY, signal)
      if (!object(policy) || !safeControlId(policy.id) || policy.key !== 'workbench-baseline::v1' || !DIGEST.test(String(policy.digest)) ||
          !sameStrings(policy.formats, CONTROL_POLICY.formats) || !sameStrings(policy.languages, CONTROL_POLICY.languages) ||
          !sameStrings(policy.release_modes, CONTROL_POLICY.release_modes)) throw controlInvalid()
      const run = await postControl(request.apiBase, '/processing-runs', token, {
        dataset_id: datasetId, rights_profile_id: rights.id, policy_snapshot_id: policy.id, recipient, purpose,
        release_mode: request.mode, language, method_id: 'rules-v1',
      }, signal, newIdempotencyKey())
      const registered = controlRunView(run, { datasetId, policyDigest: policy.digest as string, rightsDigest: rights.digest as string, recipient, purpose })
      if (registered.state !== 'REGISTERED' || registered.candidate !== null) throw controlInvalid()
      const executed = controlRunView(await postControl(request.apiBase, metadataPostPath(registered.runId), token, {}, signal), {
        datasetId, policyDigest: policy.digest as string, rightsDigest: rights.digest as string, recipient, purpose,
      })
      return {
        ...executed,
        policy: { id: policy.id, key: policy.key, digest: policy.digest as string },
        rights: { id: rights.id, profileId: rights.profile_id, digest: rights.digest as string, expiresAt: rights.expires_at },
        message: executed.state === 'QUARANTINED' ? DEFAULT_POLICY_NOTICE : 'Processing completed without returning candidate content.',
      }
    }, controller.signal)
  } catch (cause) {
    if (controller.signal.aborted) throw new ControlPlaneFailure((timedOut ? 'Request timed out after 30 seconds.' : 'Request cancelled.') + ' No candidate body was returned or released. Cancellation does not undo data already received or stop server-side processing.')
    throw cause
  } finally {
    clearTimeout(timer)
    request.signal?.removeEventListener('abort', cancel)
  }
}
