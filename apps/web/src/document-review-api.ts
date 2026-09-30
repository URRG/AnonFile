export const DOCUMENT_MAX_BYTES = 8_000_000
export type DocumentSurface = {
  id: string; kind: string; text: string; candidate: string; status: string
  location: Record<string, unknown>; matches: { start: number; end: number; kind: string; basis: string; replacement: string }[]
  residual_families: Record<string, number>; known_values_remaining: number
}
export type DocumentReview = {
  schema: 'document-review-v1'; posture: 'REVIEW_REQUIRED'; release_eligible: false
  name: string; sha256: string; format: string; surfaces: DocumentSurface[]; gaps: string[]; limitations: string[]
  inventory: { id: string; kind: string; status: string; visibility?: string; ocr?: string; visual?: string }[]
  coverage: { text: 'PARSED_WITH_GAPS'; names_addresses: 'UNQUALIFIED'; pixels: 'UNMEASURED'; original_format_output: 'NOT_PRODUCED' }
  summary: { surfaces: number; nonempty_surfaces: number; pages: number; findings: Record<string, number>; matches: number; residual_units: number; known_values_remaining: number }
}
const ERROR_MESSAGES: Record<string, string> = {
  FILE_LIMIT: 'Choose a file up to 8 MB.', PAGE_LIMIT: 'PDF review supports up to 400 pages.',
  ENCRYPTED_PDF: 'Encrypted PDFs cannot be reviewed.', UNSUPPORTED_FORMAT: 'Choose a PDF, DOCX, PPTX or XLSX file.',
  REVIEW_BUSY: 'Another document is being reviewed. Try again when it finishes.',
  REVIEW_TIMEOUT: 'The document exceeded the review time limit. Coverage was not established.',
  REVIEW_VALUE_NOT_FOUND: 'A correction does not occur in the extracted text. Check its spelling.',
  PACKAGE_LIMIT_OR_ENCRYPTION: 'The Office package is encrypted or exceeds the expansion limit.',
  PARSER_RESOURCE_LIMIT: 'The document exceeded parser limits. Coverage was not established.',
}

function record(value: unknown): value is Record<string, unknown> { return typeof value === 'object' && value !== null && !Array.isArray(value) }
function strings(value: unknown): value is string[] { return Array.isArray(value) && value.every(item => typeof item === 'string') }
function counts(value: unknown): boolean { return record(value) && Object.values(value).every(n => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0) }
function count(value: unknown): boolean { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 }

function surface(value: unknown): boolean {
  if (!record(value) || !['id', 'kind', 'text', 'candidate', 'status'].every(key => typeof value[key] === 'string') ||
      !record(value.location) || !counts(value.residual_families) || !count(value.known_values_remaining) || !Array.isArray(value.matches)) return false
  // Offsets are Unicode code points, not UTF-16 units. Count once for the whole
  // surface, without allocating a second copy for each of potentially 20k spans.
  let length = 0
  for (const _ of value.text as string) length++
  return value.matches.every(match => record(match) && ['kind', 'basis', 'replacement'].every(key => typeof match[key] === 'string') &&
    Number.isSafeInteger(match.start) && Number.isSafeInteger(match.end) && (match.start as number) >= 0 &&
    (match.end as number) > (match.start as number) && (match.end as number) <= length)
}

export function parseDocumentReview(value: unknown): DocumentReview {
  if (!record(value) || value.schema !== 'document-review-v1' || value.posture !== 'REVIEW_REQUIRED' || value.release_eligible !== false ||
    typeof value.name !== 'string' || typeof value.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.sha256) || typeof value.format !== 'string' ||
    !strings(value.gaps) || !strings(value.limitations) || !record(value.summary) || !counts(value.summary.findings) ||
    !['surfaces', 'nonempty_surfaces', 'pages', 'matches', 'residual_units', 'known_values_remaining'].every(key => count((value.summary as Record<string, unknown>)[key])) ||
    !record(value.coverage) || value.coverage.text !== 'PARSED_WITH_GAPS' || value.coverage.names_addresses !== 'UNQUALIFIED' || value.coverage.pixels !== 'UNMEASURED' || value.coverage.original_format_output !== 'NOT_PRODUCED' ||
    !Array.isArray(value.inventory) || !value.inventory.every(item => record(item) && ['id', 'kind', 'status'].every(key => typeof item[key] === 'string')) ||
    !Array.isArray(value.surfaces) || !value.surfaces.every(surface)) {
    throw new Error('The server returned an invalid review. No coverage result is available.')
  }
  return value as DocumentReview
}

export async function inspectDocument(base: string, token: string, file: File, names: string[], signal: AbortSignal): Promise<DocumentReview> {
  if (!/\.(pdf|docx|pptx|xlsx)$/i.test(file.name)) throw new Error(ERROR_MESSAGES.UNSUPPORTED_FORMAT)
  if (file.size > DOCUMENT_MAX_BYTES || file.size === 0) throw new Error(ERROR_MESSAGES.FILE_LIMIT)
  if (names.length > 100 || names.some(name => name.length < 2 || name.length > 150)) throw new Error('Enter up to 100 corrections, each 2–150 characters.')
  const bytes = new Uint8Array(await file.arrayBuffer())
  if (signal.aborted) throw new DOMException('Cancelled', 'AbortError')
  let binary = ''
  for (let offset = 0; offset < bytes.length; offset += 8192) binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192))
  let response: Response
  try { response = await fetch(`${base.replace(/\/$/, '')}/development/documents/review`, {
    method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token.trim()}` },
    cache: 'no-store', credentials: 'omit', redirect: 'error',
    body: JSON.stringify({ name: file.name, content_base64: btoa(binary), review_only: true, ocr: true,
      reviewed_values: names.map(value => ({ value, kind: 'OTHER_SENSITIVE' })) }), signal: AbortSignal.any([signal, AbortSignal.timeout(200_000)]),
  }) } catch {
    if (signal.aborted) throw new DOMException('Cancelled', 'AbortError')
    throw new Error('Cannot reach the document review API, or the request timed out. No coverage result is available.')
  }
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null)
    const message = response.status === 401 || response.status === 403 ? 'Enter an authorized processor token.' :
      response.status === 404 ? 'Document review is unavailable. Enable the local development demo.' :
      record(body) && typeof body.code === 'string' ? ERROR_MESSAGES[body.code] : undefined
    throw new Error(message || 'Document review failed. No coverage result is available.')
  }
  return parseDocumentReview(await response.json())
}
