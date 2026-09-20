export type Mode = 'external_anonymized' | 'restricted_pseudonymized'
export type SourceFormat = 'text' | 'json' | 'jsonl' | 'csv'
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
const DIGEST = /^sha256:[0-9a-f]{64}$/
const LABEL = /^[a-z0-9][a-z0-9._:-]{0,127}$/
const ISO_TIME = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/

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
    if (!object(entry) || Object.keys(entry).length !== 4 || !nonEmpty(entry.entity_type) || !nonEmpty(entry.action) || !nonEmpty(entry.reason) ||
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
      if (!object(rights) || !safeControlId(rights.id) || rights.profile_id !== 'workbench-rights' || rights.version !== 'v1' || !DIGEST.test(String(rights.digest)) ||
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
