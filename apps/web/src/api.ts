export type Mode = 'external_anonymized' | 'restricted_pseudonymized'
export type ReleaseView = {
  id: string; dataset_id: string; status: string;
  eligibility: 'BLOCKED' | 'REVIEW_REQUIRED'; output: null;
  card: { release_id: string; dataset_id: string; eligibility: 'BLOCKED' | 'REVIEW_REQUIRED'; policy_version: string; release_mode: Mode; evidence_status: 'INSUFFICIENT_EVIDENCE'; scores: null;
    findings: { entity_type: string; severity: string; count: number }[]; gates: string[]; limitations: string[] }
}
type Request = { apiBase: string; token: string; content: string; mode: Mode; recipient: string; signal?: AbortSignal }
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
      const dataset = await post(apiBase, '/datasets', token, { name: 'synthetic-workbench', content, owner: 'development', jurisdiction: 'unspecified', intended_use: 'synthetic-evaluation-only', recipient: recipient.trim(), retention_days: 1 }, signal)
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
