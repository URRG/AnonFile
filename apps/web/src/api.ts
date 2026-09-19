export type Mode = 'external_anonymized' | 'restricted_pseudonymized'
export type ReleaseView = {
  id: string; dataset_id: string; status: string;
  eligibility: 'BLOCKED' | 'REVIEW_REQUIRED'; output: null;
  card: { policy_version: string; release_mode: Mode; evidence_status: 'INSUFFICIENT_EVIDENCE'; scores: null;
    findings: { entity_type: string; severity: string; count: number }[]; gates: string[]; limitations: string[] }
}
type Request = { apiBase: string; token: string; content: string; mode: Mode; recipient: string; signal?: AbortSignal }
const object = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)
const strings = (v: unknown): v is string[] => Array.isArray(v) && v.every(x => typeof x === 'string')
const invalid = () => new Error('The API returned an invalid or unsafe response. No release was authorized.')
export function validateRelease(value: unknown): ReleaseView {
  if (!object(value) || typeof value.id !== 'string' || typeof value.dataset_id !== 'string' || typeof value.status !== 'string' ||
      value.output !== null || !['BLOCKED', 'REVIEW_REQUIRED'].includes(String(value.eligibility)) || !object(value.card)) throw invalid()
  const card = value.card
  if (card.evidence_status !== 'INSUFFICIENT_EVIDENCE' || card.scores !== null || typeof card.policy_version !== 'string' ||
      !['external_anonymized', 'restricted_pseudonymized'].includes(String(card.release_mode)) || !strings(card.gates) || !strings(card.limitations) ||
      !Array.isArray(card.findings) || !card.findings.every(f => object(f) && typeof f.entity_type === 'string' && typeof f.severity === 'string' && typeof f.count === 'number' && Number.isSafeInteger(f.count) && f.count >= 0)) throw invalid()
  return value as ReleaseView
}
async function post(base: string, path: string, token: string, body: unknown, signal?: AbortSignal): Promise<unknown> {
  let response: Response
  try { response = await fetch(base.replace(/\/$/, '') + path, {
    method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store', signal,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` }, body: JSON.stringify(body),
  }) } catch { throw new Error('Cannot reach the API. No local fallback or release was produced.') }
  if (!response.ok) {
    const messages: Record<number, string> = { 401: 'Authentication required.', 403: 'This action is not permitted.', 409: 'The request conflicts with release controls.', 413: 'Input exceeds the processing limit.', 422: 'The request did not pass validation.', 429: 'Development capacity reached.', 503: 'The development service is not configured or is unavailable.' }
    throw new Error((messages[response.status] || 'The API request failed.') + ' No release was authorized.')
  }
  try { return await response.json() } catch { throw invalid() }
}
export async function requestRelease(request: Request): Promise<ReleaseView> {
  const { apiBase, content, mode, recipient, signal } = request
  const token = request.token.trim()
  if (!token || !content.trim() || !recipient.trim() || !['external_anonymized', 'restricted_pseudonymized'].includes(mode)) throw new Error('A token, synthetic input, recipient and valid mode are required.')
  if (new TextEncoder().encode(content).length > 2_000_000) throw new Error('Input exceeds the processing limit. No release was authorized.')
  const policy = mode === 'external_anonymized' ? 'external-release-v1' : 'restricted-pseudonymized-v1'
  const dataset = await post(apiBase, '/datasets', token, { name: 'synthetic-workbench', content, owner: 'development', jurisdiction: 'unspecified', intended_use: 'synthetic-evaluation-only', recipient: recipient.trim(), retention_days: 1 }, signal)
  if (!object(dataset) || typeof dataset.id !== 'string') throw invalid()
  const release = validateRelease(await post(apiBase, '/releases', token, { dataset_id: dataset.id, release_mode: mode, policy_version: policy, allow_review: true }, signal))
  if (release.dataset_id !== dataset.id || release.card.release_mode !== mode || release.card.policy_version !== policy) throw invalid()
  return release
}
