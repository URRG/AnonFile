import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { requestRelease, validateRelease, runControlPlane, ControlPlaneFailure, DEFAULT_POLICY_NOTICE, REQUEST_TIMEOUT_MS } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
const request = { apiBase: 'http://localhost:8000', token: 'test-token', content: 'synthetic', recipient: 'buyer-test', mode: 'external_anonymized' }
const safe = () => ({ id: 'release-1', dataset_id: 'dataset-1', status: 'evaluation_incomplete', eligibility: 'REVIEW_REQUIRED', output: null, card: { release_id: 'release-1', dataset_id: 'dataset-1', eligibility: 'REVIEW_REQUIRED', policy_version: 'external-release-v1', release_mode: 'external_anonymized', evidence_status: 'INSUFFICIENT_EVIDENCE', scores: null, findings: [], gates: ['EXPORT_DISABLED', 'QUALIFICATION_REQUIRED'], limitations: ['rules-only'] } })
for (const status of [401, 403, 409, 413, 422, 429, 500, 503]) {
  test(`HTTP ${status} never becomes a local successful release`, async t => {
    const mock = t.mock.method(globalThis, 'fetch', async () => new Response('raw-password-DO-NOT-ECHO', { status }))
    await assert.rejects(requestRelease(request), error => !error.message.includes('raw-password') && error.message.includes('No release'))
    assert.equal(mock.mock.calls.length, 1)
  })
}
test('network error has no fallback and does not expose cause', async t => {
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('raw-secret') })
  await assert.rejects(requestRelease(request), /Cannot reach the API\. No local fallback/)
})
test('authenticated metadata-only path binds recipient, dataset, mode and policy', async t => {
  let calls = 0
  const mock = t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.headers.Authorization, 'Bearer test-token')
    assert.equal(options.redirect, 'error'); assert.equal(options.credentials, 'omit')
    return Response.json(++calls === 1 ? { id: 'dataset-1' } : safe())
  })
  assert.equal((await requestRelease(request)).output, null)
  assert.equal(mock.mock.calls.length, 2)
  assert.equal(JSON.parse(mock.mock.calls[0].arguments[1].body).recipient, 'buyer-test')
})
test('release failure after intake is still failure', async t => {
  let calls = 0
  t.mock.method(globalThis, 'fetch', async () => ++calls === 1 ? Response.json({ id: 'dataset-1' }) : new Response('secret', { status: 500 }))
  await assert.rejects(requestRelease(request), /No release was authorized/)
})

for (const format of ['text', 'json', 'jsonl', 'csv']) {
  test(`source format ${format} uses strict server intake`, async t => {
    let count = 0
    const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(++count === 1 ? { id: 'dataset-1' } : safe()))
    await requestRelease({ ...request, format })
    assert.equal(mock.mock.calls[0].arguments[0], 'http://localhost:8000/ingestions')
    assert.equal(JSON.parse(mock.mock.calls[0].arguments[1].body).format, format)
  })
}

test('unknown source format never reaches transport', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not run') })
  await assert.rejects(requestRelease({ ...request, format: 'xml' }), /Unsupported source format/)
  assert.equal(mock.mock.calls.length, 0)
})
test('unsafe response fields rejected', () => {
  for (const change of [x => x.output = 'secret', x => delete x.output, x => x.eligibility = 'APPROVED_ANONYMIZED', x => x.card.scores = { privacy: 99 }, x => x.card.evidence_status = 'PASSED', x => x.card.findings = [{ count: -1 }]]) {
    const value = safe(); change(value); assert.throws(() => validateRelease(value), /unsafe response/)
  }
})
test('response for a different dataset is rejected', async t => {
  let calls = 0
  t.mock.method(globalThis, 'fetch', async () => Response.json(++calls === 1 ? { id: 'different' } : safe()))
  await assert.rejects(requestRelease(request), /unsafe response/)
})
test('missing token and oversized UTF-8 input never reach API', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not run') })
  await assert.rejects(requestRelease({ ...request, token: '' }), /required/)
  await assert.rejects(requestRelease({ ...request, content: '😀'.repeat(500001) }), /limit/)
  assert.equal(mock.mock.calls.length, 0)
})
test('malformed JSON produces fixed error', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response('raw-secret', { status: 200 }))
  await assert.rejects(requestRelease(request), error => !error.message.includes('raw-secret') && error.message.includes('unsafe response'))
})
test('UI has no credential persistence, clipboard export or demo fallback', () => {
  const ui = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8')
  assert.doesNotMatch(ui, /localStorage|sessionStorage|clipboard|demoRelease/)
  assert.match(ui, /Synthetic data only/)
  assert.match(ui, /Do not submit customer data/)
  assert.match(ui, /accepts and temporarily stores submitted text/)
  assert.doesNotMatch(ui, /Customer data admission.*disabled/)
})

function shortenDeadline(t) {
  const original = globalThis.setTimeout
  const delays = []
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => {
    delays.push(delay)
    return original(callback, 20, ...args)
  })
  return delays
}

for (const phase of ['intake headers', 'intake body', 'release body']) {
  test(`one workflow deadline covers stalled ${phase}`, { timeout: 2000 }, async t => {
    const delays = shortenDeadline(t)
    const cleanup = t.mock.method(globalThis, 'clearTimeout')
    let calls = 0, transportSignal
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
      calls++; transportSignal = options.signal
      if (phase === 'intake headers') return new Promise(() => {})
      if (phase === 'release body' && calls === 1) return Response.json({ id: 'dataset-1' })
      return new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('{')) } }))
    })
    await assert.rejects(requestRelease(request), /Request timed out after 30 seconds.*does not undo/)
    assert.equal(REQUEST_TIMEOUT_MS, 30000)
    assert.deepEqual(delays, [30000], 'one deadline shared by both requests, not reset per POST')
    assert.equal(transportSignal.aborted, true)
    assert.equal(calls, phase === 'release body' ? 2 : 1)
    assert.equal(cleanup.mock.calls.length, 1)
  })
}

test('already cancelled request sends no source to the API', async t => {
  const controller = new AbortController()
  controller.abort('raw-secret-reason')
  const fetch = t.mock.method(globalThis, 'fetch', async () => Response.json({ id: 'dataset-1' }))
  await assert.rejects(requestRelease({ ...request, signal: controller.signal }), error => error.message.startsWith('Request cancelled.') && !error.message.includes('raw-secret'))
  assert.equal(fetch.mock.calls.length, 0)
})

for (const phase of ['headers', 'body']) {
  test(`cancel interrupts stalled ${phase} even if transport ignores abort`, { timeout: 2000 }, async t => {
    const controller = new AbortController()
    let transportSignal, start
    const started = new Promise(resolve => { start = resolve })
    const cleanup = t.mock.method(globalThis, 'clearTimeout')
    const remove = t.mock.method(controller.signal, 'removeEventListener')
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
      transportSignal = options.signal
      if (phase === 'headers') { start(); return new Promise(() => {}) }
      return { ok: true, json: () => { start(); return new Promise(() => {}) } }
    })
    const result = requestRelease({ ...request, signal: controller.signal })
    await started
    controller.abort('raw-secret-reason')
    await assert.rejects(result, error => error.message.startsWith('Request cancelled.') && !error.message.includes('raw-secret'))
    assert.equal(transportSignal.aborted, true)
    assert.equal(cleanup.mock.calls.length, 1)
    assert.equal(remove.mock.calls.length, 1)
  })
}

test('late intake response after cancellation cannot start release POST', async t => {
  const controller = new AbortController()
  let respond, start
  const started = new Promise(resolve => { start = resolve })
  const fetch = t.mock.method(globalThis, 'fetch', () => new Promise(resolve => { respond = resolve; start() }))
  const result = requestRelease({ ...request, signal: controller.signal })
  await started
  controller.abort()
  await assert.rejects(result, /Request cancelled/)
  respond(Response.json({ id: 'dataset-1' }))
  await new Promise(resolve => setImmediate(resolve))
  assert.equal(fetch.mock.calls.length, 1)
})

test('successful workflow cleans deadline and external abort listener', async t => {
  const controller = new AbortController()
  const cleanup = t.mock.method(globalThis, 'clearTimeout')
  const remove = t.mock.method(controller.signal, 'removeEventListener')
  let calls = 0
  t.mock.method(globalThis, 'fetch', async () => Response.json(++calls === 1 ? { id: 'dataset-1' } : safe()))
  assert.equal((await requestRelease({ ...request, signal: controller.signal })).output, null)
  assert.equal(cleanup.mock.calls.length, 1)
  assert.equal(remove.mock.calls.length, 1)
})

test('UI wires cancellation outside the disabled fieldset and guards late state', () => {
  const ui = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8')
  assert.match(ui, /<\/fieldset>\s*\{busy && <p><button type="button" onClick=\{\(\) => activeRequest\.current\?\.abort\(\)\}>Cancel request/)
  assert.match(ui, /signal: controller\.signal/)
  assert.match(ui, /if \(activeRequest\.current\) return/)
  assert.match(ui, /activeRequest\.current === controller && !controller\.signal\.aborted/)
  assert.match(ui, /activeRequest\.current = null; setBusy\(false\)/)
  assert.match(ui, /useEffect\(\(\) => \(\) =>/)
})
test('card identity, eligibility and required gates must match safe envelope', () => {
  for (const change of [x => x.card.release_id = 'foreign', x => x.card.dataset_id = 'foreign', x => x.card.eligibility = 'APPROVED_ANONYMIZED', x => x.card.eligibility = 'BLOCKED', x => x.card.gates = [], x => x.status = 'approved', x => x.eligibility = ['REVIEW_REQUIRED'], x => x.card.release_mode = ['external_anonymized']]) {
    const value = safe(); change(value); assert.throws(() => validateRelease(value), /unsafe response/)
  }
})

const controlRequest = { apiBase: 'http://localhost:8000', token: 'test-token', content: 'synthetic', recipient: 'buyer-test', purpose: 'ai-training-resale', mode: 'external_anonymized' }
const digest = char => `sha256:${char.repeat(64)}`
const controlRun = (state, candidate = null) => ({
  id: 'run-1', dataset_id: 'dataset-1', state, attempts: state === 'REGISTERED' ? 0 : 1,
  request_digest: digest('c'), method_id: 'rules-v1', language: 'en', policy_digest: digest('d'), rights_digest: digest('e'),
  recipient: 'buyer-test', purpose: 'ai-training-resale', candidate,
  events: [{ sequence: 1, state: state === 'REGISTERED' ? 'REGISTERED' : state, action: state === 'REGISTERED' ? 'REGISTERED' : 'QUARANTINED', occurred_at: '2026-09-20T00:00:00Z', attempt: state === 'REGISTERED' ? 0 : 1 }],
})
const safeCandidate = () => ({ artifact_digest: digest('a'), schema_digest: digest('b'), payload_kind: 'text', media_type: 'text/plain', byte_count: 12, ledger: [{ entity_type: 'PII', action: 'REDACT', reason: 'POLICY_RULE', count: 1 }] })
const controlResponses = (state = 'QUARANTINED', candidate = safeCandidate()) => [
  { id: 'dataset-1' },
  { id: 'rights-1', profile_id: 'workbench-rights', version: 'v1', digest: digest('e'), expires_at: '2026-09-20T01:00:00Z', resale_allowed: true, permitted_purposes: ['ai-training-resale'], permitted_recipients: ['buyer-test'] },
  { id: 'policy-1', key: 'workbench-baseline::v1', digest: digest('d'), formats: ['csv', 'json', 'jsonl', 'text'], languages: ['en', 'und'], release_modes: ['external_anonymized', 'restricted_pseudonymized'] },
  controlRun('REGISTERED'), controlRun(state, candidate),
]

test('M6 control plane uses five strict metadata-only requests and never calls legacy releases', async t => {
  const payloads = []
  let index = 0
  const mock = t.mock.method(globalThis, 'fetch', async (url, options) => {
    payloads.push({ url, options, body: JSON.parse(options.body) })
    return Response.json(controlResponses()[index++])
  })
  const view = await runControlPlane(controlRequest)
  assert.equal(view.state, 'QUARANTINED')
  assert.equal(view.candidate?.artifactDigest, digest('a'))
  assert.equal(view.message, DEFAULT_POLICY_NOTICE)
  assert.deepEqual(payloads.map(call => call.url), [
    'http://localhost:8000/ingestions', 'http://localhost:8000/rights-profiles', 'http://localhost:8000/policy-snapshots',
    'http://localhost:8000/processing-runs', 'http://localhost:8000/processing-runs/run-1/execute',
  ])
  assert.equal(mock.mock.calls.length, 5)
  assert.equal(payloads.some(call => call.url.includes('/releases')), false)
  assert.equal(payloads[3].options.headers['Idempotency-Key'].length > 0, true)
  assert.equal(payloads[4].body && Object.keys(payloads[4].body).length, 0)
  assert.deepEqual(payloads[2].body.rules.map(rule => rule.category), ['CREDENTIAL', 'PAYMENT', 'HEALTH_SENSITIVE', 'PII', 'BUSINESS_CONFIDENTIAL', 'QUASI_IDENTIFIER'])
  assert.equal(payloads[1].body.permitted_purposes[0], 'ai-training-resale')
  assert.equal(payloads[1].body.permitted_recipients[0], 'buyer-test')
})

test('M6 refuses an API candidate body and does not return it', async t => {
  let index = 0
  t.mock.method(globalThis, 'fetch', async () => Response.json(controlResponses('CANDIDATE', { ...safeCandidate(), body: 'raw-secret' })[index++]))
  await assert.rejects(runControlPlane(controlRequest), error => error instanceof ControlPlaneFailure && !error.message.includes('raw-secret') && error.message.includes('invalid control-plane'))
})

test('M6 validates recipient and purpose labels before sending source', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not run') })
  await assert.rejects(runControlPlane({ ...controlRequest, recipient: 'OpenAI' }), /lowercase control-plane labels/)
  await assert.rejects(runControlPlane({ ...controlRequest, purpose: 'AI training' }), /lowercase control-plane labels/)
  assert.equal(mock.mock.calls.length, 0)
})

test('M6 transport failures never echo a response body or create a fallback', async t => {
  let index = 0
  t.mock.method(globalThis, 'fetch', async () => index++ === 0 ? Response.json(controlResponses()[0]) : new Response('raw-secret', { status: 500 }))
  await assert.rejects(runControlPlane(controlRequest), error => error instanceof ControlPlaneFailure && !error.message.includes('raw-secret') && error.message.includes('No candidate body'))
})

test('M6 cancellation stops client progression before rights or policy requests', async t => {
  const controller = new AbortController()
  let begin
  const started = new Promise(resolve => { begin = resolve })
  const mock = t.mock.method(globalThis, 'fetch', async () => {
    begin()
    return new Promise(() => {})
  })
  const result = runControlPlane({ ...controlRequest, signal: controller.signal })
  await started
  controller.abort('raw-secret-reason')
  await assert.rejects(result, error => error instanceof ControlPlaneFailure && error.message.startsWith('Request cancelled.') && !error.message.includes('raw-secret'))
  assert.equal(mock.mock.calls.length, 1)
})
