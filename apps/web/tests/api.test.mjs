import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')
const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { requestRelease, validateRelease, runControlPlane, ControlPlaneFailure, DEFAULT_POLICY_NOTICE, REQUEST_TIMEOUT_MS, decodeDemoUpload, inspectSyntheticDemo, DemoInspectionFailure, DEMO_MAX_BYTES, getRecordedGraphReview, decideRecordedGraphClaim, mergeRecordedGraphIdentities, resolveRecordedGraphConflict, splitRecordedGraphIdentity, GraphReviewFailure } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
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

const opaque = prefix => `${prefix}:v1:${'A'.repeat(43)}`
const recordedGraph = { nodes: [{ id: 'person_1', kind: 'person', label: 'Person A', documentIds: ['document_1'] }, { id: 'organization_1', kind: 'organization', label: 'Organization A', documentIds: ['document_1'] }], edges: [{ id: 'edge_1', type: 'works_at', sourceId: 'person_1', targetId: 'organization_1', evidence: [] }] }
const recordedBinding = { snapshotRef: opaque('graphsnap'), nodes: [{ graphNodeId: 'person_1', nodeRef: opaque('graphnode') }, { graphNodeId: 'organization_1', nodeRef: `${opaque('graphnode').slice(0, -1)}B` }], claims: [{ graphEdgeId: 'edge_1', claimRef: opaque('graphclaim') }], posture: 'DEVELOPMENT_BINDING_ONLY_NO_ADJUDICATION_OR_RELEASE' }
const recordedPayload = revision => ({ snapshot_ref: recordedBinding.snapshotRef, revision, nodes: [{ id: recordedBinding.nodes[0].nodeRef, kind: 'person' }, { id: recordedBinding.nodes[1].nodeRef, kind: 'organization' }], claims: [{ id: recordedBinding.claims[0].claimRef, relation: 'works_at', source: recordedBinding.nodes[0].nodeRef, target: recordedBinding.nodes[1].nodeRef }], decisions: [], identity_actions: [], conflicts: [], conflict_groups: [], posture: 'REVIEW_ONLY_NO_RELEASE_OR_DELIVERY' })

test('recorded graph review uses authenticated no-store GET and binds opaque objects to this graph only', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async (_url, options) => { assert.equal(options.method, 'GET'); assert.equal(options.headers.Authorization, 'Bearer reviewer-secret'); assert.equal(options.credentials, 'omit'); assert.equal(options.cache, 'no-store'); return Response.json(recordedPayload(0)) })
  const view = await getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph })
  assert.equal(view.revision, 0); assert.equal(view.decisions.length, 0); assert.equal(mock.mock.calls.length, 1)
})

test('recorded review maps all authorization and revision errors to source-safe failures', async t => {
  for (const status of [401, 403, 404, 409]) {
    t.mock.method(globalThis, 'fetch', async () => new Response('do-not-echo-secret', { status }))
    await assert.rejects(getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph }), error => error instanceof GraphReviewFailure && !error.message.includes('do-not-echo-secret'))
    t.mock.restoreAll()
  }
})

test('recorded decision posts only bound claim and expected revision', async t => {
  let received
  t.mock.method(globalThis, 'fetch', async (_url, options) => { received = JSON.parse(options.body); return Response.json({ ...recordedPayload(1), decisions: [{ claim_ref: recordedBinding.claims[0].claimRef, decision: 'ACCEPT' }] }) })
  const view = await decideRecordedGraphClaim({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph, claimRef: recordedBinding.claims[0].claimRef, decision: 'ACCEPT', expectedRevision: 0 })
  assert.deepEqual(received, { claim_ref: recordedBinding.claims[0].claimRef, decision: 'ACCEPT', expected_revision: 0 }); assert.deepEqual(view.decisions, [{ claimRef: recordedBinding.claims[0].claimRef, decision: 'ACCEPT' }])
})

test('recorded review rejects schema-valid inconsistent revision, action cap, and conflicts', async t => {
  const invalid = [
    () => ({ ...recordedPayload(1) }),
    () => ({ ...recordedPayload(2), decisions: [{ claim_ref: recordedBinding.claims[0].claimRef, decision: 'REJECT' }, { claim_ref: recordedBinding.claims[0].claimRef, decision: 'REJECT' }] }),
    () => ({ ...recordedPayload(0), conflicts: [{ kind: 'POTENTIAL_MULTIPLE_WORKS_AT', subjects: 1, relationships: 2 }] }),
    () => ({ ...recordedPayload(201), identity_actions: Array.from({ length: 201 }, () => ({ action: 'MERGE', canonical: recordedBinding.nodes[0].nodeRef, members: [recordedBinding.nodes[0].nodeRef, recordedBinding.nodes[0].nodeRef] })) }),
  ]
  for (const makePayload of invalid) {
    t.mock.method(globalThis, 'fetch', async () => Response.json(makePayload()))
    await assert.rejects(getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph }), GraphReviewFailure)
    t.mock.restoreAll()
  }
})

test('recorded review accepts only exact source-free conflict groups bound to accepted claims', async t => {
  const orgTwo = `${opaque('graphnode').slice(0, -1)}C`, claimTwo = `${opaque('graphclaim').slice(0, -1)}B`
  const graph = { nodes: [...recordedGraph.nodes, { id: 'organization_2', kind: 'organization', label: 'Organization B', documentIds: [] }], edges: [...recordedGraph.edges, { id: 'edge_2', type: 'works_at', sourceId: 'person_1', targetId: 'organization_2', evidence: [] }] }
  const binding = { ...recordedBinding, nodes: [...recordedBinding.nodes, { graphNodeId: 'organization_2', nodeRef: orgTwo }], claims: [...recordedBinding.claims, { graphEdgeId: 'edge_2', claimRef: claimTwo }] }
  const base = { ...recordedPayload(2), nodes: [...recordedPayload(2).nodes, { id: orgTwo, kind: 'organization' }], claims: [...recordedPayload(2).claims, { id: claimTwo, relation: 'works_at', source: recordedBinding.nodes[0].nodeRef, target: orgTwo }], decisions: [{ claim_ref: recordedBinding.claims[0].claimRef, decision: 'ACCEPT' }, { claim_ref: claimTwo, decision: 'ACCEPT' }], conflicts: [{ kind: 'POTENTIAL_MULTIPLE_WORKS_AT', subjects: 1, relationships: 2 }], conflict_groups: [{ kind: 'POTENTIAL_MULTIPLE_WORKS_AT', subject_ref: recordedBinding.nodes[0].nodeRef, claim_refs: [recordedBinding.claims[0].claimRef, claimTwo] }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(base))
  const view = await getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph })
  assert.deepEqual(view.conflictGroups[0].claimRefs, [recordedBinding.claims[0].claimRef, claimTwo]); t.mock.restoreAll()
  t.mock.method(globalThis, 'fetch', async () => Response.json({ ...base, conflict_groups: [] }))
  await assert.rejects(getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph }), GraphReviewFailure)
})

test('recorded conflict resolution counts its durable action, replays, and fails closed when the live group changes', async t => {
  const orgTwo = `${opaque('graphnode').slice(0, -1)}C`, claimTwo = `${opaque('graphclaim').slice(0, -1)}B`
  const graph = { nodes: [...recordedGraph.nodes, { id: 'organization_2', kind: 'organization', label: 'Organization B', documentIds: [] }], edges: [...recordedGraph.edges, { id: 'edge_2', type: 'works_at', sourceId: 'person_1', targetId: 'organization_2', evidence: [] }] }
  const binding = { ...recordedBinding, nodes: [...recordedBinding.nodes, { graphNodeId: 'organization_2', nodeRef: orgTwo }], claims: [...recordedBinding.claims, { graphEdgeId: 'edge_2', claimRef: claimTwo }] }
  const group = { kind: 'POTENTIAL_MULTIPLE_WORKS_AT', subject_ref: recordedBinding.nodes[0].nodeRef, claim_refs: [recordedBinding.claims[0].claimRef, claimTwo] }
  const resolved = { ...recordedPayload(3), nodes: [...recordedPayload(3).nodes, { id: orgTwo, kind: 'organization' }], claims: [...recordedPayload(3).claims, { id: claimTwo, relation: 'works_at', source: recordedBinding.nodes[0].nodeRef, target: orgTwo }], decisions: [{ claim_ref: recordedBinding.claims[0].claimRef, decision: 'ACCEPT' }, { claim_ref: claimTwo, decision: 'ACCEPT' }], conflicts: [{ kind: group.kind, subjects: 1, relationships: 2 }], conflict_groups: [group], conflict_resolutions: [{ ...group, status: 'RESOLVED' }], conflict_resolution_actions: [{ ...group, disposition: 'RETAIN_ALL' }] }
  let received
  t.mock.method(globalThis, 'fetch', async (_url, options) => { received = JSON.parse(options.body); return Response.json(resolved) })
  const view = await resolveRecordedGraphConflict({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph, group: { kind: group.kind, subjectRef: group.subject_ref, claimRefs: group.claim_refs }, expectedRevision: 2 })
  assert.deepEqual(received, { kind: group.kind, subject_ref: group.subject_ref, claim_refs: group.claim_refs, disposition: 'RETAIN_ALL', expected_revision: 2 })
  assert.equal(view.revision, 3); assert.equal(view.conflictResolutionActions.length, 1)
  t.mock.restoreAll(); t.mock.method(globalThis, 'fetch', async () => Response.json(resolved))
  assert.equal((await getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph })).conflictResolutions[0].status, 'RESOLVED')
  t.mock.restoreAll(); t.mock.method(globalThis, 'fetch', async () => Response.json({ ...resolved, conflict_groups: [] }))
  await assert.rejects(getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph }), GraphReviewFailure)
})

test('recorded client accepts a retained resolution after a later split removes its live group', async t => {
  const secondPerson = `${opaque('graphnode').slice(0, -1)}C`, thirdPerson = `${opaque('graphnode').slice(0, -1)}D`, orgTwo = `${opaque('graphnode').slice(0, -1)}E`, claimTwo = `${opaque('graphclaim').slice(0, -1)}B`
  const graph = { nodes: [...recordedGraph.nodes, { id: 'person_2', kind: 'person', label: 'Person B', documentIds: [] }, { id: 'person_3', kind: 'person', label: 'Person C', documentIds: [] }, { id: 'organization_2', kind: 'organization', label: 'Organization B', documentIds: [] }], edges: [...recordedGraph.edges, { id: 'edge_2', type: 'works_at', sourceId: 'person_1', targetId: 'organization_2', evidence: [] }] }
  const binding = { ...recordedBinding, nodes: [...recordedBinding.nodes, { graphNodeId: 'person_2', nodeRef: secondPerson }, { graphNodeId: 'person_3', nodeRef: thirdPerson }, { graphNodeId: 'organization_2', nodeRef: orgTwo }], claims: [...recordedBinding.claims, { graphEdgeId: 'edge_2', claimRef: claimTwo }] }
  const historical = { kind: 'POTENTIAL_MULTIPLE_WORKS_AT', subject_ref: recordedBinding.nodes[0].nodeRef, claim_refs: [recordedBinding.claims[0].claimRef, claimTwo] }
  const response = { ...recordedPayload(4), nodes: [...recordedPayload(4).nodes, { id: secondPerson, kind: 'person' }, { id: thirdPerson, kind: 'person' }, { id: orgTwo, kind: 'organization' }], claims: [...recordedPayload(4).claims, { id: claimTwo, relation: 'works_at', source: recordedBinding.nodes[0].nodeRef, target: orgTwo }], decisions: [{ claim_ref: recordedBinding.claims[0].claimRef, decision: 'ACCEPT' }, { claim_ref: claimTwo, decision: 'ACCEPT' }], identity_actions: [{ action: 'SPLIT', source: recordedBinding.nodes[0].nodeRef, replacements: [secondPerson, thirdPerson], assignments: [{ claim_ref: recordedBinding.claims[0].claimRef, endpoint: 'source', replacement: secondPerson }, { claim_ref: claimTwo, endpoint: 'source', replacement: thirdPerson }] }], conflicts: [], conflict_groups: [], conflict_resolutions: [], conflict_resolution_actions: [{ ...historical, disposition: 'RETAIN_ALL' }] }
  t.mock.method(globalThis, 'fetch', async () => Response.json(response))
  const view = await getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph })
  assert.equal(view.revision, 4); assert.deepEqual(view.conflictGroups, []); assert.deepEqual(view.conflictResolutions, []); assert.equal(view.conflictResolutionActions.length, 1)
})

test('recorded split parser tolerates unavailable decision/action chronology without accepting extra endpoints', async t => {
  const sourceRef = recordedBinding.nodes[0].nodeRef, firstRef = `${opaque('graphnode').slice(0, -1)}C`, secondRef = `${opaque('graphnode').slice(0, -1)}D`
  const graph = { nodes: [{ id: 'person_1', kind: 'person', label: 'Person A', documentIds: [] }, { id: 'person_2', kind: 'person', label: 'Person B', documentIds: [] }, { id: 'person_3', kind: 'person', label: 'Person C', documentIds: [] }, { id: 'organization_1', kind: 'organization', label: 'Organization A', documentIds: [] }], edges: [{ id: 'edge_1', type: 'works_at', sourceId: 'person_1', targetId: 'organization_1', evidence: [] }] }
  const binding = { snapshotRef: recordedBinding.snapshotRef, nodes: [{ graphNodeId: 'person_1', nodeRef: sourceRef }, { graphNodeId: 'person_2', nodeRef: firstRef }, { graphNodeId: 'person_3', nodeRef: secondRef }, recordedBinding.nodes[1]], claims: recordedBinding.claims, posture: recordedBinding.posture }
  const response = assignments => ({ snapshot_ref: binding.snapshotRef, revision: 2, nodes: [{ id: sourceRef, kind: 'person' }, { id: firstRef, kind: 'person' }, { id: secondRef, kind: 'person' }, { id: recordedBinding.nodes[1].nodeRef, kind: 'organization' }], claims: [{ id: recordedBinding.claims[0].claimRef, relation: 'works_at', source: sourceRef, target: recordedBinding.nodes[1].nodeRef }], decisions: [{ claim_ref: recordedBinding.claims[0].claimRef, decision: 'REJECT' }], identity_actions: [{ action: 'SPLIT', source: sourceRef, replacements: [firstRef, secondRef], assignments }], conflicts: [], conflict_groups: [], posture: 'REVIEW_ONLY_NO_RELEASE_OR_DELIVERY' })
  // The public view omits audit ordering. These are respectively the
  // split-then-reject and reject-then-split shapes; both must parse safely.
  for (const assignments of [[{ claim_ref: recordedBinding.claims[0].claimRef, endpoint: 'source', replacement: firstRef }], []]) {
    t.mock.method(globalThis, 'fetch', async () => Response.json(response(assignments)))
    const view = await getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph })
    assert.equal(view.identityActions[0].action, 'SPLIT'); t.mock.restoreAll()
  }
  const fabricated = response([{ claim_ref: recordedBinding.claims[0].claimRef, endpoint: 'target', replacement: firstRef }])
  t.mock.method(globalThis, 'fetch', async () => Response.json(fabricated))
  await assert.rejects(getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph }), GraphReviewFailure)
})

test('recorded identity actions post only bound opaque refs and reject malformed post responses as uncertain', async t => {
  const secondRef = `${opaque('graphnode').slice(0, -1)}C`
  const graph = { ...recordedGraph, nodes: [...recordedGraph.nodes, { id: 'person_2', kind: 'person', label: 'Person B', documentIds: ['document_1'] }] }
  const binding = { ...recordedBinding, nodes: [...recordedBinding.nodes, { graphNodeId: 'person_2', nodeRef: secondRef }] }
  let received
  t.mock.method(globalThis, 'fetch', async (_url, options) => { received = JSON.parse(options.body); return Response.json({ ...recordedPayload(1), nodes: [...recordedPayload(1).nodes, { id: secondRef, kind: 'person' }], identity_actions: [{ action: 'MERGE', canonical: recordedBinding.nodes[0].nodeRef, members: [recordedBinding.nodes[0].nodeRef, secondRef] }] }) })
  const view = await mergeRecordedGraphIdentities({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph, canonicalPersonRef: recordedBinding.nodes[0].nodeRef, memberPersonRefs: [recordedBinding.nodes[0].nodeRef, secondRef], expectedRevision: 0 })
  assert.deepEqual(received, { canonical_person_ref: recordedBinding.nodes[0].nodeRef, member_person_refs: [recordedBinding.nodes[0].nodeRef, secondRef], expected_revision: 0 })
  assert.deepEqual(view.identityActions, [{ action: 'MERGE', canonicalPersonRef: recordedBinding.nodes[0].nodeRef, memberPersonRefs: [recordedBinding.nodes[0].nodeRef, secondRef] }])
  t.mock.restoreAll(); t.mock.method(globalThis, 'fetch', async () => Response.json({ invalid: true }))
  await assert.rejects(mergeRecordedGraphIdentities({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding, graph, canonicalPersonRef: recordedBinding.nodes[0].nodeRef, memberPersonRefs: [recordedBinding.nodes[0].nodeRef, secondRef], expectedRevision: 0 }), /identity outcome may be unverified/)
  await assert.rejects(splitRecordedGraphIdentity({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph, sourcePersonRef: recordedBinding.nodes[0].nodeRef, replacementPersonRefs: ['unbound', 'also-unbound'], endpointAssignments: [], expectedRevision: 0 }), GraphReviewFailure)
})

test('recorded decision separates definite HTTP rejection from uncertain transport outcome', async t => {
  for (const [status, expected] of [[401, 'Reviewer authentication is required.'], [403, 'This token is not permitted to review recorded graphs.'], [404, 'This recorded graph is unavailable or no longer belongs to this reviewer.'], [409, 'This graph changed. Reload it before submitting another decision.']]) {
    t.mock.method(globalThis, 'fetch', async () => new Response('', { status }))
    await assert.rejects(decideRecordedGraphClaim({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph, claimRef: recordedBinding.claims[0].claimRef, decision: 'ACCEPT', expectedRevision: 0 }), error => error instanceof GraphReviewFailure && error.status === status && error.message === expected)
    t.mock.restoreAll()
  }
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('do-not-echo') })
  await assert.rejects(decideRecordedGraphClaim({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph, claimRef: recordedBinding.claims[0].claimRef, decision: 'ACCEPT', expectedRevision: 0 }), error => error instanceof GraphReviewFailure && error.status === undefined && /may be unverified/.test(error.message) && !error.message.includes('do-not-echo'))
})

test('recorded review fails closed on an unbound claim, changed endpoint, or unsafe response field', async t => {
  for (const mutate of [value => { value.claims[0].source = recordedBinding.nodes[1].nodeRef }, value => { value.claims[0].id = opaque('graphclaim').replace(/A$/, 'C') }, value => { value.evidence = 'source-text' }]) {
    const payload = structuredClone(recordedPayload(0)); mutate(payload)
    t.mock.method(globalThis, 'fetch', async () => Response.json(payload))
    await assert.rejects(getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph }), GraphReviewFailure)
    t.mock.restoreAll()
  }
})

test('recorded review has one 30-second deadline and propagates caller cancellation', { timeout: 2000 }, async t => {
  const original = globalThis.setTimeout; const delays = []
  t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => { delays.push(delay); return original(callback, 0, ...args) })
  let transportSignal
  t.mock.method(globalThis, 'fetch', async (_url, options) => { transportSignal = options.signal; return new Promise(() => {}) })
  await assert.rejects(getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph }), /Recorded review timed out after 30 seconds/)
  assert.deepEqual(delays, [30000]); assert.equal(transportSignal.aborted, true)
  const controller = new AbortController(); let secondSignal
  t.mock.restoreAll(); t.mock.method(globalThis, 'fetch', async (_url, options) => { secondSignal = options.signal; return new Promise(() => {}) })
  const pending = getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph, signal: controller.signal })
  await new Promise(resolve => setImmediate(resolve)); controller.abort()
  await assert.rejects(pending, /request was cancelled/); assert.equal(secondSignal.aborted, true)
})

test('recorded review bounds a streamed response before JSON parsing', async t => {
  const oversized = new Uint8Array(64_001)
  t.mock.method(globalThis, 'fetch', async () => new Response(oversized, { status: 200, headers: { 'content-type': 'application/json' } }))
  await assert.rejects(getRecordedGraphReview({ apiBase: 'http://localhost:8000', token: 'reviewer-secret', binding: recordedBinding, graph: recordedGraph }), GraphReviewFailure)
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
test('UI keeps the advanced control plane metadata-only and has no credential persistence or export', () => {
  const ui = readFileSync(new URL('../src/main.tsx', import.meta.url), 'utf8')
  assert.doesNotMatch(ui, /localStorage|sessionStorage|clipboard|demoRelease|download=/)
  assert.match(ui, /Synthetic data only/)
  assert.match(ui, /Do not submit customer, employee, passenger/)
  assert.match(ui, /receives and temporarily stores submitted content/)
  assert.match(ui, /output preview is available from this workbench/)
  assert.match(ui, /token is held only in this page’s memory/)
  assert.match(ui, /Advanced control-plane workflow/)
  assert.match(ui, /private candidate record exists\. Its body is intentionally not available/)
  assert.match(ui, /Upload and inspect synthetic data/)
  assert.match(ui, /can miss or leave sensitive information unredacted/)
  assert.match(ui, /const selection = \+\+fileSelection\.current\s*\n\s*if \(file\.size === 0 \|\| file\.size > DEMO_MAX_BYTES\)/)
  assert.match(ui, /const \[readingFile, setReadingFile\] = useState\(false\)/)
  assert.match(ui, /const invalidateDemoFileSelection = \(\) => \{ fileSelection\.current \+= 1; setReadingFile\(false\) \}/)
  assert.match(ui, /onChange=\{event => \{ invalidateDemoFileSelection\(\); clearDemoResult\(\); setDemoFormat/)
  assert.match(ui, /onChange=\{event => \{ invalidateDemoFileSelection\(\); clearDemoResult\(\); setDemoContent/)
  assert.match(ui, /disabled=\{!syntheticAcknowledged \|\| readingFile\}/)
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
  assert.match(ui, /<\/fieldset>\s*\{busy && <div className="run-actions"[^>]*>.*onClick=\{cancel\}>Cancel browser request/s)
  assert.match(ui, /signal: controller\.signal/)
  assert.match(ui, /if \(activeRequest\.current\) return/)
  assert.match(ui, /activeRequest\.current === controller && !controller\.signal\.aborted/)
  assert.match(ui, /activeRequest\.current = null\s*\r?\n\s*setBusy\(false\)/)
  assert.match(ui, /useEffect\(\(\) => \(\) =>/)
})
test('card identity, eligibility and required gates must match safe envelope', () => {
  for (const change of [x => x.card.release_id = 'foreign', x => x.card.dataset_id = 'foreign', x => x.card.eligibility = 'APPROVED_ANONYMIZED', x => x.card.eligibility = 'BLOCKED', x => x.card.gates = [], x => x.status = 'approved', x => x.eligibility = ['REVIEW_REQUIRED'], x => x.card.release_mode = ['external_anonymized']]) {
    const value = safe(); change(value); assert.throws(() => validateRelease(value), /unsafe response/)
  }
})

const controlRequest = { apiBase: 'http://localhost:8000', token: 'test-token', content: 'synthetic', recipient: 'buyer-test', purpose: 'ai-training-resale', mode: 'external_anonymized' }
const digest = char => `sha256:${char.repeat(64)}`
const rightsDigest = char => char.repeat(64)
const controlRun = (state, candidate = null) => ({
  id: 'run-1', dataset_id: 'dataset-1', state, attempts: state === 'REGISTERED' ? 0 : 1,
  request_digest: digest('c'), method_id: 'rules-v1', language: 'en', policy_digest: digest('d'), rights_digest: rightsDigest('e'),
  recipient: 'buyer-test', purpose: 'ai-training-resale', candidate,
  events: [{ sequence: 1, state: state === 'REGISTERED' ? 'REGISTERED' : state, action: state === 'REGISTERED' ? 'REGISTERED' : 'QUARANTINED', occurred_at: '2026-09-20T00:00:00Z', attempt: state === 'REGISTERED' ? 0 : 1 }],
})
const safeCandidate = () => ({ artifact_digest: digest('a'), schema_digest: digest('b'), payload_kind: 'text', media_type: 'text/plain', byte_count: 12, ledger: [{ entity_type: 'PII', action: 'REDACT', reason: 'POLICY_RULE', count: 1 }] })
const controlResponses = (state = 'QUARANTINED', candidate = safeCandidate()) => [
  { id: 'dataset-1' },
  { id: 'rights-1', profile_id: 'workbench-rights', version: 'v1', digest: rightsDigest('e'), expires_at: '2026-09-20T01:00:00Z', resale_allowed: true, permitted_purposes: ['ai-training-resale'], permitted_recipients: ['buyer-test'] },
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

test('M6 refuses non-contract ledger strings that could contain source content', async t => {
  for (const mutate of [
    entry => { entry.entity_type = 'alex@example.com' },
    entry => { entry.action = 'raw-secret' },
    entry => { entry.reason = 'raw-secret' },
  ]) {
    let index = 0
    const candidate = safeCandidate()
    mutate(candidate.ledger[0])
    t.mock.method(globalThis, 'fetch', async () => Response.json(controlResponses('QUARANTINED', candidate)[index++]))
    await assert.rejects(runControlPlane(controlRequest), error => error instanceof ControlPlaneFailure && !error.message.includes('raw-secret') && !error.message.includes('alex@example.com'))
    t.mock.reset()
  }
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

const demoResponse = (overrides = {}) => ({
  posture: 'SYNTHETIC_DEMO_ONLY', format: 'text', release_authorized: false,
  findings: [{ entity_type: 'EMAIL', severity: 'high', count: 1 }],
  operations: [{ entity_type: 'EMAIL', action: 'REDACT', count: 1 }],
  transformed_preview: 'contact [REDACTED_EMAIL]',
  limitations: ['Rules-only coverage is incomplete.'], ...overrides,
})

test('synthetic demo inspector posts the explicit acknowledgment and returns only its strict contract', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async (_url, options) => {
    assert.equal(options.headers.Authorization, 'Bearer demo-token')
    assert.deepEqual(JSON.parse(options.body), { format: 'text', content: 'synthetic@example.test', synthetic_only: true })
    return Response.json(demoResponse())
  })
  const result = await inspectSyntheticDemo({ apiBase: 'http://localhost:8000/', token: ' demo-token ', format: 'text', content: 'synthetic@example.test' })
  assert.equal(mock.mock.calls[0].arguments[0], 'http://localhost:8000/demo/inspect')
  assert.equal(result.releaseAuthorized, false)
  assert.equal(result.transformedPreview, 'contact [REDACTED_EMAIL]')
  assert.equal(result.findings[0].entityType, 'EMAIL')
})

test('synthetic demo inspector rejects unsafe and mismatched API responses', async t => {
  for (const response of [
    demoResponse({ release_authorized: true }), demoResponse({ format: 'csv' }), demoResponse({ findings: [{ entity_type: 'raw@example.test', severity: 'high', count: 1 }] }),
    demoResponse({ transformed_preview: 'x'.repeat(DEMO_MAX_BYTES + 1) }), demoResponse({ unexpected: true }),
  ]) {
    t.mock.method(globalThis, 'fetch', async () => Response.json(response))
    await assert.rejects(inspectSyntheticDemo({ apiBase: 'http://localhost:8000', token: 'demo-token', format: 'text', content: 'synthetic' }), error => error instanceof DemoInspectionFailure && /invalid inspection/.test(error.message))
    t.mock.reset()
  }
})

test('synthetic demo upload decoding enforces extension, size, UTF-8 and nonblank input locally', () => {
  assert.deepEqual(decodeDemoUpload('sample.CSV', new TextEncoder().encode('email\nsynthetic@example.test')), { format: 'csv', content: 'email\nsynthetic@example.test' })
  for (const [name, bytes] of [
    ['sample.pdf', new Uint8Array([1])], ['empty.txt', new Uint8Array()], ['large.txt', new Uint8Array(DEMO_MAX_BYTES + 1)], ['broken.txt', new Uint8Array([0xc3, 0x28])], ['blank.txt', new TextEncoder().encode(' \n')],
  ]) assert.throws(() => decodeDemoUpload(name, bytes), DemoInspectionFailure)
})

test('synthetic demo invalid input and HTTP errors do not create a result', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not run') })
  await assert.rejects(inspectSyntheticDemo({ apiBase: 'http://localhost:8000', token: '', format: 'text', content: 'synthetic' }), /required/)
  await assert.rejects(inspectSyntheticDemo({ apiBase: 'http://localhost:8000', token: 'token', format: 'text', content: 'x'.repeat(DEMO_MAX_BYTES + 1) }), /100 KB/)
  assert.equal(mock.mock.calls.length, 0)
  t.mock.reset()
  t.mock.method(globalThis, 'fetch', async () => new Response('raw-secret', { status: 503 }))
  await assert.rejects(inspectSyntheticDemo({ apiBase: 'http://localhost:8000', token: 'token', format: 'text', content: 'synthetic' }), error => error instanceof DemoInspectionFailure && !error.message.includes('raw-secret') && /unavailable/.test(error.message))
})

test('synthetic demo rejects an unsupported runtime format before sending source', async t => {
  const mock = t.mock.method(globalThis, 'fetch', async () => { throw new Error('must not run') })
  await assert.rejects(inspectSyntheticDemo({ apiBase: 'http://localhost:8000', token: 'token', format: 'xml', content: 'synthetic' }), /Unsupported demo source format/)
  assert.equal(mock.mock.calls.length, 0)
})

for (const phase of ['headers', 'body']) {
  test(`synthetic demo deadline aborts stalled ${phase}`, { timeout: 2000 }, async t => {
    const originalSetTimeout = globalThis.setTimeout
    const delays = []
    t.mock.method(globalThis, 'setTimeout', (callback, delay, ...args) => {
      delays.push(delay)
      return originalSetTimeout(callback, 20, ...args)
    })
    let signal
    t.mock.method(globalThis, 'fetch', async (_url, options) => {
      signal = options.signal
      if (phase === 'headers') return new Promise(() => {})
      return new Response(new ReadableStream({ start(controller) { controller.enqueue(new TextEncoder().encode('{')) } }))
    })
    await assert.rejects(inspectSyntheticDemo({ apiBase: 'http://localhost:8000', token: 'token', format: 'text', content: 'synthetic' }), error => error instanceof DemoInspectionFailure && /timed out after 30 seconds/.test(error.message))
    assert.deepEqual(delays, [REQUEST_TIMEOUT_MS])
    assert.equal(signal.aborted, true)
  })
}

test('synthetic demo caller cancellation aborts its transport without echoing an abort reason', async t => {
  const caller = new AbortController()
  let start, signal
  const started = new Promise(resolve => { start = resolve })
  t.mock.method(globalThis, 'fetch', async (_url, options) => { signal = options.signal; start(); return new Promise(() => {}) })
  const pending = inspectSyntheticDemo({ apiBase: 'http://localhost:8000', token: 'token', format: 'text', content: 'synthetic', signal: caller.signal })
  await started
  caller.abort('raw-secret-reason')
  await assert.rejects(pending, error => error instanceof DemoInspectionFailure && /was cancelled/.test(error.message) && !error.message.includes('raw-secret'))
  assert.equal(signal.aborted, true)
})
