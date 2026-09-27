// Real HTTP smoke test: local single-worker API + actual browser request module.
// All data and credentials are generated synthetic test fixtures.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:net'
import { createServer as createHTTPServer } from 'node:http'
import { fileURLToPath } from 'node:url'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

test('real HTTP intake, withholding, independent review and isolation', { timeout: 20000 }, async () => {
  const server = createServer()
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  await new Promise(resolve => server.close(resolve))
  const token = () => randomBytes(32).toString('hex')
  const processor = token(), reviewer = token(), foreign = token(), buyer = token()
  const principals = [
    { token: processor, subject: 'processor-test', tenant: 'synthetic-a', roles: ['processor', 'reviewer'] },
    { token: reviewer, subject: 'reviewer-test', tenant: 'synthetic-a', roles: ['reviewer'] },
    { token: foreign, subject: 'foreign-test', tenant: 'synthetic-b', roles: ['processor'] },
    { token: buyer, subject: 'buyer-test', tenant: 'synthetic-a', roles: ['buyer'] },
  ]
  const child = spawn(process.env.ANONFLOW_TEST_PYTHON || 'python', ['-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', String(port), '--no-access-log'], {
    cwd: fileURLToPath(new URL('../../../services/api/', import.meta.url)),
    env: { ...process.env, ANONFLOW_ENV: 'development', ANONFLOW_AUTH_MODE: 'dev-token', ANONFLOW_STORAGE_MODE: 'memory', ANONFLOW_DEMO_MODE: 'enabled', ANONFLOW_DEV_PRINCIPALS: JSON.stringify(principals), PYTHONDONTWRITEBYTECODE: '1' },
    stdio: 'ignore', windowsHide: true,
  })
  let launchError = false
  child.on('error', () => { launchError = true })
  const base = `http://127.0.0.1:${port}`
  try {
    let ready = false
    for (let attempt = 0; attempt < 100 && !ready; attempt++) {
      if (launchError || child.exitCode !== null) throw new Error('Local synthetic API did not start.')
      try { ready = (await fetch(base + '/health', { signal: AbortSignal.timeout(200) })).ok } catch {}
      if (!ready) await new Promise(resolve => setTimeout(resolve, 50))
    }
    assert.ok(ready, 'API startup deadline')
    const source = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')
    const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
    const { requestRelease, runControlPlane, inspectSyntheticDemo, inspectSyntheticBatch } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
    const demoCsv = readFileSync(new URL('../../../demo-data/synthetic-airline-passengers.csv', import.meta.url), 'utf8')
    const demoInspection = await inspectSyntheticDemo({ apiBase: base, token: processor, format: 'csv', content: demoCsv })
    assert.equal(demoInspection.releaseAuthorized, false)
    assert.ok(demoInspection.transformedPreview.includes('[REDACTED_EMAIL]'))
    assert.ok(!demoInspection.transformedPreview.includes('alex@example.test'))
    assert.ok(demoInspection.findings.some(f => f.entityType === 'EMAIL'))
    const mailText = 'From: Riya <riya@example.test>\nTo: Sita <sita@example.test>\nHi Sita!'
    const recordText = '{"account_owner":"Riya","client_name":"Sita","email":"riya@example.test"}'
    const batch = await inspectSyntheticBatch({ apiBase: base, token: processor, files: [
      { id: 'mail', name: 'mail.txt', size: Buffer.byteLength(mailText), contentBase64: Buffer.from(mailText).toString('base64') },
      { id: 'record', name: 'record.json', size: Buffer.byteLength(recordText), contentBase64: Buffer.from(recordText).toString('base64') },
    ], manualNames: [], aliasOverrides: {}, referenceManifest: { basis: 'REVIEWER_ATTESTED_EXHAUSTIVE', documents: [
      { name: 'mail.txt', annotations: [{ start: mailText.indexOf('Riya'), end: mailText.indexOf('Riya') + 4, entity_type: 'PERSON_NAME' }] },
      { name: 'record.json', annotations: [{ start: recordText.indexOf('Riya'), end: recordText.indexOf('Riya') + 4, entity_type: 'PERSON_NAME' }] },
    ] } })
    assert.equal(batch.releaseAuthorized, false)
    assert.equal(batch.exportAvailable, false)
    assert.equal(batch.documents.length, 2)
    assert.equal(batch.relationships.length, 2)
    assert.ok(batch.relationships.some(edge => edge.type === 'ACCOUNT_OWNER_OF' && edge.basis === 'same JSON record account_owner/client_name'))
    const person = batch.entities.find(entity => entity.source === 'Riya')
    assert.equal(person.alias.length, 4)
    assert.ok(batch.documents.every(document => document.candidateText.includes(person.alias)))
    assert.equal(batch.verification.status, 'REVIEW_REQUIRED')
    assert.equal(batch.verification.annotationScore.goldAnnotations, 2)
    assert.equal(batch.verification.annotationScore.exact.truePositives, 2)
    assert.equal(batch.verification.aggregateScorecard.qualification, 'NOT_QUALIFIED')
    assert.equal(batch.verification.aggregateScorecard.finalArtifactValidation.status, 'ABSTAINED')
    const excluded = await inspectSyntheticBatch({ apiBase: base, token: processor, files: [
      { id: 'mail', name: 'mail.txt', size: Buffer.byteLength(mailText), contentBase64: Buffer.from(mailText).toString('base64') },
      { id: 'record', name: 'record.json', size: Buffer.byteLength(recordText), contentBase64: Buffer.from(recordText).toString('base64') },
    ], manualNames: [], aliasOverrides: {}, reviewExclusions: { [person.id]: 'FALSE_POSITIVE_CONFIRMED' } })
    assert.equal(excluded.summary.suppressedMentions, person.mentions)
    assert.ok(excluded.documents[0].candidateText.includes('Riya'))
    assert.equal(excluded.verification.checks.find(check => check.name === 'Reviewer exclusions').status, 'REVIEW')
    const content = 'Synthetic contact alex@example.com'
    const release = await requestRelease({ apiBase: base, token: processor, content, mode: 'external_anonymized', recipient: 'synthetic-buyer' })
    assert.equal(release.eligibility, 'REVIEW_REQUIRED')
    assert.equal(release.output, null)
    assert.equal(release.card.scores, null)
    assert.ok(release.card.findings.some(f => f.entity_type === 'EMAIL'))
    assert.ok(!JSON.stringify(release).includes('alex@example.com'))
    const controlRun = await runControlPlane({
      apiBase: base, token: processor, content, recipient: 'synthetic-buyer',
      purpose: 'model-training', mode: 'external_anonymized',
    })
    assert.equal(controlRun.state, 'QUARANTINED')
    assert.ok(controlRun.candidate, 'private candidate metadata is available for audit only')
    assert.ok(!JSON.stringify(controlRun).includes('alex@example.com'))
    assert.equal(controlRun.message.includes('expected to quarantine'), true)
    const call = (path, credential, body) => fetch(base + path, { method: body ? 'POST' : 'GET', headers: { Authorization: `Bearer ${credential}`, 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined })
    assert.equal((await call(`/releases/${release.id}`, foreign)).status, 404)
    assert.equal((await call(`/releases/${release.id}`, buyer)).status, 403)
    assert.equal((await call(`/reviews/${release.id}/decision`, processor, { decision: 'reject' })).status, 403)
    assert.equal((await call(`/reviews/${release.id}/decision`, reviewer, { decision: 'approve' })).status, 409)
    const rejected = await call(`/reviews/${release.id}/decision`, reviewer, { decision: 'reject' })
    assert.equal(rejected.status, 200)
    assert.equal((await rejected.json()).eligibility, 'BLOCKED')
    const critical = await requestRelease({ apiBase: base, token: processor, content: 'password="synthetic-only-secret"', mode: 'restricted_pseudonymized', recipient: 'synthetic-buyer' })
    assert.equal(critical.eligibility, 'BLOCKED')
    assert.equal(critical.output, null)
    for (const [format, content] of [['csv', 'contact,code\nsynthetic@example.test,001'], ['json', '[{"contact":"synthetic@example.test"}]'], ['jsonl', '{"contact":"synthetic@example.test"}\n']]) {
      const parsed = await requestRelease({ apiBase: base, token: processor, content, format, mode: 'external_anonymized', recipient: 'synthetic-buyer' })
      assert.equal(parsed.output, null)
      const manifest = await call(`/datasets/${parsed.dataset_id}/manifest`, reviewer)
      assert.equal(manifest.status, 200)
      assert.equal((await manifest.json()).manifest.format, format)
      assert.equal((await fetch(`${base}/datasets/${parsed.dataset_id}`, { method: 'DELETE', headers: { Authorization: `Bearer ${processor}` } })).status, 204)
      assert.equal((await call(`/releases/${parsed.id}`, processor)).status, 404)
    }
    const audit = await call('/audit', reviewer)
    assert.equal(audit.status, 200)
    assert.ok((await audit.json()).events.some(event => event.action === 'dataset.deleted'))
  } finally {
    if (child.exitCode === null && !launchError) {
      const closed = new Promise(resolve => child.once('close', resolve))
      child.kill()
      await closed
    }
  }
})

for (const phase of ['headers', 'body']) {
  test(`actual HTTP cancellation closes a stalled ${phase} connection`, { timeout: 5000 }, async () => {
    let observe, disconnected
    const observed = new Promise(resolve => { observe = resolve })
    const closed = new Promise(resolve => { disconnected = resolve })
    const server = createHTTPServer((incoming, response) => {
      incoming.socket.once('close', disconnected)
      if (phase === 'body') {
        response.writeHead(200, { 'Content-Type': 'application/json' })
        response.write('{')
      }
      observe()
    })
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
    const controller = new AbortController()
    try {
      const source = readFileSync(new URL('../src/api.ts', import.meta.url), 'utf8')
      const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
      const { requestRelease } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
      const result = requestRelease({ apiBase: `http://127.0.0.1:${server.address().port}`, token: 'synthetic-only-test-token', content: 'synthetic', recipient: 'synthetic', mode: 'external_anonymized', signal: controller.signal })
      await observed
      controller.abort()
      await assert.rejects(result, /Request cancelled.*No release was authorized/)
      await closed
    } finally {
      controller.abort()
      server.closeAllConnections()
      await new Promise(resolve => server.close(resolve))
    }
  })
}
