// Real HTTP smoke test: local single-worker API + actual browser request module.
// All data and credentials are generated synthetic test fixtures.
import test from 'node:test'
import assert from 'node:assert/strict'
import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createServer } from 'node:net'
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
    env: { ...process.env, ANONFLOW_ENV: 'development', ANONFLOW_DEV_PRINCIPALS: JSON.stringify(principals), PYTHONDONTWRITEBYTECODE: '1' },
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
    const { requestRelease } = await import(`data:text/javascript;base64,${Buffer.from(compiled).toString('base64')}`)
    const content = 'Synthetic contact alex@example.com'
    const release = await requestRelease({ apiBase: base, token: processor, content, mode: 'external_anonymized', recipient: 'synthetic-buyer' })
    assert.equal(release.eligibility, 'REVIEW_REQUIRED')
    assert.equal(release.output, null)
    assert.equal(release.card.scores, null)
    assert.ok(release.card.findings.some(f => f.entity_type === 'EMAIL'))
    assert.ok(!JSON.stringify(release).includes('alex@example.com'))
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
  } finally {
    if (child.exitCode === null && !launchError) {
      const closed = new Promise(resolve => child.once('close', resolve))
      child.kill()
      await closed
    }
  }
})
