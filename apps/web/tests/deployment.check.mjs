import test from 'node:test'
// Repository-level checks: intentionally separate from the web-only image suite.
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
const read = path => readFileSync(new URL(path, import.meta.url), 'utf8')
test('Compose preserves explicit environment guard and loopback ports', () => {
  const compose = read('../../../docker-compose.yml')
  assert.match(compose, /ANONFLOW_ENV: \$\{ANONFLOW_ENV:-development\}/)
  assert.match(compose, /127\.0\.0\.1:8000:8000/)
  assert.match(compose, /127\.0\.0\.1:3000:3000/)
  assert.doesNotMatch(compose, /VITE_API_BASE_URL/)
})
test('Docker source contexts exclude local dependency trees and credentials', () => {
  const web = read('../.dockerignore').split(/\r?\n/)
  for (const value of ['node_modules', 'dist', '.env', '.env.*']) assert.ok(web.includes(value))
  const api = read('../../../services/api/.dockerignore').split(/\r?\n/)
  for (const value of ['.venv', '.env', '.env.*', '**/__pycache__']) assert.ok(api.includes(value))
  for (const value of ['**/*.db', '**/*.db-*', '**/*.sqlite', '**/*.sqlite-*', '**/*.sqlite3', '**/*.sqlite3-*', '**/*.pem', '**/*.key', '**/secrets']) {
    assert.ok(api.includes(value)); assert.ok(web.includes(value))
  }
})
test('CI audits resolved dependencies and builds both development images', () => {
  const workflow = read('../../../.github/workflows/ci.yml')
  assert.match(workflow, /dependency-audit:/)
  assert.match(workflow, /python -m pip_audit --strict --progress-spinner off/)
  assert.match(workflow, /npm audit --omit=dev --audit-level=high/)
  assert.match(workflow, /container-build:/)
  assert.match(workflow, /docker compose build api web/)
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/)
})
test('development image bases are digest-pinned across all stages', () => {
  const api = read('../../../services/api/Dockerfile')
  const web = read('../Dockerfile')
  const apiBases = [...api.matchAll(/^FROM\s+(\S+)/gm)].map(match => match[1])
  const webBases = [...web.matchAll(/^FROM\s+(\S+)/gm)].map(match => match[1])
  assert.equal(apiBases.length, 1)
  assert.deepEqual(webBases.slice(1, 3), ['source', 'source'])
  assert.equal(webBases.length, 4)
  for (const base of [...apiBases, webBases[0], webBases[3]]) {
    assert.match(base, /^\S+@sha256:[a-f0-9]{64}$/)
  }
  assert.equal(webBases[0], webBases[3])
})
test('CI action references use immutable full commit SHAs', () => {
  const workflow = read('../../../.github/workflows/ci.yml')
  const actions = [...workflow.matchAll(/^\s*- uses:\s+(\S+)/gm)].map(match => match[1])
  assert.ok(actions.length >= 10)
  for (const action of actions) assert.match(action, /^actions\/(?:checkout|setup-python|setup-node)@[a-f0-9]{40}$/)
})
test('CI database service image is digest-pinned', () => {
  const workflow = read('../../../.github/workflows/ci.yml')
  assert.match(workflow, /^\s+image: postgres:16-alpine@sha256:[a-f0-9]{64}$/m)
})
