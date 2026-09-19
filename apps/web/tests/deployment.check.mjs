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
