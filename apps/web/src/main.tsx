import React, { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { requestRelease, type Mode, type ReleaseView } from './api'
import './styles.css'

function App() {
  const [token, setToken] = useState('')
  const [content, setContent] = useState('Synthetic example only: contact alex@example.com about booking DEMO-123.')
  const [recipient, setRecipient] = useState('synthetic-recipient')
  const [mode, setMode] = useState<Mode>('external_anonymized')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ReleaseView | null>(null)
  const [error, setError] = useState('')
  const activeRequest = useRef<AbortController | null>(null)
  useEffect(() => () => {
    activeRequest.current?.abort()
    activeRequest.current = null
  }, [])
  const clear = () => { setResult(null); setError('') }
  async function run() {
    if (activeRequest.current) return
    const controller = new AbortController()
    activeRequest.current = controller
    clear(); setBusy(true)
    try {
      const release = await requestRelease({ apiBase: import.meta.env.VITE_API_URL || 'http://localhost:8000', token, content, recipient, mode, signal: controller.signal })
      if (activeRequest.current === controller && !controller.signal.aborted) setResult(release)
    } catch (cause) {
      if (activeRequest.current === controller) setError(cause instanceof Error ? cause.message : 'Processing failed. No release was authorized.')
    } finally {
      if (activeRequest.current === controller) { activeRequest.current = null; setBusy(false) }
    }
  }
  return <main className="workbench">
    <h1>AnonFlow · secure processing foundation</h1>
    <p role="note"><strong>Synthetic data only.</strong> Do not submit customer data. This development service accepts and temporarily stores submitted text; it cannot verify that data is synthetic. Buyer export is disabled.</p>
    <p>Rules can miss names, context, health information, confidential business data and identifying relationships. No result from this workbench qualifies a dataset for sale.</p>
    <form onSubmit={event => { event.preventDefault(); void run() }}>
      <fieldset disabled={busy}>
        <label>Development processor token<input type="password" value={token} autoComplete="off" spellCheck={false} required onChange={e => { clear(); setToken(e.target.value) }} /></label>
        <label>Intended recipient<input value={recipient} required maxLength={160} onChange={e => { clear(); setRecipient(e.target.value) }} /></label>
        <label>Requested mode<select value={mode} onChange={e => { clear(); setMode(e.target.value as Mode) }}>
          <option value="external_anonymized">External anonymized candidate (unqualified)</option>
          <option value="restricted_pseudonymized">Restricted pseudonymized candidate (unqualified)</option>
        </select></label>
        <label>Synthetic input<textarea value={content} required rows={9} onChange={e => { clear(); setContent(e.target.value) }} /></label>
        <button type="submit">{busy ? 'Processing…' : 'Run synthetic evaluation'}</button>
      </fieldset>
      {busy && <p><button type="button" onClick={() => activeRequest.current?.abort()}>Cancel request</button></p>}
    </form>
    <p>Requests time out after 30 seconds. Cancelling stops this browser request, not server-side processing or retention of data already received.</p>
    {error && <p role="alert">{error}</p>}
    {result && <section aria-label="Processing evidence" aria-live="polite">
      <h2>{result.eligibility.replaceAll('_', ' ')}</h2>
      <p>Evidence: {result.card.evidence_status}. Output withheld. No release authorized.</p>
      <p>Release {result.id} · Policy {result.card.policy_version}</p>
      <h3>Detected findings (not complete coverage)</h3>
      <ul>{result.card.findings.map((finding, index) => <li key={index}>{finding.entity_type}: {finding.count} ({finding.severity})</li>)}</ul>
      <h3>Release gates</h3><ul>{result.card.gates.map((gate, index) => <li key={index}>{gate}</li>)}</ul>
      <h3>Limitations</h3><ul>{result.card.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul>
    </section>}
  </main>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
