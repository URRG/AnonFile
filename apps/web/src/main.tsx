import React, { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  runControlPlane,
  type ControlPlaneFailure,
  type ControlPlaneRequest,
  type ControlPlaneView,
  type Mode,
  type SourceFormat,
} from './api'
import './styles.css'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const MODE: Mode = 'external_anonymized'

function failureMessage(failure: ControlPlaneFailure): string {
  const value = failure as unknown
  if (value instanceof Error && value.message) return value.message
  if (typeof value === 'object' && value !== null && 'message' in value && typeof value.message === 'string') return value.message
  return 'The control-plane request failed. No output was returned or authorized.'
}

function StateBadge({ state }: Pick<ControlPlaneView, 'state'>) {
  return <span className={`state state-${state.toLowerCase()}`}>{state.replaceAll('_', ' ')}</span>
}

function App() {
  const [token, setToken] = useState('')
  const [content, setContent] = useState('Synthetic example only: contact alex@example.com about booking DEMO-123.')
  const [recipient, setRecipient] = useState('synthetic-recipient')
  const [purpose, setPurpose] = useState('model-training')
  const [format, setFormat] = useState<SourceFormat>('text')
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ControlPlaneView | null>(null)
  const [failure, setFailure] = useState<ControlPlaneFailure | null>(null)
  const activeRequest = useRef<AbortController | null>(null)

  useEffect(() => () => {
    activeRequest.current?.abort()
    activeRequest.current = null
  }, [])

  const clearResult = () => {
    setResult(null)
    setFailure(null)
  }

  async function run() {
    if (activeRequest.current) return
    const controller = new AbortController()
    activeRequest.current = controller
    clearResult()
    setBusy(true)
    const request: ControlPlaneRequest = {
      apiBase: API_BASE,
      token,
      content,
      recipient,
      purpose,
      mode: MODE,
      format,
      language: 'en',
      signal: controller.signal,
    } as ControlPlaneRequest
    try {
      const view = await runControlPlane(request)
      if (activeRequest.current === controller && !controller.signal.aborted) setResult(view)
    } catch (cause) {
      if (activeRequest.current === controller && !controller.signal.aborted) setFailure(cause as ControlPlaneFailure)
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null
        setBusy(false)
      }
    }
  }

  const cancel = () => activeRequest.current?.abort()

  return <main className="workbench">
    <header className="masthead">
      <p className="eyebrow">Development control plane</p>
      <h1>AnonFlow workbench</h1>
      <p className="lede">Create an auditable processing run and inspect only its control metadata. Source and transformed content are never previewed or downloaded here.</p>
    </header>

    <aside className="notice" role="note">
      <strong>Synthetic data only.</strong> This development service receives and temporarily stores submitted content. It cannot verify that it is synthetic. Do not submit customer, employee, passenger, health, payment, credential, or confidential business data.
    </aside>

    <section className="controls-summary" aria-labelledby="controls-heading">
      <h2 id="controls-heading">What this run does</h2>
      <dl>
        <div><dt>Workflow</dt><dd>Ingest, bind local rights and policy controls, register a run, then execute it.</dd></div>
        <div><dt>Processing method</dt><dd><code>rules-v1</code> with a fixed external-candidate policy profile.</dd></div>
        <div><dt>What is withheld</dt><dd>Source data, transformed content, output previews, approvals, and exports.</dd></div>
        <div><dt>What is not proven</dt><dd>Completeness of detection, anonymization, residual privacy risk, utility, or sale eligibility.</dd></div>
      </dl>
    </section>

    <form onSubmit={event => { event.preventDefault(); void run() }}>
      <fieldset disabled={busy}>
        <legend>Start a control-plane run</legend>
        <p className="field-help">The token is held only in this page’s memory and is not saved by the workbench.</p>
        <label>
          Processor access token
          <input type="password" value={token} autoComplete="off" spellCheck={false} required onChange={event => { clearResult(); setToken(event.target.value) }} />
        </label>
        <div className="field-grid">
          <label>
            Intended recipient
            <input value={recipient} required maxLength={128} pattern="[a-z0-9][a-z0-9._:-]{0,127}" spellCheck={false} onChange={event => { clearResult(); setRecipient(event.target.value) }} />
          </label>
          <label>
            Permitted purpose
            <input value={purpose} required maxLength={128} pattern="[a-z0-9][a-z0-9._:-]{0,127}" spellCheck={false} onChange={event => { clearResult(); setPurpose(event.target.value) }} />
          </label>
        </div>
        <p className="field-help">Use lower-case control labels, for example <code>buyer-a</code> and <code>model-training</code>. They must match the temporary rights profile created for this development run.</p>
        <label>
          Source format
          <select value={format} onChange={event => { clearResult(); setFormat(event.target.value as SourceFormat) }}>
            <option value="text">Plain text</option>
            <option value="json">JSON array of objects</option>
            <option value="jsonl">JSON Lines (objects)</option>
            <option value="csv">CSV with headers</option>
          </select>
        </label>
        <label>
          Synthetic source content
          <textarea value={content} required rows={10} onChange={event => { clearResult(); setContent(event.target.value) }} />
        </label>
        <button type="submit">Run control-plane processing</button>
      </fieldset>
      {busy && <div className="run-actions" aria-live="polite"><span>Control-plane request in progress…</span><button type="button" className="secondary" onClick={cancel}>Cancel browser request</button></div>}
    </form>

    <p className="field-help">Cancellation stops this browser request only. It does not undo data already received or stop server-side processing. This page has no browser credential persistence.</p>

    {failure && <section className="failure" role="alert" aria-live="assertive">
      <h2>Run was not completed</h2>
      <p>{failureMessage(failure)}</p>
      <p>No output was returned, approved, or exported.</p>
    </section>}

    {result && <section className="run-result" aria-label="Control-plane run metadata" aria-live="polite">
      <div className="result-heading">
        <div><p className="eyebrow">Run state</p><h2><StateBadge state={result.state} /></h2></div>
        <p>{result.message}</p>
      </div>

      <div className="metadata-grid">
        <article>
          <h3>Run evidence</h3>
          <dl>
            <div><dt>Run ID</dt><dd><code>{result.runId}</code></dd></div>
            <div><dt>Dataset ID</dt><dd><code>{result.datasetId}</code></dd></div>
            <div><dt>Attempts</dt><dd>{result.attempts}</dd></div>
          </dl>
        </article>
        <article>
          <h3>Policy binding</h3>
          <dl>
            <div><dt>Policy</dt><dd>{result.policy.id} · {result.policy.key}</dd></div>
            <div><dt>Digest</dt><dd><code>{result.policy.digest}</code></dd></div>
          </dl>
        </article>
        <article>
          <h3>Rights binding</h3>
          <dl>
            <div><dt>Profile</dt><dd>{result.rights.profileId}</dd></div>
            <div><dt>Expiry</dt><dd>{result.rights.expiresAt}</dd></div>
            <div><dt>Digest</dt><dd><code>{result.rights.digest}</code></dd></div>
          </dl>
        </article>
      </div>

      {result.candidate ? <article className="candidate-evidence">
        <h3>Candidate metadata only</h3>
        <p>A private candidate record exists. Its body is intentionally not available to this workbench.</p>
        <dl className="metadata-grid compact">
          <div><dt>Artifact digest</dt><dd><code>{result.candidate.artifactDigest}</code></dd></div>
          <div><dt>Schema digest</dt><dd><code>{result.candidate.schemaDigest}</code></dd></div>
          <div><dt>Payload kind</dt><dd>{result.candidate.payloadKind}</dd></div>
          <div><dt>Media type</dt><dd>{result.candidate.mediaType}</dd></div>
          <div><dt>Byte count</dt><dd>{result.candidate.byteCount}</dd></div>
        </dl>
        <h4>Applied operation counts</h4>
        {result.candidate.ledger.length === 0 ? <p>No output operations were recorded. This is not evidence that no sensitive data was present.</p> : <ul>{result.candidate.ledger.map(item => <li key={`${item.entityType}-${item.action}-${item.reason}`}><code>{item.entityType}</code>: {item.count} {item.action} ({item.reason})</li>)}</ul>}
      </article> : <article className="candidate-evidence">
        <h3>Candidate metadata unavailable</h3>
        <p>No private candidate metadata is available for this run. Nothing is eligible for approval or export.</p>
      </article>}

      <article className="limitations">
        <h3>Evidence limitations</h3>
        <ul>
          <li>The built-in rules can miss names, context, health information, business-confidential data, and identifying relationships.</li>
          <li>This workflow does not independently evaluate residual findings, re-identification risk, data utility, or policy completeness.</li>
          <li>A candidate record is not a qualified, approved, anonymous, or sellable dataset.</li>
          <li>No buyer delivery, approval, export, or output preview is available from this workbench.</li>
        </ul>
      </article>
    </section>}
  </main>
}

createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
