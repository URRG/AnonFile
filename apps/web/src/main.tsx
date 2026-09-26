import React, { useEffect, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import {
  DEMO_MAX_BYTES,
  decodeDemoUpload,
  inspectSyntheticDemo,
  runControlPlane,
  DemoInspectionFailure,
  type ControlPlaneFailure,
  type ControlPlaneRequest,
  type ControlPlaneView,
  type DemoInspection,
  type Mode,
  type SourceFormat,
} from './api'
import './styles.css'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const MODE: Mode = 'external_anonymized'

function failureMessage(failure: unknown): string {
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
  const [demoToken, setDemoToken] = useState('')
  const [demoContent, setDemoContent] = useState('[{"full_name":"Priya Demo","email":"priya.demo@example.test","phone":"+1 415 555 0134","passport_number":"DEMO123456","date_of_birth":"1990-01-01","booking_reference":"DEMO-BOOKING-001"}]')
  const [demoFormat, setDemoFormat] = useState<SourceFormat>('json')
  const [syntheticAcknowledged, setSyntheticAcknowledged] = useState(false)
  const [demoBusy, setDemoBusy] = useState(false)
  const [readingFile, setReadingFile] = useState(false)
  const [demoResult, setDemoResult] = useState<DemoInspection | null>(null)
  const [demoFailure, setDemoFailure] = useState<DemoInspectionFailure | null>(null)
  const activeDemoRequest = useRef<AbortController | null>(null)
  const fileSelection = useRef(0)

  useEffect(() => () => {
    activeRequest.current?.abort()
    activeRequest.current = null
    activeDemoRequest.current?.abort()
    activeDemoRequest.current = null
    fileSelection.current += 1
  }, [])

  const clearResult = () => {
    setResult(null)
    setFailure(null)
  }
  const clearDemoResult = () => { setDemoResult(null); setDemoFailure(null) }
  const invalidateDemoFileSelection = () => { fileSelection.current += 1; setReadingFile(false) }

  async function selectDemoFile(file: File | undefined) {
    if (!file) return
    clearDemoResult()
    // A later selection (including one rejected before reading) must prevent
    // an earlier File.arrayBuffer() from overwriting the current form values.
    const selection = ++fileSelection.current
    if (file.size === 0 || file.size > DEMO_MAX_BYTES) {
      setReadingFile(false)
      setDemoFailure(new DemoInspectionFailure('Demo files must be between 1 byte and 100 KB.'))
      return
    }
    setReadingFile(true)
    try {
      const bytes = new Uint8Array(await file.arrayBuffer())
      if (selection !== fileSelection.current) return
      const upload = decodeDemoUpload(file.name, bytes)
      setDemoFormat(upload.format)
      setDemoContent(upload.content)
    } catch (cause) {
      if (selection === fileSelection.current) setDemoFailure(cause as DemoInspectionFailure)
    } finally {
      if (selection === fileSelection.current) setReadingFile(false)
    }
  }

  async function inspectDemo() {
    if (activeDemoRequest.current || readingFile || !syntheticAcknowledged) return
    const controller = new AbortController()
    activeDemoRequest.current = controller
    clearDemoResult()
    setDemoBusy(true)
    try {
      const view = await inspectSyntheticDemo({ apiBase: API_BASE, token: demoToken, content: demoContent, format: demoFormat, signal: controller.signal })
      if (activeDemoRequest.current === controller && !controller.signal.aborted) setDemoResult(view)
    } catch (cause) {
      if (activeDemoRequest.current === controller && !controller.signal.aborted) setDemoFailure(cause as DemoInspectionFailure)
    } finally {
      if (activeDemoRequest.current === controller) { activeDemoRequest.current = null; setDemoBusy(false) }
    }
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
      <p className="eyebrow">Synthetic demo + development control plane</p>
      <h1>AnonFlow workbench</h1>
      <p className="lede">Inspect explicitly synthetic samples with bounded rules, then optionally create an auditable control-plane run. The advanced workflow never previews source or candidate content.</p>
    </header>

    <aside className="notice" role="note">
      <strong>Synthetic data only.</strong> This development service receives and temporarily stores submitted content. It cannot verify that it is synthetic. Do not submit customer, employee, passenger, health, payment, credential, or confidential business data.
    </aside>

    <section className="demo-panel" aria-labelledby="demo-heading">
      <div className="section-heading"><div><p className="eyebrow">Demo inspector</p><h2 id="demo-heading">Upload and inspect synthetic data</h2></div><span className="demo-badge">Synthetic demo only</span></div>
      <p className="lede compact">This isolated preview shows what the bounded <code>rules-v1</code> detector transforms. It is not a certification that all PII was found, and it never authorizes a release or export.</p>
      <form onSubmit={event => { event.preventDefault(); void inspectDemo() }}>
        <fieldset disabled={demoBusy}>
          <label>
            Processor access token
            <input type="password" value={demoToken} autoComplete="off" spellCheck={false} required onChange={event => { clearDemoResult(); setDemoToken(event.target.value) }} />
          </label>
          <label>
            Upload a synthetic file (optional)
            <input type="file" accept=".txt,.csv,.json,.jsonl,text/plain,text/csv,application/json" onChange={event => { void selectDemoFile(event.target.files?.[0]) }} />
          </label>
          <p className="field-help">Accepted: UTF-8 <code>.txt</code>, <code>.csv</code>, <code>.json</code>, or <code>.jsonl</code>, up to 100 KB. Selecting a file fills the text area; it is not uploaded until inspection starts.</p>
          <label>
            Demo source format
            <select value={demoFormat} onChange={event => { invalidateDemoFileSelection(); clearDemoResult(); setDemoFormat(event.target.value as SourceFormat) }}>
              <option value="text">Plain text</option><option value="json">JSON array of objects</option><option value="jsonl">JSON Lines (objects)</option><option value="csv">CSV with headers</option>
            </select>
          </label>
          <label>
            Synthetic demo content
            <textarea value={demoContent} required rows={8} onChange={event => { invalidateDemoFileSelection(); clearDemoResult(); setDemoContent(event.target.value) }} />
          </label>
          <label className="acknowledgment">
            <input type="checkbox" checked={syntheticAcknowledged} onChange={event => setSyntheticAcknowledged(event.target.checked)} />
            <span>I confirm this is synthetic demo data only. I understand the preview can miss or leave sensitive information unredacted.</span>
          </label>
          <button type="submit" disabled={!syntheticAcknowledged || readingFile}>{readingFile ? 'Reading selected file…' : 'Inspect synthetic sample'}</button>
        </fieldset>
      </form>
      {demoBusy && <div className="run-actions" aria-live="polite"><span>Inspecting synthetic demo sample…</span><button type="button" className="secondary" onClick={() => activeDemoRequest.current?.abort()}>Cancel inspection</button></div>}
      {demoFailure && <section className="failure" role="alert"><h3>Demo inspection was not completed</h3><p>{failureMessage(demoFailure)}</p></section>}
      {demoResult && <section className="demo-result" aria-live="polite" aria-label="Synthetic demo inspection result">
        <div className="warning-preview"><strong>Not certified — review this preview carefully.</strong> Rules can miss PII, so transformed content may still contain sensitive information. Do not share, export, or treat it as anonymous.</div>
        <div className="demo-grid">
          <article><h3>Detected categories</h3>{demoResult.findings.length ? <ul>{demoResult.findings.map(item => <li key={`${item.entityType}-${item.severity}`}><code>{item.entityType}</code> · {item.count} ({item.severity})</li>)}</ul> : <p>No rules matched. This does not establish that the sample contains no PII.</p>}</article>
          <article><h3>Applied operations</h3>{demoResult.operations.length ? <ul>{demoResult.operations.map(item => <li key={`${item.entityType}-${item.action}`}><code>{item.entityType}</code> · {item.count} {item.action}</li>)}</ul> : <p>No transformation operations were recorded.</p>}</article>
        </div>
        <article className="preview"><h3>Transformed synthetic preview</h3>{(demoResult.format === 'csv' || demoResult.format === 'jsonl') && <p className="field-help">Structured input is displayed as normalized JSON; the original file layout is not preserved.</p>}<pre>{demoResult.transformedPreview}</pre></article>
        <article className="limitations"><h3>Detector limitations</h3><ul>{demoResult.limitations.map((item, index) => <li key={index}>{item}</li>)}<li>Identifiers represented by unrecognized fields, such as <code>booking_reference</code>, may remain visible.</li><li>This preview is synthetic-demo-only and cannot approve a release, export, anonymity claim, or sale.</li></ul></article>
      </section>}
    </section>

    <section className="controls-summary" aria-labelledby="controls-heading">
      <h2 id="controls-heading">Advanced control-plane workflow</h2>
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
