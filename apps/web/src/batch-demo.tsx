import React, { useEffect, useRef, useState } from 'react'
import { ArrowDown, ArrowLeft, ArrowRight, Check, ChevronRight, CircleAlert, FileCode2, FileText,
  Files, Fingerprint, FlaskConical, Link2, LockKeyhole, Plus, RefreshCw, Search, ShieldCheck,
  Sparkles, UploadCloud, X } from 'lucide-react'
import { inspectSyntheticBatch, readBatchFile, readBatchReferenceManifest, type BatchDocument, type BatchInspection,
  type BatchReferenceManifest, type BatchReferenceSpan, type BatchUpload, DemoInspectionFailure } from './api'
import './batch.css'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const SUPPRESSIBLE_KINDS = new Set(['PERSON_NAME', 'EMAIL', 'PHONE', 'IP_ADDRESS'])
type Step = 'upload' | 'detect' | 'results'
type ResultTab = 'documents' | 'relationships' | 'verification'

const SAMPLE_DOCUMENTS = [
  { name: '01-email-thread.txt', type: 'text/plain', text: 'From: Riya <riya@example.test>\nTo: Sita <sita@example.test>\nSubject: Flight change\n\nHi Sita, Riya can review the itinerary. Please call +1 415 555 0134.' },
  { name: '02-passenger-list.csv', type: 'text/csv', text: 'full_name,email,passport_number,date_of_birth,booking_reference\nRiya,riya@example.test,DEMO123456,1990-01-01,DEMO-4821\nSita,sita@example.test,DEMO654321,1992-02-02,DEMO-4822\n' },
  { name: '03-support-record.json', type: 'application/json', text: '{"client_name":"Sita","account_owner":"Riya","note":"Riya emailed Sita about DEMO-4822."}' },
] as const
const SAMPLES = SAMPLE_DOCUMENTS.map(item => new File([item.text], item.name, { type: item.type }))

function sampleSpans(text: string, values: [string, string][]): BatchReferenceSpan[] {
  const spans: BatchReferenceSpan[] = []
  for (const [value, entity_type] of values) {
    let from = 0
    while (true) {
      const start = text.indexOf(value, from)
      if (start === -1) break
      spans.push({ start, end: start + value.length, entity_type })
      from = start + value.length
    }
  }
  return spans.sort((a, b) => a.start - b.start)
}
const SAMPLE_REFERENCE: BatchReferenceManifest = { basis: 'CURATED_SYNTHETIC_SAMPLE', documents: [
  { name: SAMPLE_DOCUMENTS[0].name, annotations: sampleSpans(SAMPLE_DOCUMENTS[0].text, [
    ['Riya', 'PERSON_NAME'], ['Sita', 'PERSON_NAME'], ['riya@example.test', 'EMAIL'], ['sita@example.test', 'EMAIL'], ['+1 415 555 0134', 'PHONE']]) },
  { name: SAMPLE_DOCUMENTS[1].name, annotations: sampleSpans(SAMPLE_DOCUMENTS[1].text, [
    ['Riya', 'PERSON_NAME'], ['Sita', 'PERSON_NAME'], ['riya@example.test', 'EMAIL'], ['sita@example.test', 'EMAIL'],
    ['DEMO123456', 'GOVERNMENT_ID'], ['DEMO654321', 'GOVERNMENT_ID'], ['1990-01-01', 'DATE_OF_BIRTH'],
    ['1992-02-02', 'DATE_OF_BIRTH'], ['DEMO-4821', 'OTHER_SENSITIVE'], ['DEMO-4822', 'OTHER_SENSITIVE']]) },
  { name: SAMPLE_DOCUMENTS[2].name, annotations: sampleSpans(SAMPLE_DOCUMENTS[2].text, [
    ['Riya', 'PERSON_NAME'], ['Sita', 'PERSON_NAME'], ['DEMO-4822', 'OTHER_SENSITIVE']]) },
] }

function shortType(kind: string) { return kind === 'PERSON_NAME' ? 'Person' : kind.replaceAll('_', ' ').toLowerCase().replace(/^./, c => c.toUpperCase()) }
function fileIcon(name: string) { return name.toLowerCase().endsWith('.json') || name.toLowerCase().endsWith('.jsonl') ? <FileCode2 size={21} /> : <FileText size={21} /> }
function graphLabel(entity?: BatchInspection['entities'][number]) { return entity?.excluded ? 'Source retained' : entity?.alias || 'Unknown' }
function percent(numerator: number, denominator: number) { return denominator ? `${Math.round(100 * numerator / denominator)}%` : '—' }

function HighlightedSource({ document }: { document: BatchDocument }) {
  const chunks: React.ReactNode[] = []
  let cursor = 0
  document.matches.forEach((match, index) => {
    chunks.push(document.text.slice(cursor, match.start))
    chunks.push(<mark key={`${match.start}-${index}`} className={match.applied ? '' : 'excluded'}
      title={match.applied ? `${shortType(match.kind)} → ${match.replacement}` : `${shortType(match.kind)} retained after reviewer exclusion`}>{match.source}</mark>)
    cursor = match.end
  })
  chunks.push(document.text.slice(cursor))
  return <pre>{chunks}</pre>
}

export default function BatchDemo() {
  const [step, setStep] = useState<Step>('upload')
  const [resultTab, setResultTab] = useState<ResultTab>('documents')
  const [files, setFiles] = useState<BatchUpload[]>([])
  const [token, setToken] = useState('')
  const [acknowledged, setAcknowledged] = useState(false)
  const [busy, setBusy] = useState(false)
  const [reading, setReading] = useState(false)
  const [dragging, setDragging] = useState(false)
  const [error, setError] = useState('')
  const [inspection, setInspection] = useState<BatchInspection | null>(null)
  const [referenceManifest, setReferenceManifest] = useState<BatchReferenceManifest | null>(null)
  const [referenceAttested, setReferenceAttested] = useState(false)
  const [manualNames, setManualNames] = useState<string[]>([])
  const [manualInput, setManualInput] = useState('')
  const [aliasOverrides, setAliasOverrides] = useState<Record<string, string>>({})
  const [excludedIds, setExcludedIds] = useState<string[]>([])
  const [exclusionAcknowledged, setExclusionAcknowledged] = useState(false)
  const [selectedDoc, setSelectedDoc] = useState('')
  const sequence = useRef(0)
  const request = useRef<AbortController | null>(null)
  const intakeEpoch = useRef(0)

  useEffect(() => () => { request.current?.abort(); intakeEpoch.current += 1 }, [])

  function resetReview() { setInspection(null); setReferenceManifest(null); setReferenceAttested(false); setManualNames([]); setAliasOverrides({}); setExcludedIds([]); setExclusionAcknowledged(false); setStep('upload'); setError('') }

  async function addFiles(selected: File[], replace = false) {
    if (!selected.length) return false
    const epoch = ++intakeEpoch.current
    setReading(true)
    setError('')
    try {
      const existing = replace ? [] : files
      if (selected.length > 3 || existing.length + selected.length > 3) throw new DemoInspectionFailure('A demo batch holds two or three files. Remove a file before adding more.')
      const added = await Promise.all(selected.map(file => readBatchFile(file, `file_${++sequence.current}`)))
      if (epoch !== intakeEpoch.current) return false
      if (new Set([...existing, ...added].map(item => item.name.toLowerCase())).size !== existing.length + added.length) throw new DemoInspectionFailure('Each file in the batch needs a distinct filename.')
      if ([...existing, ...added].reduce((sum, item) => sum + item.size, 0) > 300_000) throw new DemoInspectionFailure('The entire synthetic batch must be 300 KB or less.')
      setFiles(current => [...(replace ? [] : current), ...added])
      setInspection(null)
      setReferenceManifest(null)
      setReferenceAttested(false)
      setExcludedIds([])
      setExclusionAcknowledged(false)
      return true
    } catch (cause) { if (epoch === intakeEpoch.current) setError(cause instanceof Error ? cause.message : 'Could not read the selected files.'); return false }
    finally { if (epoch === intakeEpoch.current) setReading(false) }
  }

  async function loadSample() {
    ++intakeEpoch.current
    setFiles([])
    resetReview()
    if (await addFiles(SAMPLES, true)) setReferenceManifest(SAMPLE_REFERENCE)
  }

  async function loadReference(file: File) {
    const epoch = intakeEpoch.current
    setError('')
    try {
      const manifest = await readBatchReferenceManifest(file, files)
      if (epoch === intakeEpoch.current) { setReferenceManifest(manifest); setReferenceAttested(false) }
    } catch (cause) { if (epoch === intakeEpoch.current) setError(cause instanceof Error ? cause.message : 'Could not read reference labels.') }
  }

  async function inspect(nextNames = manualNames, nextAliases = aliasOverrides, nextStep: Step = 'detect', nextExclusions = excludedIds) {
    if (busy || !acknowledged || !token.trim()) { setError('Enter a processor token and confirm the batch is synthetic.'); return }
    if (nextStep === 'results' && nextExclusions.length && !exclusionAcknowledged) {
      setError('Confirm that excluded findings are false positives and will remain in the candidate preview.'); return
    }
    if (nextStep === 'results' && referenceManifest?.basis === 'REVIEWER_ATTESTED_EXHAUSTIVE' && !referenceAttested) {
      setError('Confirm that the uploaded reference labels are complete before measuring agreement.'); return
    }
    const controller = new AbortController()
    request.current = controller
    setBusy(true)
    setError('')
    try {
      const value = await inspectSyntheticBatch({ apiBase: API_BASE, token, files, manualNames: nextNames, aliasOverrides: nextAliases,
        reviewExclusions: Object.fromEntries(nextExclusions.map(id => [id, 'FALSE_POSITIVE_CONFIRMED' as const])),
        referenceManifest: referenceManifest?.basis === 'CURATED_SYNTHETIC_SAMPLE' || referenceAttested ? referenceManifest : null,
        signal: controller.signal })
      if (request.current !== controller || controller.signal.aborted) return
      setInspection(value)
      setManualNames(nextNames)
      setAliasOverrides(nextAliases)
      setExcludedIds(nextExclusions)
      setSelectedDoc(value.documents[0]?.id || '')
      setStep(nextStep)
    } catch (cause) {
      if (request.current === controller && !controller.signal.aborted) setError(cause instanceof Error ? cause.message : 'Batch inspection failed.')
    } finally { if (request.current === controller) { request.current = null; setBusy(false) } }
  }

  async function addManualName() {
    const name = manualInput.trim()
    if (!/^[A-Za-z][A-Za-z .'-]{1,79}$/.test(name)) { setError('Enter a person name of 2–80 letters and simple punctuation.'); return }
    if (manualNames.some(item => item.toLowerCase() === name.toLowerCase())) { setError('This name is already in the manual list.'); return }
    if (!inspection?.documents.some(document => new RegExp(`(?<!\\w)${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?!\\w)`, 'i').test(document.text))) {
      setError('That name was not found in the current files. Enter the exact spelling shown in a document.')
      return
    }
    setManualInput('')
    // Entity IDs are recomputed when the set of names changes. Clear pending
    // overrides, then let reviewers edit aliases on the refreshed detection.
    setExcludedIds([])
    setExclusionAcknowledged(false)
    await inspect([...manualNames, name], {}, 'detect', [])
  }

  const selected = inspection?.documents.find(doc => doc.id === selectedDoc) || inspection?.documents[0]
  const visibleEntities = inspection?.entities.filter(item => item.mentions > 0) || []
  const byId = new Map(visibleEntities.map(item => [item.id, item]))
  const hasPendingAliases = inspection?.entities.some(entity => aliasOverrides[entity.id] !== undefined && aliasOverrides[entity.id] !== entity.alias) || false
  const hasPendingExclusions = inspection?.entities.some(entity => excludedIds.includes(entity.id) !== entity.excluded) || false

  function toggleExclusion(entityId: string) {
    setExcludedIds(current => current.includes(entityId) ? current.filter(id => id !== entityId) : [...current, entityId])
    setAliasOverrides(current => { const next = { ...current }; delete next[entityId]; return next })
    setExclusionAcknowledged(false)
  }

  return <div className="batch-app">
    <aside className="batch-sidebar" aria-label="Workbench navigation">
      <div className="brand"><div className="brand-mark"><Fingerprint size={23} strokeWidth={2.3} /></div><div><strong>AnonFlow</strong><span>Privacy workbench</span></div></div>
      <div className="sidebar-section-label">WORKSPACE</div>
      <nav className="step-nav" aria-label="Demo workflow">
        {([['upload', '01', 'Upload batch'], ['detect', '02', 'Detection review'], ['results', '03', 'Results & verification']] as const).map(([key, number, label]) => {
          const enabled = key === 'upload' || (key === 'detect' && inspection !== null) || (key === 'results' && step === 'results')
          return <button key={key} type="button" className={`step-link ${step === key ? 'active' : ''}`} disabled={!enabled} onClick={() => setStep(key)} aria-current={step === key ? 'step' : undefined}><span>{number}</span>{label}{step === key && <ChevronRight size={16} />}</button>
        })}
      </nav>
      <div className="sidebar-divider" />
      <div className="sidebar-section-label">CURRENT SESSION</div>
      <div className="session-card"><Files size={19} /><div><strong>{files.length ? `${files.length} files staged` : 'No batch yet'}</strong><span>Ephemeral synthetic preview</span></div></div>
      <div className="sidebar-bottom"><div className="sidebar-note"><LockKeyhole size={17} /><span>No release or export is available in this demo.</span></div><a href="?mode=advanced">Developer controls <ArrowRight size={14} /></a></div>
    </aside>

    <main className="batch-main">
      <header className="topbar"><div className="breadcrumb">Workbench <ChevronRight size={14} /> <strong>{step === 'upload' ? 'Upload batch' : step === 'detect' ? 'Detection review' : 'Results & verification'}</strong></div><span className="environment-badge"><span /> SYNTHETIC DEMO</span></header>
      <div className="batch-content">
        {step === 'upload' && <>
          <div className="page-heading"><div><p className="overline">01 / INTAKE</p><h1>Start with your dataset.</h1><p>Bring two or three synthetic documents together. We’ll trace sensitive mentions across files, then give you a reviewable candidate—not an anonymity claim.</p></div><div className="heading-icon"><UploadCloud size={29} /></div></div>
          <div className="flow-strip"><div className="current"><span>1</span><strong>Upload</strong><small>Choose a batch</small></div><div className="flow-line" /><div><span>2</span><strong>Detect</strong><small>Review matches</small></div><div className="flow-line" /><div><span>3</span><strong>Verify</strong><small>Compare & assess</small></div></div>
          <section className="batch-card intake-card" aria-labelledby="intake-heading"><div className="card-header"><div><p className="overline">BATCH INPUT</p><h2 id="intake-heading">Your documents <span className="count-pill">{files.length}/3</span></h2></div><span className="quiet-tag">Up to 300 KB total</span></div>
            <div className={`drop-zone ${dragging ? 'dragging' : ''}`} onDragEnter={event => { event.preventDefault(); setDragging(true) }} onDragOver={event => event.preventDefault()} onDragLeave={event => { event.preventDefault(); setDragging(false) }} onDrop={event => { event.preventDefault(); setDragging(false); void addFiles(Array.from(event.dataTransfer.files)) }}>
              <div className="drop-icon"><UploadCloud size={25} /></div><strong>Drop your synthetic files here</strong><span>or select documents from your computer</span><label className="file-button">Browse files<input type="file" multiple accept=".txt,.csv,.json,.jsonl,.pdf" onChange={event => { void addFiles(Array.from(event.target.files || [])); event.target.value = '' }} /></label><small>TXT, CSV, JSON, JSONL, text-based PDF · 100 KB per file</small>
            </div>
            <div className="sample-bar"><div><Sparkles size={18} /><span>Want to see the workflow first? Load a fictional three-file case.</span></div><button type="button" className="text-button" onClick={() => void loadSample()} disabled={busy || reading}>Use sample batch <ArrowRight size={16} /></button></div>
            {files.length > 0 && <div className="staged-files" aria-label="Staged documents">{files.map((file, index) => <div className="staged-file" key={file.id}><span className="file-type-icon">{fileIcon(file.name)}</span><div><strong>{file.name}</strong><span>{Math.max(1, Math.ceil(file.size / 1024))} KB · Document {index + 1}</span></div><span className="ready-pill"><Check size={13} /> Ready</span><button type="button" className="icon-button" aria-label={`Remove ${file.name}`} onClick={() => { ++intakeEpoch.current; setFiles(current => current.filter(item => item.id !== file.id)); resetReview() }}><X size={17} /></button></div>)}</div>}
          </section>
          <section className="batch-card access-card" aria-labelledby="access-heading"><div><p className="overline">DEMO ACCESS</p><h2 id="access-heading">Before you continue</h2><p>This local development service receives submitted content in memory for inspection. It cannot verify that a file is synthetic.</p></div><div className="access-form"><label htmlFor="processor-token">Processor access token</label><input id="processor-token" type="password" autoComplete="off" spellCheck={false} value={token} onChange={event => setToken(event.target.value)} placeholder="Paste the token from the demo launcher" /><label className="check-label"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} /><span>I confirm all files are fictional demo data. I understand the detector may miss sensitive content.</span></label></div></section>
          <div className="page-actions"><p><ShieldCheck size={16} /> No production data · No automatic release</p><button type="button" className="primary-button" disabled={files.length < 2 || !acknowledged || !token.trim() || reading || busy} onClick={() => void inspect([], {}, 'detect')}>{busy ? 'Inspecting batch…' : 'Analyze batch'} <ArrowRight size={18} /></button></div>
        </>}

        {step === 'detect' && inspection && <>
          <div className="page-heading"><div><p className="overline">02 / DETECTION REVIEW</p><h1>Know what was found.</h1><p>Inspect the rule matches and consistent aliases across the batch. Add a missed name before opening the candidate comparison.</p></div><div className="heading-icon"><Search size={29} /></div></div>
          <div className="metrics-grid"><div className="metric-card"><span>Documents inspected</span><strong>{inspection.summary.files}</strong><small>One connected batch</small></div><div className="metric-card"><span>Detected mentions</span><strong>{inspection.summary.detectedMentions}</strong><small>Proposed transformations</small></div><div className="metric-card"><span>Unique signals</span><strong>{visibleEntities.length}</strong><small>Across all documents</small></div><div className="metric-card"><span>Explicit links</span><strong>{inspection.summary.explicitRelationships}</strong><small>Email headers only</small></div></div>
          <div className="review-grid"><section className="batch-card entity-review"><div className="card-header"><div><p className="overline">ENTITY REGISTER</p><h2>Detected identities & signals</h2></div><span className="quiet-tag">{visibleEntities.length} entities</span></div><div className="table-scroll"><table><thead><tr><th>Source value</th><th>Type</th><th>Mentions</th><th>Proposed replacement</th><th>Review decision</th></tr></thead><tbody>{visibleEntities.map(entity => { const excluded = excludedIds.includes(entity.id); const suppressible = SUPPRESSIBLE_KINDS.has(entity.kind); return <tr key={entity.id} className={excluded ? 'entity-excluded' : ''}><td className="source-cell">{entity.source}</td><td><span className="type-pill">{shortType(entity.kind)}</span></td><td>{entity.mentions}</td><td>{entity.kind === 'PERSON_NAME' ? <input className="alias-input" aria-label={`Replacement for ${entity.source}`} value={aliasOverrides[entity.id] ?? entity.alias} maxLength={entity.source.length} disabled={excluded} onChange={event => setAliasOverrides(current => ({ ...current, [entity.id]: event.target.value }))} /> : <code>{entity.alias}</code>}</td><td><button type="button" className={`decision-button ${excluded ? 'excluded' : ''}`} disabled={!suppressible || busy} title={suppressible ? 'Review this signal across every file' : 'Critical or unsupported categories cannot be excluded in this demo'} aria-label={`${excluded ? 'Restore' : 'Exclude'} ${entity.source}`} onClick={() => toggleExclusion(entity.id)}>{excluded ? 'Restore' : 'Exclude'}</button></td></tr> })}</tbody></table></div>{visibleEntities.length === 0 && <p className="empty-note">No rule matches were found. That does not establish that the files contain no sensitive information.</p>}<div className="card-footnote"><CircleAlert size={16} /> Excluding a signal keeps every matched source value in the candidate. Critical and unsupported categories cannot be excluded. Names in arbitrary prose may still be missed.</div></section>
            <aside className="batch-card review-side"><p className="overline">HUMAN-IN-THE-LOOP</p><h2>Found a missed name?</h2><p>Add the exact person name. We’ll rescan all documents and keep the replacement consistent across files.</p><div className="inline-form"><label htmlFor="manual-name">Person name</label><input id="manual-name" value={manualInput} onChange={event => setManualInput(event.target.value)} placeholder="e.g. Tara" onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); void addManualName() } }} /><button type="button" className="secondary-button" onClick={() => void addManualName()} disabled={busy || !manualInput.trim()}><Plus size={16} /> Add & rescan</button></div>{manualNames.length > 0 && <div className="manual-list">Added: {manualNames.join(', ')}</div>}<div className="review-hint"><ShieldCheck size={19} /><span>Equal-character-length aliases are proposed for names. This does not establish PDF layout fidelity or anonymity.</span></div></aside></div>
          {excludedIds.length > 0 && <div className="exclusion-notice"><CircleAlert size={19} /><label className="check-label"><input type="checkbox" checked={exclusionAcknowledged} onChange={event => setExclusionAcknowledged(event.target.checked)} /><span>I confirm the {excludedIds.length} excluded {excludedIds.length === 1 ? 'signal is' : 'signals are'} a false positive for this synthetic batch. Its source values will remain visible in the proposed candidate.</span></label></div>}
          <section className="batch-card reference-card" aria-labelledby="reference-heading"><div className="card-header"><div><p className="overline">OPTIONAL MEASUREMENT</p><h2 id="reference-heading">Reference labels</h2></div><span className="quiet-tag">{referenceManifest ? 'Attached' : 'Not supplied'}</span></div>
            <p>To measure exact-span agreement, attach a complete annotation manifest for all staged files. The built-in sample includes demo-authored labels. Uploaded labels are reviewer-attested, not independently verified.</p>
            <div className="reference-actions"><label className="file-button">Attach labels JSON<input type="file" accept=".json" onChange={event => { const file = event.target.files?.[0]; if (file) void loadReference(file); event.target.value = '' }} /></label>{referenceManifest && <button type="button" className="text-button" onClick={() => { setReferenceManifest(null); setReferenceAttested(false) }}>Remove labels</button>}</div>
            {referenceManifest?.basis === 'REVIEWER_ATTESTED_EXHAUSTIVE' && <label className="check-label reference-attestation"><input type="checkbox" checked={referenceAttested} onChange={event => setReferenceAttested(event.target.checked)} /><span>I reviewed the synthetic batch and attest that these labels cover every relevant sensitive span for this measurement.</span></label>}
            <details><summary>Annotation file format</summary><pre>{'{"schema_version":"batch-reference-v1","documents":[{"name":"file.txt","annotations":[{"start":0,"end":4,"entity_type":"PERSON_NAME"}]}]}'}</pre><small>List every staged filename once, including files with zero labels. Offsets are half-open Unicode character positions in source text; for PDFs, they refer to extracted text shown here.</small></details>
          </section>
          <section className="batch-card document-coverage"><div className="card-header"><div><p className="overline">FILE COVERAGE</p><h2>What the detector reviewed</h2></div></div><div className="coverage-list">{inspection.documents.map(document => <div key={document.id}><span className="file-type-icon">{fileIcon(document.name)}</span><div><strong>{document.name}</strong><span>{document.kind === 'pdf' ? 'Selectable PDF text extracted; original PDF not rewritten' : 'Source text reviewed'}</span></div><strong>{document.matches.length} matches</strong></div>)}</div></section>
          <div className="page-actions"><button type="button" className="back-button" onClick={() => setStep('upload')}><ArrowLeft size={17} /> Edit batch</button><button type="button" className="primary-button" disabled={busy} onClick={() => void inspect(manualNames, aliasOverrides, 'results', excludedIds)}>{busy ? 'Applying changes…' : hasPendingAliases || hasPendingExclusions ? 'Apply decisions & review candidate' : 'Review candidate'} <ArrowRight size={18} /></button></div>
        </>}

        {step === 'results' && inspection && <>
          <div className="page-heading"><div><p className="overline">03 / RESULTS & VERIFICATION</p><h1>Review the proposed output.</h1><p>Trace every replacement, inspect explicit relationships, and understand what this run did—and did not—prove.</p></div><div className="heading-icon"><ShieldCheck size={29} /></div></div>
          <div className="result-alert"><CircleAlert size={21} /><div><strong>Review required · not anonymous or export-ready</strong><span>This is a synthetic text preview. Detector completeness, privacy risk, PDF layout, and release eligibility are not certified.</span></div></div>
          <div className="metrics-grid"><div className="metric-card"><span>Files processed</span><strong>{inspection.summary.files}</strong><small>In this batch</small></div><div className="metric-card"><span>Mentions transformed</span><strong>{inspection.summary.transformedMentions}</strong><small>Detected spans only</small></div><div className="metric-card"><span>Unique signals</span><strong>{visibleEntities.length}</strong><small>Tracked across files</small></div><div className="metric-card"><span>Residual rule matches</span><strong>{inspection.verification.knownRuleResidualMatches}</strong><small>Requires human review</small></div></div>
          {inspection.summary.suppressedMentions > 0 && <div className="result-alert exclusion-result"><CircleAlert size={19} /><div><strong>{inspection.summary.suppressedMentions} detected {inspection.summary.suppressedMentions === 1 ? 'mention was' : 'mentions were'} retained after reviewer exclusion</strong><span>Those original values remain in the proposed text. This preview cannot be exported or treated as anonymized.</span></div></div>}
          <div className="result-tabs" role="tablist" aria-label="Batch result views">{([['documents', 'Documents', Files], ['relationships', 'Entities & relationships', Link2], ['verification', 'Verification scorecard', ShieldCheck]] as const).map(([key, label, Icon]) => <button key={key} type="button" role="tab" aria-selected={resultTab === key} className={resultTab === key ? 'selected' : ''} onClick={() => setResultTab(key)}><Icon size={17} /> {label}</button>)}</div>
          {resultTab === 'documents' && selected && <section className="batch-card result-panel"><div className="card-header"><div><p className="overline">DOCUMENT COMPARISON</p><h2>Before & after, side by side</h2></div><span className="quiet-tag">{selected.matches.length} matches in this file</span></div><div className="doc-selector" role="tablist" aria-label="Documents">{inspection.documents.map(document => <button type="button" role="tab" aria-selected={selected.id === document.id} className={selected.id === document.id ? 'selected' : ''} key={document.id} onClick={() => setSelectedDoc(document.id)}>{fileIcon(document.name)}<span>{document.name}</span><small>{document.matches.length}</small></button>)}</div>{selected.kind === 'pdf' && <div className="pdf-note"><CircleAlert size={16} /> This is extracted text, not an edited PDF. Page layout, annotations, embedded images, and metadata have not been checked.</div>}<div className="comparison"><div><div className="pane-heading"><span>ORIGINAL · SYNTHETIC INPUT</span><span>{selected.matches.length} highlighted matches</span></div><div className="document-pane"><HighlightedSource document={selected} /></div></div><div className="compare-divider"><ArrowDown size={17} /></div><div><div className="pane-heading"><span>PROPOSED TEXT CANDIDATE</span><span>Not exportable</span></div><div className="document-pane candidate"><pre>{selected.candidateText}</pre></div></div></div><div className="card-footnote"><CircleAlert size={16} /> Highlighting shows detected spans only. Unmarked content has not been certified safe.</div></section>}
          {resultTab === 'relationships' && <section className="batch-card result-panel"><div className="card-header"><div><p className="overline">CROSS-DOCUMENT CONTEXT</p><h2>Entities & relationships</h2></div><span className="quiet-tag">Explicit evidence only</span></div><p className="panel-intro">A link appears only when a From/To/Cc header explicitly connected two people. Surrogates are shown for transformed names; excluded names are marked as retained without displaying their source in this graph.</p><div className="relationship-list">{inspection.relationships.length ? inspection.relationships.map((relationship, index) => { const source = byId.get(relationship.sourceId), target = byId.get(relationship.targetId); return <div className="relationship-row" key={`${relationship.documentId}-${index}`}><div className="relation-person"><span className="avatar">{graphLabel(source).slice(0, 1).toUpperCase()}</span><div><strong>{graphLabel(source)}</strong><small>Sender</small></div></div><div className="relation-verb"><span>EMAILED <ArrowRight size={16} /></span><small>{inspection.documents.find(doc => doc.id === relationship.documentId)?.name}</small></div><div className="relation-person"><span className="avatar purple">{graphLabel(target).slice(0, 1).toUpperCase()}</span><div><strong>{graphLabel(target)}</strong><small>Recipient</small></div></div></div> }) : <div className="empty-note">No explicit mail-header relationship was found. No relationship is inferred from proximity alone.</div>}</div><div className="entity-chips">{visibleEntities.filter(entity => entity.kind === 'PERSON_NAME').map(entity => <span key={entity.id}><Fingerprint size={15} /> {graphLabel(entity)} <small>· {entity.mentions} mentions</small></span>)}</div></section>}
          {resultTab === 'verification' && <section className="batch-card result-panel"><div className="card-header"><div><p className="overline">EVIDENCE, NOT A VANITY SCORE</p><h2>Verification scorecard</h2></div><span className="status-pill">REVIEW REQUIRED</span></div>
            <p className="panel-intro">These are observable checks for this run. Reference-label agreement appears only when complete synthetic labels were supplied; it does not measure anonymity or performance on other datasets.</p>
            {inspection.verification.annotationScore ? (() => { const score = inspection.verification.annotationScore; return <div className="annotation-panel"><div className="annotation-heading"><div><span className="overline">EXACT-SPAN AGREEMENT</span><h3>Reviewed candidate vs reference labels</h3></div><span className="quiet-tag">{score.basis === 'CURATED_SYNTHETIC_SAMPLE' ? 'Demo-authored sample' : 'Reviewer-attested labels'}</span></div>
              <div className="annotation-metrics"><div><span>Precision on these labels</span><strong>{percent(score.exact.truePositives, score.exact.truePositives + score.exact.falsePositives)}</strong><small>{score.exact.falsePositives} unmatched predictions</small></div><div><span>Recall on these labels</span><strong>{percent(score.exact.truePositives, score.exact.truePositives + score.exact.falseNegatives)}</strong><small>{score.exact.falseNegatives} missed reference spans</small></div><div><span>Labelled spans</span><strong>{score.goldAnnotations}</strong><small>Across {score.labelledDocuments} documents</small></div></div>
              <div className="table-scroll"><table><thead><tr><th>Reference category</th><th>Matched</th><th>False positives</th><th>Missed</th></tr></thead><tbody>{Object.entries(score.perType).sort(([a], [b]) => a.localeCompare(b)).map(([kind, counts]) => <tr key={kind}><td>{shortType(kind)}</td><td>{counts.truePositives}</td><td>{counts.falsePositives}</td><td>{counts.falseNegatives}</td></tr>)}{Object.keys(score.perType).length === 0 && <tr><td colSpan={4}>No labelled or predicted spans. Precision and recall are undefined.</td></tr>}</tbody></table></div>
              <p className="annotation-caveat">Counts include manual corrections made before this review. They depend on the supplied labels being complete and are not an independent holdout test, a residual-disclosure test, or release approval.</p>
            </div> })() : <div className="unmeasured-panel"><strong>Precision and recall not measured</strong><span>No complete reference-label set was attached. Return to Detection review to add one; zero residual rule matches cannot substitute for labelled ground truth.</span></div>}
            <div className="scorecard-list">{inspection.verification.checks.map((check, index) => <div key={`${check.name}-${index}`}><span className={`check-status status-${check.status.toLowerCase()}`}>{check.status === 'PASS' ? <Check size={15} /> : <CircleAlert size={15} />}{check.status.replaceAll('_', ' ')}</span><div><strong>{check.name}</strong><p>{check.detail}</p></div></div>)}</div><div className="limitations-panel"><h3>What remains unproven</h3><ul>{inspection.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></div></section>}
          <div className="page-actions"><button type="button" className="back-button" onClick={() => { setStep('detect'); setResultTab('documents') }}><ArrowLeft size={17} /> Back to detection</button><span className="no-export"><LockKeyhole size={16} /> Export disabled for this development preview</span></div>
        </>}
        {error && <div className="batch-error" role="alert"><CircleAlert size={19} /><span>{error}</span><button type="button" aria-label="Dismiss error" onClick={() => setError('')}><X size={17} /></button></div>}
        {busy && <div className="batch-working" role="status"><RefreshCw size={18} className="spinning" /> Inspecting synthetic files… <button type="button" onClick={() => request.current?.abort()}>Cancel</button></div>}
      </div>
    </main>
  </div>
}
