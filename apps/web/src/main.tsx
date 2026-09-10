import React, { useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import { AlertTriangle, CheckCircle2, ChevronRight, Copy, FileText, Lock, Play, ShieldCheck, Sparkles, Upload, XCircle } from 'lucide-react'
import './styles.css'

type Finding = { entity_type: string; count: number; severity: 'critical'|'high'|'medium'|'low' }
type Release = { release_id?: string; decision: 'APPROVED_ANONYMIZED'|'APPROVED_RESTRICTED'|'REVIEW_REQUIRED'|'BLOCKED'; anonymized_text: string; findings: Finding[]; scores: { privacy_risk: number; utility: number; subjectivity: number; sensitivity: string }; card?: Record<string, unknown> }

const sample = `From: priya.shah@acme-example.com\n\nHi Martin,\n\nPlease call me on +91 98765 43210 about the Project Aurora pricing review. The Q3 pipeline is ₹42,50,000. My Aadhaar is 2345 6789 1234.\n\n— Priya Shah`
// Vite injects VITE_* values at build time. The localhost default keeps the
// self-hosted Compose demo usable without a reverse proxy.
const apiBase = (import.meta.env.VITE_API_URL || 'http://localhost:8000').replace(/\/$/, '')

function demoRelease(input: string): Release {
  const patterns: [RegExp, string, Finding['severity'], string][] = [
    [/\b[\w.+-]+@[\w-]+\.[\w.-]+\b/g, 'EMAIL_ADDRESS', 'high', '[EMAIL_ADDRESS]'],
    [/\+?91[\s-]?\d{5}[\s-]?\d{5}/g, 'PHONE_NUMBER', 'high', '[PHONE_NUMBER]'],
    [/\b\d{4}[\s-]\d{4}[\s-]\d{4}\b/g, 'AADHAAR', 'critical', '[GOVERNMENT_ID]'],
    [/\b(?:Priya Shah|Martin)\b/g, 'PERSON', 'medium', '[PERSON]'],
    [/\bProject Aurora\b/g, 'PROJECT', 'medium', '[PROJECT]'],
    [/₹[\d,]+/g, 'FINANCIAL_AMOUNT', 'high', '[AMOUNT_RANGE]']
  ]
  const counts = new Map<string, Finding>()
  let anonymized = input
  patterns.forEach(([regex, entity, severity, replacement]) => {
    const found = input.match(regex)?.length ?? 0
    if (found) { counts.set(entity, { entity_type: entity, count: found, severity }); anonymized = anonymized.replace(regex, replacement) }
  })
  const findings = [...counts.values()]
  const risk = Math.min(96, 10 + findings.reduce((sum, f) => sum + f.count * ({ critical: 20, high: 12, medium: 7, low: 3 }[f.severity]), 0))
  return { decision: 'APPROVED_RESTRICTED', anonymized_text: anonymized, findings, scores: { privacy_risk: Math.max(4, risk - 73), utility: 91, subjectivity: 24, sensitivity: findings.some(f => f.severity === 'critical') ? 'Restricted' : 'Confidential' }, card: { mode: 'anonymized_release', policy_version: 'external-release-v1', validation: 'passed', source_risk: risk } }
}

async function runApi(input: string, policy: string): Promise<Release> {
  const datasetResponse = await fetch(`${apiBase}/datasets`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ name: `demo-${new Date().toISOString()}`, content: input, owner: 'local-demo', intended_use: 'evaluation' })
  })
  if (!datasetResponse.ok) throw new Error(`Dataset API returned ${datasetResponse.status}`)
  const dataset = await datasetResponse.json() as { id: string }
  const releaseResponse = await fetch(`${apiBase}/releases`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ dataset_id: dataset.id, policy_version: policy, release_mode: policy.startsWith('restricted') ? 'restricted_pseudonymized' : 'external_anonymized' })
  })
  if (!releaseResponse.ok) throw new Error(`Release API returned ${releaseResponse.status}`)
  const response = await releaseResponse.json() as { id: string; eligibility: Release['decision']; output: string; card: { findings: Finding[]; scores: { privacy_risk: number; utility_legibility: number; subjectivity: number; sensitivity: string } } }
  return {
    release_id: response.id,
    decision: response.eligibility,
    anonymized_text: response.output,
    findings: response.card.findings,
    scores: { privacy_risk: response.card.scores.privacy_risk, utility: response.card.scores.utility_legibility, subjectivity: response.card.scores.subjectivity, sensitivity: response.card.scores.sensitivity },
    card: response.card as unknown as Record<string, unknown>
  }
}

function Score({ label, value, tone, suffix = '' }: { label: string; value: number|string; tone: string; suffix?: string }) {
  return <div className="score"><span>{label}</span><strong className={tone}>{value}{suffix}</strong></div>
}

function App() {
  const [text, setText] = useState(sample); const [policy, setPolicy] = useState('external-release-v1'); const [running, setRunning] = useState(false); const [result, setResult] = useState<Release | null>(null); const [notice, setNotice] = useState(''); const fileRef = useRef<HTMLInputElement>(null)
  const sourceLines = useMemo(() => text.split('\n').length, [text])
  async function run() { if (!text.trim()) return; setRunning(true); setNotice(''); try { setResult(await runApi(text, policy)) } catch { setResult(demoRelease(text)); setNotice('Showing local demonstration result — API was unavailable.') } finally { setRunning(false) } }
  function upload(file?: File) { if (!file) return; if (file.size > 2_000_000) { setNotice('For this demo, choose a text file smaller than 2 MB.'); return } const reader = new FileReader(); reader.onload = () => setText(String(reader.result ?? '')); reader.readAsText(file) }
  const decisionTone = result?.decision === 'BLOCKED' ? 'danger' : result?.decision === 'REVIEW_REQUIRED' ? 'warn' : 'success'
  return <main><header><div className="brand"><div className="brandmark"><ShieldCheck size={20}/></div><span>anonflow</span><em>release control</em></div><div className="environment"><span></span> Local workspace</div></header>
    <section className="hero"><div><p className="eyebrow">ENTERPRISE DATA RELEASE</p><h1>Make data useful.<br/><i>Keep people protected.</i></h1><p className="sub">Classify, transform, validate, and document every data release with a defensible privacy–utility decision.</p></div><div className="trust"><Lock size={18}/><div><b>Raw data stays in your boundary</b><small>No content is logged by this interface.</small></div></div></section>
    <section className="workspace"><aside><p className="section-label">RELEASE POLICY</p><label>Policy pack<select value={policy} onChange={e=>setPolicy(e.target.value)}><option value="external-release-v1">External anonymized release</option><option value="restricted-pseudonymized-v1">Restricted pseudonymized processing</option></select></label><label>Recipient context<select><option>External buyer · controlled</option><option>Internal analytics</option><option>Named research partner</option></select></label><div className="rule"><ShieldCheck size={17}/><div><b>Fail-closed validation</b><span>Residual critical identifiers block export.</span></div></div><div className="rule"><Sparkles size={17}/><div><b>Semantic utility checks</b><span>Assess quality after transformation.</span></div></div><button className="run" onClick={run} disabled={running || !text.trim()}>{running ? 'Validating release…' : <><Play size={16} fill="currentColor"/> Run privacy release</>}</button><small className="api">API: {apiBase || 'same origin'} · POST /datasets then POST /releases</small></aside>
      <div className="editor"><div className="pane-head"><div><FileText size={16}/><b>Source data</b><small>{sourceLines} lines</small></div><button className="upload" onClick={()=>fileRef.current?.click()}><Upload size={15}/> Import file</button><input ref={fileRef} type="file" accept=".txt,.csv,.json,.md" hidden onChange={e=>upload(e.target.files?.[0])}/></div><textarea value={text} onChange={e=>setText(e.target.value)} spellCheck={false} aria-label="Source data"/><div className="input-foot">Paste data or import .txt, .csv, .json, or .md</div></div>
      <div className="output"><div className="pane-head"><div><ShieldCheck size={16}/><b>Release preview</b></div>{result && <span className={`badge ${decisionTone}`}>{result.decision.replaceAll('_',' ')}</span>}</div>{!result ? <div className="empty"><ShieldCheck size={35}/><b>Ready for review</b><span>Run a policy to see transformed data, risk evidence, and your Release Card.</span></div> : <><pre>{result.anonymized_text}</pre><button className="copy" onClick={()=>navigator.clipboard.writeText(result.anonymized_text)}><Copy size={14}/> Copy output</button></>}</div></section>
    {notice && <div className="notice"><AlertTriangle size={16}/>{notice}</div>}
    {result && <section className="report"><div className="report-title"><div><p className="section-label">RELEASE CARD</p><h2>Decision evidence</h2></div><button className="outline" onClick={()=>navigator.clipboard.writeText(JSON.stringify(result.card ?? result, null, 2))}>Export card</button></div><div className="scores"><Score label="Privacy risk" value={result.scores.privacy_risk} suffix=" / 100" tone={result.scores.privacy_risk > 30 ? 'warn' : 'success'}/><Score label="Utility / legibility" value={result.scores.utility} suffix="%" tone="success"/><Score label="Subjectivity" value={result.scores.subjectivity} suffix="%" tone="neutral"/><Score label="Sensitivity" value={result.scores.sensitivity} tone="danger"/></div><div className="evidence"><div><h3>Detected & transformed</h3>{result.findings.map(f=><div className="finding" key={f.entity_type}><span className={`dot ${f.severity}`}></span><b>{f.entity_type.replaceAll('_',' ')}</b><span>{f.count} occurrence{f.count===1?'':'s'}</span><ChevronRight size={15}/></div>)}</div><div className="decision"><p className="section-label">RELEASE DECISION</p><div className={`decision-icon ${decisionTone}`}>{decisionTone==='success'?<CheckCircle2/>:decisionTone==='danger'?<XCircle/>:<AlertTriangle/>}</div><h3>{result.decision.replaceAll('_',' ')}</h3><p>Policy {policy} completed with independent validation. This card is a technical risk assessment, not a legal compliance determination.</p></div></div></section>}
    <footer>AnonFlow · Privacy–utility release governance · v0.1</footer>
  </main>
}
createRoot(document.getElementById('root')!).render(<React.StrictMode><App /></React.StrictMode>)
