import React, { useEffect, useRef, useState } from 'react'
import { ArrowDown, ArrowLeft, ArrowRight, Check, ChevronRight, CircleAlert, Download, FileCode2, FileText,
  Files, Fingerprint, FlaskConical, ImageIcon, Link2, LockKeyhole, Plus, RefreshCw, Search, ShieldCheck,
  Sparkles, UploadCloud, X, ZoomIn, ZoomOut } from 'lucide-react'
import { inspectSyntheticBatch, readBatchFile, readBatchReferenceManifest, type BatchDocument, type BatchInspection,
  type BatchCoordinateCorrection, type BatchManualFinding, type BatchReferenceManifest, type BatchReferenceSpan, type BatchUpload,
  type EntityGraphEvidence, BATCH_MAX_TOTAL_BYTES, DemoInspectionFailure } from './api'
import { downloadDemoCandidate } from './demo-download'
import { RelationshipGraph } from './relationship-graph'
import './batch.css'

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const SUPPRESSIBLE_KINDS = new Set(['PERSON_NAME', 'EMAIL', 'PHONE', 'IP_ADDRESS'])
const MANUAL_FINDING_OPTIONS: { kind: BatchManualFinding['kind']; label: string }[] = [
  { kind: 'OTHER_SENSITIVE', label: 'Other sensitive' }, { kind: 'BUSINESS_CONFIDENTIAL', label: 'Business confidential' },
  { kind: 'QUASI_IDENTIFIER', label: 'Quasi-identifier' }, { kind: 'GOVERNMENT_ID', label: 'Government ID' },
  { kind: 'DATE_OF_BIRTH', label: 'Date of birth' },
]
const MANUAL_FINDING_KINDS = new Set(MANUAL_FINDING_OPTIONS.map(item => item.kind))
type Step = 'upload' | 'detect' | 'results'
type ResultTab = 'documents' | 'relationships' | 'verification'
type ComparisonMode = 'split' | 'original' | 'candidate'
type MediaZoom = 'fit' | 50 | 75 | 100 | 125 | 150 | 200
const MEDIA_ZOOMS = [50, 75, 100, 125, 150, 200] as const

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
type RegisterGroup = 'all' | 'people' | 'contacts' | 'identifiers' | 'other'
const REGISTER_GROUPS: { id: RegisterGroup; label: string }[] = [
  { id: 'all', label: 'All' }, { id: 'people', label: 'People' }, { id: 'contacts', label: 'Contacts' },
  { id: 'identifiers', label: 'IDs' }, { id: 'other', label: 'Other' },
]
function registerGroup(kind: string): Exclude<RegisterGroup, 'all'> {
  if (kind === 'PERSON_NAME') return 'people'
  if (kind === 'EMAIL' || kind === 'PHONE') return 'contacts'
  if (['GOVERNMENT_ID', 'EMPLOYEE_ID', 'PAN', 'AADHAAR', 'CARD'].includes(kind)) return 'identifiers'
  return 'other'
}
const REGISTER_PAGE_SIZE = 8
const STRATEGY_LABELS: Record<BatchInspection['entities'][number]['strategy'], string> = {
  NAME_LENGTH_MATCH: 'Plausible same-length name', EMAIL_TEST_ADDRESS: 'Reserved .test address',
  PAN_INVALID_TEST: 'PAN-shaped · invalid', US_SSN_INVALID: 'SSN-shaped · invalid',
  NANP_FICTIONAL: 'Fictional US number', OPAQUE_REDACTION: 'Opaque redaction',
  CONTEXTUAL_REVIEW_REF: 'Review-only reference',
  INTERNAL_URL_RESERVED_DOMAIN: 'Reserved .invalid link',
}
function fileIcon(name: string) { return /\.(png|jpe?g)$/i.test(name) ? <ImageIcon size={21} /> :
  name.toLowerCase().endsWith('.json') || name.toLowerCase().endsWith('.jsonl') ? <FileCode2 size={21} /> : <FileText size={21} /> }
function graphLabel(entity?: BatchInspection['entities'][number]) { return entity?.excluded ? 'Source retained' : entity?.alias || 'Unknown' }
function relationLabels(type: BatchInspection['relationships'][number]['type']) {
  return type === 'EMAILED' ? { source: 'Sender', target: 'Recipient', verb: 'EMAILED' } :
    { source: 'Account owner', target: 'Client', verb: 'ACCOUNT OWNER FOR' }
}
function percent(numerator: number, denominator: number) { return denominator ? `${Math.round(100 * numerator / denominator)}%` : '—' }

function FileScorecard({ score, documents, onInspect, onCorrect }: {
  score: NonNullable<BatchInspection['verification']['annotationScore']>; documents: BatchDocument[];
  onInspect: (id: string) => void; onCorrect: (finding: BatchManualFinding) => void
}) {
  return <div className="file-scorecard"><h4>Review by document</h4><p>Exact-span counts show where supplied labels and applied replacements disagree. A miss means a labelled source span is not replaced by an exact same-category match.</p>
    <div className="table-scroll"><table><thead><tr><th>Document</th><th>Matched</th><th>Unmatched predictions</th><th>Missed labels</th><th>Review</th></tr></thead><tbody>{score.perDocument.map(item => {
      const document = documents.find(doc => doc.id === item.id)!
      return <tr key={item.id}><td className="source-cell">{document.name}</td><td>{item.exact.truePositives}</td><td>{item.exact.falsePositives}</td><td>{item.exact.falseNegatives}</td><td><button type="button" className="text-button" onClick={() => onInspect(item.id)}>View comparison <ArrowRight size={14} /></button></td></tr>
    })}</tbody></table></div>
    {score.perDocument.filter(item => item.missed.length > 0).map(item => {
      const document = documents.find(doc => doc.id === item.id)!
      return <details key={item.id} className="missed-file"><summary>{item.missed.length} unmatched reference {item.missed.length === 1 ? 'span' : 'spans'} in {document.name}</summary><ul>{item.missed.map((span, index) => { const value = Array.from(document.text).slice(span.start, span.end).join(''); return <li key={`${span.start}-${span.end}-${span.entity_type}-${index}`}><span className="type-pill">{shortType(span.entity_type)}</span><code>{value}</code><small>Character {span.start + 1}</small>{MANUAL_FINDING_KINDS.has(span.entity_type as BatchManualFinding['kind']) && <button type="button" className="text-button" onClick={() => onCorrect({ value, kind: span.entity_type as BatchManualFinding['kind'] })}>Add correction</button>}</li> })}</ul></details>
    })}
  </div>
}

function HighlightedSource({ document, provenance }: { document: BatchDocument; provenance: EntityGraphEvidence | null }) {
  const target = provenance?.locator.status === 'SUPPORTED' && provenance.locator.kind === 'text_span' ? provenance.locator : null
  const points = new Set([0, document.text.length])
  document.matches.forEach(match => { points.add(match.start); points.add(match.end) })
  if (target) { points.add(target.start); points.add(target.end) }
  const boundaries = [...points].sort((a, b) => a - b)
  return <pre>{boundaries.slice(0, -1).map((start, index) => {
    const end = boundaries[index + 1]; const value = document.text.slice(start, end)
    const match = document.matches.find(item => item.start <= start && item.end >= end)
    const targeted = target && target.start <= start && target.end >= end
    if (!match && !targeted) return <React.Fragment key={`${start}-${end}`}>{value}</React.Fragment>
    const classes = [match && !match.applied ? 'excluded' : '', targeted ? 'provenance-target' : ''].filter(Boolean).join(' ')
    const title = targeted ? `Graph evidence: lines ${target!.lineStart}${target!.lineEnd === target!.lineStart ? '' : `–${target!.lineEnd}`}` :
      (match?.applied ? `${shortType(match.kind)} → ${match.replacement}` : `${shortType(match!.kind)} retained after reviewer exclusion`)
    return <mark key={`${start}-${end}`} className={classes} data-provenance-target={targeted || undefined} tabIndex={targeted ? -1 : undefined} title={title}>{value}</mark>
  })}</pre>
}

function MediaPages({ document, candidate, zoom, pending = [], provenance = null, onDraw }: { document: BatchDocument; candidate: boolean; zoom: MediaZoom;
  pending?: BatchCoordinateCorrection[]; provenance?: EntityGraphEvidence | null;
  onDraw?: (page: number, x0: number, y0: number, x1: number, y1: number) => void }) {
  const drawStart = useRef<{ pointerId: number; page: number; x: number; y: number; rect: DOMRect } | null>(null)
  const mediaEvidence = !candidate && provenance?.locator.status === 'SUPPORTED' && provenance.locator.kind === 'ocr_line_boxes'
    ? provenance.locator : null
  const pointFor = (event: React.PointerEvent<HTMLImageElement>, page: { width: number; height: number }, rect: DOMRect) => ({
    x: Math.max(0, Math.min(page.width, Math.round((event.clientX - rect.left) * page.width / rect.width))),
    y: Math.max(0, Math.min(page.height, Math.round((event.clientY - rect.top) * page.height / rect.height))),
  })
  return <div className={`media-preview-pages ${zoom === 'fit' ? 'is-fit' : ''}`}>{document.mediaPreview?.pages.map(page => <figure key={page.number}
    style={{ width: zoom === 'fit' ? `min(100%, ${page.width + 16}px)` : `${Math.round(page.width * zoom / 100) + 16}px` }}>
    <div className={`media-page-image ${onDraw && !candidate ? 'is-drawable' : ''}`}><img src={`data:image/png;base64,${candidate ? page.candidatePngBase64 : page.sourcePngBase64}`}
      width={page.width} height={page.height}
      style={{ width: zoom === 'fit' ? '100%' : `${Math.round(page.width * zoom / 100)}px` }}
      draggable={false}
      onDragStart={event => event.preventDefault()}
      onPointerDown={event => { if (!onDraw || candidate || event.button !== 0) return; const rect = event.currentTarget.getBoundingClientRect(); const point = pointFor(event, page, rect); drawStart.current = { pointerId: event.pointerId, page: page.number, x: point.x, y: point.y, rect }; event.currentTarget.setPointerCapture(event.pointerId); event.preventDefault() }}
      onPointerUp={event => { const start = drawStart.current; if (!onDraw || !start || start.pointerId !== event.pointerId || start.page !== page.number) return; drawStart.current = null; if (event.currentTarget.hasPointerCapture(event.pointerId)) event.currentTarget.releasePointerCapture(event.pointerId); const point = pointFor(event, page, start.rect); if (Math.abs(point.x - start.x) > 1 && Math.abs(point.y - start.y) > 1) onDraw(page.number, Math.min(start.x, point.x), Math.min(start.y, point.y), Math.max(start.x, point.x), Math.max(start.y, point.y)) }}
      onPointerCancel={event => { if (drawStart.current?.pointerId === event.pointerId) drawStart.current = null }}
      onLostPointerCapture={() => { drawStart.current = null }}
      alt={`${candidate ? 'Raster candidate' : 'Source rendering'} of ${document.name}, page ${page.number}`} />
      {[...(page.manualRegions || []), ...pending.filter(region => region.documentId === document.id && region.page === page.number)].map((region, index) => <span key={`${region.x0}-${region.y0}-${region.x1}-${region.y1}-${index}`} className={`media-region ${index < page.manualRegions.length ? 'applied' : 'pending'}`} style={{ left: `${100 * region.x0 / page.width}%`, top: `${100 * region.y0 / page.height}%`, width: `${100 * (region.x1 - region.x0) / page.width}%`, height: `${100 * (region.y1 - region.y0) / page.height}%` }} />)}
      {mediaEvidence?.page === page.number && mediaEvidence.lineBoxes.map((box, index) => <span key={`graph-evidence-${index}`} className="media-provenance-region" role="note"
          tabIndex={index === 0 ? -1 : undefined} data-provenance-target={index === 0 ? 'true' : undefined}
          aria-label={`Approximate OCR line box ${index + 1} of ${mediaEvidence.lineBoxes.length} for graph evidence on page ${page.number}`}
          style={{ left: `${100 * box.x0 / page.width}%`, top: `${100 * box.y0 / page.height}%`,
            width: `${100 * (box.x1 - box.x0) / page.width}%`, height: `${100 * (box.y1 - box.y0) / page.height}%` }} />)}</div>
    <figcaption>Page {page.number} · {page.width} × {page.height} px · {page.ocrLines} OCR lines{onDraw && !candidate ? ' · drag to stage a region' : ''}</figcaption>
  </figure>)}</div>
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
  const [sampleMode, setSampleMode] = useState<'text' | 'media' | null>(null)
  const [manualNames, setManualNames] = useState<string[]>([])
  const [manualInput, setManualInput] = useState('')
  const [manualFindings, setManualFindings] = useState<BatchManualFinding[]>([])
  const [manualValue, setManualValue] = useState('')
  const [manualKind, setManualKind] = useState<BatchManualFinding['kind']>('OTHER_SENSITIVE')
  const [coordinateCorrections, setCoordinateCorrections] = useState<BatchCoordinateCorrection[]>([])
  const [appliedCoordinates, setAppliedCoordinates] = useState<BatchCoordinateCorrection[]>([])
  const [coordinateRescanRequired, setCoordinateRescanRequired] = useState(false)
  const [coordinateRescanTarget, setCoordinateRescanTarget] = useState<BatchCoordinateCorrection[] | null>(null)
  const [coordinateDraft, setCoordinateDraft] = useState({ page: 1, x0: '', y0: '', x1: '', y1: '', kind: 'OTHER_SENSITIVE' as BatchManualFinding['kind'] })
  const [aliasOverrides, setAliasOverrides] = useState<Record<string, string>>({})
  const [excludedIds, setExcludedIds] = useState<string[]>([])
  const [exclusionAcknowledged, setExclusionAcknowledged] = useState(false)
  const [selectedDoc, setSelectedDoc] = useState('')
  const [registerGroupFilter, setRegisterGroupFilter] = useState<RegisterGroup>('all')
  const [registerSearch, setRegisterSearch] = useState('')
  const [registerPage, setRegisterPage] = useState(0)
  const [comparisonMode, setComparisonMode] = useState<ComparisonMode>('split')
  const [mediaZoom, setMediaZoom] = useState<MediaZoom>(100)
  const [demoDownloadAcknowledged, setDemoDownloadAcknowledged] = useState(false)
  const [provenanceTarget, setProvenanceTarget] = useState<EntityGraphEvidence | null>(null)
  const sourcePane = useRef<HTMLDivElement | null>(null)
  const candidatePane = useRef<HTMLDivElement | null>(null)
  const sequence = useRef(0)
  const request = useRef<AbortController | null>(null)
  const intakeEpoch = useRef(0)

  useEffect(() => () => { request.current?.abort(); intakeEpoch.current += 1 }, [])
  useEffect(() => {
    if (resultTab !== 'documents' || !provenanceTarget || provenanceTarget.locator.status !== 'SUPPORTED') return
    const frame = requestAnimationFrame(() => {
      const target = sourcePane.current?.querySelector<HTMLElement>('[data-provenance-target="true"]')
      const reduceMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false
      target?.scrollIntoView({ block: 'center', behavior: reduceMotion ? 'auto' : 'smooth' })
      target?.focus({ preventScroll: true })
    })
    return () => cancelAnimationFrame(frame)
  }, [resultTab, selectedDoc, provenanceTarget])

  function resetReview() { setInspection(null); setReferenceManifest(null); setReferenceAttested(false); setSampleMode(null); setManualNames([]); setManualFindings([]); setCoordinateCorrections([]); setAppliedCoordinates([]); setCoordinateRescanRequired(false); setCoordinateRescanTarget(null); setAliasOverrides({}); setExcludedIds([]); setExclusionAcknowledged(false); setStep('upload'); setError('') }

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
      if ([...existing, ...added].reduce((sum, item) => sum + item.size, 0) > BATCH_MAX_TOTAL_BYTES) throw new DemoInspectionFailure('The entire synthetic batch must be 1.5 MB or less.')
      setFiles(current => [...(replace ? [] : current), ...added])
      setInspection(null)
      setReferenceManifest(null)
      setReferenceAttested(false)
      setSampleMode(null)
      setManualNames([])
      setManualFindings([])
      setCoordinateCorrections([])
      setAppliedCoordinates([])
      setCoordinateRescanRequired(false)
      setCoordinateRescanTarget(null)
      setAliasOverrides({})
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
    if (await addFiles(SAMPLES, true)) { setReferenceManifest(SAMPLE_REFERENCE); setSampleMode('text') }
  }

  async function loadMediaSample() {
    const epoch = ++intakeEpoch.current
    setReading(true)
    setError('')
    try {
      const specs = [
        { name: '01-email-thread.pdf', type: 'application/pdf' },
        { name: '02-service-note.png', type: 'image/png' },
      ]
      const media = await Promise.all(specs.map(async spec => {
        const response = await fetch(`${import.meta.env.BASE_URL}demo-media/${spec.name}`, { cache: 'no-store' })
        if (!response.ok) throw new Error('The fictional media sample could not be loaded.')
        return new File([await response.arrayBuffer()], spec.name, { type: spec.type })
      }))
      if (epoch !== intakeEpoch.current) return
      if (await addFiles([...media, new File([SAMPLE_DOCUMENTS[2].text], SAMPLE_DOCUMENTS[2].name,
        { type: SAMPLE_DOCUMENTS[2].type })], true)) setSampleMode('media')
    } catch { if (epoch === intakeEpoch.current) setError('The fictional media sample could not be loaded. Try again or choose your own synthetic files.') }
    finally { if (epoch === intakeEpoch.current) setReading(false) }
  }

  async function loadReference(file: File) {
    const epoch = intakeEpoch.current
    setError('')
    try {
      const manifest = await readBatchReferenceManifest(file, files)
      if (epoch === intakeEpoch.current) { setReferenceManifest(manifest); setReferenceAttested(false) }
    } catch (cause) { if (epoch === intakeEpoch.current) setError(cause instanceof Error ? cause.message : 'Could not read reference labels.') }
  }

  async function inspect(nextNames = manualNames, nextAliases = aliasOverrides, nextStep: Step = 'detect', nextExclusions = excludedIds,
    nextFindings = manualFindings, nextCoordinates = [...appliedCoordinates, ...coordinateCorrections], coordinateRescan = false) {
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
      const value = await inspectSyntheticBatch({ apiBase: API_BASE, token, files, manualNames: nextNames, manualFindings: nextFindings, coordinateCorrections: nextCoordinates,
        aliasOverrides: nextAliases,
        reviewExclusions: Object.fromEntries(nextExclusions.map(id => [id, 'FALSE_POSITIVE_CONFIRMED' as const])),
        referenceManifest: referenceManifest?.basis === 'CURATED_SYNTHETIC_SAMPLE' || referenceAttested ? referenceManifest : null,
        signal: controller.signal })
      if (request.current !== controller || controller.signal.aborted) return
      setInspection(value)
      setDemoDownloadAcknowledged(false)
      setManualNames(nextNames)
      setManualFindings(nextFindings)
      setAppliedCoordinates(value.documents.flatMap(document => document.mediaPreview?.pages.flatMap(page => page.manualRegions.map(region => ({ documentId: document.id, page: region.page, x0: region.x0, y0: region.y0, x1: region.x1, y1: region.y1, kind: region.kind }))) || []))
      setCoordinateCorrections([])
      if (coordinateRescan) { setCoordinateRescanRequired(false); setCoordinateRescanTarget(null) }
      setAliasOverrides(nextAliases)
      setExcludedIds(nextExclusions)
      setSelectedDoc(current => value.documents.some(document => document.id === current) ? current : (value.documents[0]?.id || ''))
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

  async function addManualFinding(finding: BatchManualFinding) {
    const value = finding.value.trim()
    if (Array.from(value).length < 2 || Array.from(value).length > 80 || /[\p{C}\p{Zl}\p{Zp}]/u.test(value)) {
      setError('Enter an exact sensitive value of 2–80 printable characters.'); return
    }
    if (manualFindings.some(item => item.kind === finding.kind && item.value.toLocaleLowerCase() === value.toLocaleLowerCase())) {
      setError('This correction is already in the review list.'); return
    }
    if (!inspection?.documents.some(document => new RegExp(`(?<!\\w)${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?!\\w)`, 'i').test(document.text))) {
      setError('That exact value was not found in the current files.'); return
    }
    setManualValue('')
    setExcludedIds([])
    setExclusionAcknowledged(false)
    await inspect(manualNames, {}, 'detect', [], [...manualFindings, { value, kind: finding.kind }])
  }

  function stageCoordinate(documentId: string, page: number, x0: number, y0: number, x1: number, y1: number, kind = coordinateDraft.kind) {
    if (busy || coordinateRescanRequired) return
    const document = inspection?.documents.find(item => item.id === documentId)
    const target = document?.mediaPreview?.pages.find(item => item.number === page)
    if (!document || !target || ![x0, y0, x1, y1].every(Number.isSafeInteger) || x0 < 0 || y0 < 0 || x1 - x0 < 4 || y1 - y0 < 4 || x1 > target.width || y1 > target.height) { setError('Enter a box of at least 4 × 4 pixels within the selected source page.'); return }
    const region: BatchCoordinateCorrection = { documentId: document.id, page, x0, y0, x1, y1, kind }
    if (coordinateCorrections.length + appliedCoordinates.length >= 20) { setError('At most 20 coordinate regions can be reviewed in one batch.'); return }
    const intersects = (item: BatchCoordinateCorrection) => item.documentId === region.documentId && item.page === region.page && x0 < item.x1 && x1 > item.x0 && y0 < item.y1 && y1 > item.y0
    if ([...appliedCoordinates, ...coordinateCorrections].some(intersects)) { setError('That region overlaps another staged or applied region.'); return }
    if ((x1 - x0) * (y1 - y0) > target.width * target.height * .25) { setError('A single region cannot cover more than 25% of its page.'); return }
    setCoordinateCorrections(current => [...current, region]); setCoordinateDraft(current => ({ ...current, page, x0: String(x0), y0: String(y0), x1: String(x1), y1: String(y1) })); setError('')
  }

  function rescanCoordinates(nextApplied = appliedCoordinates) {
    if (busy) return
    const nextCoordinates = [...nextApplied, ...coordinateCorrections]
    setCoordinateRescanRequired(true)
    setCoordinateRescanTarget(nextCoordinates)
    void inspect(manualNames, aliasOverrides, 'results', excludedIds, manualFindings, nextCoordinates, true)
  }

  function removeAppliedCoordinate(index: number) {
    if (busy) return
    rescanCoordinates(appliedCoordinates.filter((_, itemIndex) => itemIndex !== index))
  }

  function retryCoordinateRescan() {
    if (!coordinateRescanTarget || busy) return
    setCoordinateRescanRequired(true)
    void inspect(manualNames, aliasOverrides, 'results', excludedIds, manualFindings, coordinateRescanTarget, true)
  }

  function keepPreviousCoordinateCandidate() {
    if (busy) return
    setCoordinateRescanRequired(false)
    setCoordinateRescanTarget(null)
    setError('Kept the previous applied coordinate regions. Stage or remove regions, then rescan when ready.')
  }

  const selected = inspection?.documents.find(doc => doc.id === selectedDoc) || inspection?.documents[0]
  const selectedAppliedCoordinates = selected ? appliedCoordinates.filter(region => region.documentId === selected.id) : []
  useEffect(() => {
    const pages = inspection?.documents.find(document => document.id === selectedDoc)?.mediaPreview?.pages
    setCoordinateDraft(current => ({ ...current, page: pages?.some(page => page.number === current.page) ? current.page : 1,
      x0: '', y0: '', x1: '', y1: '' }))
  }, [selectedDoc, inspection])
  const visibleEntities = inspection?.entities.filter(item => item.mentions > 0) || []
  const registerEntities = [...visibleEntities].sort((left, right) => {
    const order = ['people', 'contacts', 'identifiers', 'other']
    return order.indexOf(registerGroup(left.kind)) - order.indexOf(registerGroup(right.kind)) || left.source.localeCompare(right.source)
  })
  const registerFiltered = registerEntities.filter(entity =>
    (registerGroupFilter === 'all' || registerGroup(entity.kind) === registerGroupFilter) &&
    (!registerSearch.trim() || `${entity.source} ${entity.kind} ${entity.alias}`.toLocaleLowerCase().includes(registerSearch.trim().toLocaleLowerCase())))
  const registerPageCount = Math.max(1, Math.ceil(registerFiltered.length / REGISTER_PAGE_SIZE))
  const registerCurrentPage = Math.min(registerPage, registerPageCount - 1)
  const registerVisiblePage = registerFiltered.slice(registerCurrentPage * REGISTER_PAGE_SIZE, (registerCurrentPage + 1) * REGISTER_PAGE_SIZE)
  const byId = new Map(visibleEntities.map(item => [item.id, item]))
  const hasPendingAliases = inspection?.entities.some(entity => aliasOverrides[entity.id] !== undefined && aliasOverrides[entity.id] !== entity.alias) || false
  const hasPendingExclusions = inspection?.entities.some(entity => excludedIds.includes(entity.id) !== entity.excluded) || false
  const demoDownloadBlockReason = inspection?.summary.suppressedMentions ? 'Download is blocked while reviewer-excluded source values are retained.'
    : inspection?.verification.sourceValueResiduals ? 'Download is blocked because detected source values remain in the candidate.'
    : inspection?.verification.structureFailures ? 'Download is blocked because a candidate failed its structure check.'
    : inspection?.documents.some(document => document.mediaPreview && document.mediaPreview.selfOcrResidualSources > 0)
      ? 'Download is blocked because the raster recheck found a detected source value.' : ''

  function changeMediaZoom(direction: -1 | 1) {
    const position = MEDIA_ZOOMS.indexOf(mediaZoom === 'fit' ? 100 : mediaZoom)
    setMediaZoom(MEDIA_ZOOMS[Math.max(0, Math.min(MEDIA_ZOOMS.length - 1, position + direction))])
  }

  function syncPaneScroll(source: HTMLDivElement, target: HTMLDivElement | null) {
    if (!target || comparisonMode !== 'split') return
    if (Math.abs(target.scrollTop - source.scrollTop) > 1) target.scrollTop = source.scrollTop
    if (Math.abs(target.scrollLeft - source.scrollLeft) > 1) target.scrollLeft = source.scrollLeft
  }

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
      <div className="sidebar-bottom"><div className="sidebar-note"><LockKeyhole size={17} /><span>Only unverified synthetic review copies can be downloaded. No buyer release is available.</span></div><a href="?mode=advanced">Developer controls <ArrowRight size={14} /></a></div>
    </aside>

    <main className="batch-main">
      <header className="topbar"><div className="breadcrumb">Workbench <ChevronRight size={14} /> <strong>{step === 'upload' ? 'Upload batch' : step === 'detect' ? 'Detection review' : 'Results & verification'}</strong></div><span className="environment-badge"><span /> SYNTHETIC DEMO</span></header>
      <div className={`batch-content ${step === 'results' ? 'batch-content-results' : ''}`}>
        {step === 'upload' && <>
          <div className="page-heading"><div><p className="overline">01 / INTAKE</p><h1>Start with your dataset.</h1><p>Bring two or three synthetic documents together. We’ll trace sensitive mentions across files, then give you a reviewable candidate—not an anonymity claim.</p></div><div className="heading-icon"><UploadCloud size={29} /></div></div>
          <div className="flow-strip"><div className="current"><span>1</span><strong>Upload</strong><small>Choose a batch</small></div><div className="flow-line" /><div><span>2</span><strong>Detect</strong><small>Review matches</small></div><div className="flow-line" /><div><span>3</span><strong>Verify</strong><small>Compare & assess</small></div></div>
          <section className="batch-card intake-card" aria-labelledby="intake-heading"><div className="card-header"><div><p className="overline">BATCH INPUT</p><h2 id="intake-heading">Your documents <span className="count-pill">{files.length}/3</span></h2></div><span className="quiet-tag">Up to 1.5 MB total</span></div>
            <div className={`drop-zone ${dragging ? 'dragging' : ''}`} onDragEnter={event => { event.preventDefault(); setDragging(true) }} onDragOver={event => event.preventDefault()} onDragLeave={event => { event.preventDefault(); setDragging(false) }} onDrop={event => { event.preventDefault(); setDragging(false); void addFiles(Array.from(event.dataTransfer.files)) }}>
              <div className="drop-icon"><UploadCloud size={25} /></div><strong>Drop your synthetic files here</strong><span>or select documents from your computer</span><label className="file-button">Browse files<input type="file" multiple accept=".txt,.csv,.json,.jsonl,.pdf,.png,.jpg,.jpeg" onChange={event => { void addFiles(Array.from(event.target.files || [])); event.target.value = '' }} /></label><small>Text up to 100 KB · PDF/image up to 500 KB · two PDF pages · 3 million media pixels per batch</small>
            </div>
            <div className="sample-bar"><div><Sparkles size={18} /><span>Explore a fictional three-file case, or try PDF and image redaction.</span></div><div className="sample-actions"><button type="button" className="text-button" onClick={() => void loadSample()} disabled={busy || reading}>Use sample batch <ArrowRight size={16} /></button><button type="button" className="text-button" onClick={() => void loadMediaSample()} disabled={busy || reading}>Use PDF + image sample <ArrowRight size={16} /></button></div></div>
            {files.length > 0 && <div className="staged-files" aria-label="Staged documents">{files.map((file, index) => <div className="staged-file" key={file.id}><span className="file-type-icon">{fileIcon(file.name)}</span><div><strong>{file.name}</strong><span>{Math.max(1, Math.ceil(file.size / 1024))} KB · Document {index + 1}</span></div><span className="ready-pill"><Check size={13} /> Ready</span><button type="button" className="icon-button" aria-label={`Remove ${file.name}`} onClick={() => { ++intakeEpoch.current; setFiles(current => current.filter(item => item.id !== file.id)); resetReview() }}><X size={17} /></button></div>)}</div>}
          </section>
          <section className="batch-card access-card" aria-labelledby="access-heading"><div><p className="overline">DEMO ACCESS</p><h2 id="access-heading">Before you continue</h2><p>This local development service receives submitted content in memory for inspection. It cannot verify that a file is synthetic.</p></div><div className="access-form"><label htmlFor="processor-token">Processor access token</label><input id="processor-token" type="password" autoComplete="off" spellCheck={false} value={token} onChange={event => setToken(event.target.value)} placeholder="Paste the token from the demo launcher" /><label className="check-label"><input type="checkbox" checked={acknowledged} onChange={event => setAcknowledged(event.target.checked)} /><span>I confirm all files are fictional demo data. I understand the detector may miss sensitive content.</span></label></div></section>
          <div className="page-actions"><p><ShieldCheck size={16} /> No production data · No automatic release</p><button type="button" className="primary-button" disabled={files.length < 2 || !acknowledged || !token.trim() || reading || busy} onClick={() => void inspect([], {}, 'detect')}>{busy ? 'Inspecting batch…' : 'Analyze batch'} <ArrowRight size={18} /></button></div>
        </>}

        {step === 'detect' && inspection && <>
          <div className="page-heading"><div><p className="overline">02 / DETECTION REVIEW</p><h1>Know what was found.</h1><p>Inspect the rule matches and consistent aliases across the batch. Add a missed name before opening the candidate comparison.</p></div><div className="heading-icon"><Search size={29} /></div></div>
          {sampleMode === 'media' && <div className="media-guidance"><CircleAlert size={18} /><span>Guided media case: the fictional booking code <code>DEMO-4822</code> is deliberately left for review. Add it as <strong>Other sensitive</strong>, rescan, then compare both raster pages. No independent media accuracy score is available.</span></div>}
          <div className="metrics-grid"><div className="metric-card"><span>Documents inspected</span><strong>{inspection.summary.files}</strong><small>One connected batch</small></div><div className="metric-card"><span>Selected mentions</span><strong>{inspection.summary.detectedMentions}</strong><small>Rules + reviewer corrections</small></div><div className="metric-card"><span>Unique signals</span><strong>{visibleEntities.length}</strong><small>Across all documents</small></div><div className="metric-card"><span>Evidenced graph links</span><strong>{inspection.entityGraph.edges.length}</strong><small>Typed roles & mail headers</small></div></div>
          <div className="review-grid"><section className="batch-card entity-review">
            <div className="card-header"><div><p className="overline">ENTITY REGISTER</p><h2>Detected identities & signals</h2></div><span className="quiet-tag">{visibleEntities.length} entities</span></div>
            <div className="register-toolbar">
              <div className="register-filters" role="group" aria-label="Filter detected signals">
                {REGISTER_GROUPS.map(group => { const count = group.id === 'all' ? registerEntities.length : registerEntities.filter(entity => registerGroup(entity.kind) === group.id).length; return <button type="button" key={group.id} className={registerGroupFilter === group.id ? 'selected' : ''} aria-pressed={registerGroupFilter === group.id} onClick={() => { setRegisterGroupFilter(group.id); setRegisterPage(0) }}>{group.label} <span>{count}</span></button> })}
              </div>
              <label className="register-search"><Search size={16} aria-hidden="true" /><input aria-label="Search detected signals" value={registerSearch} placeholder="Search values" onChange={event => { setRegisterSearch(event.target.value); setRegisterPage(0) }} /></label>
            </div>
            <div className="table-scroll"><table><thead><tr><th scope="col">Source value</th><th scope="col">Type</th><th scope="col">Mentions</th><th scope="col">Proposed replacement</th><th scope="col">Review decision</th></tr></thead><tbody>{registerVisiblePage.map(entity => { const excluded = excludedIds.includes(entity.id); const suppressible = SUPPRESSIBLE_KINDS.has(entity.kind); return <tr key={entity.id} className={excluded ? 'entity-excluded' : ''}><td className="source-cell">{entity.source}</td><td><span className="type-pill">{shortType(entity.kind)}</span></td><td>{entity.mentions}</td><td><div className="alias-proposal">{entity.kind === 'PERSON_NAME' ? <input className="alias-input" aria-label={`Replacement for ${entity.source}`} value={aliasOverrides[entity.id] ?? entity.alias} maxLength={entity.source.length} disabled={excluded} onChange={event => setAliasOverrides(current => ({ ...current, [entity.id]: event.target.value }))} /> : <code>{entity.alias}</code>}<small>{STRATEGY_LABELS[entity.strategy]}</small>{entity.kind === 'GOVERNMENT_ID' && entity.strategy === 'OPAQUE_REDACTION' && <small>No verified non-issuable range for this issuer.</small>}</div></td><td><button type="button" className={`decision-button ${excluded ? 'excluded' : ''}`} disabled={!suppressible || busy} title={suppressible ? 'Review this signal across every file' : 'Critical or unsupported categories cannot be excluded in this demo'} aria-label={`${excluded ? 'Restore' : 'Exclude'} ${entity.source}`} onClick={() => toggleExclusion(entity.id)}>{excluded ? 'Restore' : 'Exclude'}</button></td></tr> })}</tbody></table></div>
            {visibleEntities.length === 0 && <p className="empty-note">No rule matches were found. That does not establish that the files contain no sensitive information.</p>}
            {visibleEntities.length > 0 && registerFiltered.length === 0 && <p className="empty-note">No signals match this filter. All detected signals remain available in the other categories.</p>}
            {registerFiltered.length > 0 && <div className="register-pagination"><span>Showing {registerCurrentPage * REGISTER_PAGE_SIZE + 1}–{Math.min(registerFiltered.length, (registerCurrentPage + 1) * REGISTER_PAGE_SIZE)} of {registerFiltered.length}</span><div><button type="button" disabled={registerCurrentPage === 0} onClick={() => setRegisterPage(page => page - 1)}>Previous</button><span>Page {registerCurrentPage + 1} of {registerPageCount}</span><button type="button" disabled={registerCurrentPage >= registerPageCount - 1} onClick={() => setRegisterPage(page => page + 1)}>Next</button></div></div>}
            <div className="card-footnote"><CircleAlert size={16} /> Format-aware examples are intentionally invalid or non-working; they are not safe real identifiers. Other IDs stay opaque. Excluding a signal keeps its source value. Names in arbitrary prose may still be missed.</div>
          </section>
            <aside className="batch-card review-side"><p className="overline">HUMAN-IN-THE-LOOP</p><h2>Found a miss?</h2><p>Add an exact person name or sensitive value. We’ll rescan all documents; manual corrections are tracked separately from automatic detector quality.</p><div className="inline-form"><label htmlFor="manual-name">Person name</label><input id="manual-name" value={manualInput} onChange={event => setManualInput(event.target.value)} placeholder="e.g. Tara" onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); void addManualName() } }} /><button type="button" className="secondary-button" onClick={() => void addManualName()} disabled={busy || !manualInput.trim()}><Plus size={16} /> Add name & rescan</button></div>{manualNames.length > 0 && <div className="manual-list">Names added: {manualNames.join(', ')}</div>}
              <div className="inline-form manual-sensitive-form"><label htmlFor="manual-sensitive">Sensitive value</label><input id="manual-sensitive" value={manualValue} onChange={event => setManualValue(event.target.value)} placeholder="e.g. DEMO-4821" /><label htmlFor="manual-sensitive-kind">Category</label><select id="manual-sensitive-kind" value={manualKind} onChange={event => setManualKind(event.target.value as BatchManualFinding['kind'])}>{MANUAL_FINDING_OPTIONS.map(item => <option key={item.kind} value={item.kind}>{item.label}</option>)}</select><button type="button" className="secondary-button" onClick={() => void addManualFinding({ value: manualValue, kind: manualKind })} disabled={busy || !manualValue.trim()}><Plus size={16} /> Add value & rescan</button></div>{manualFindings.length > 0 && <div className="manual-list">Sensitive values added: {manualFindings.map(item => item.value).join(', ')}</div>}<div className="review-hint"><ShieldCheck size={19} /><span>Corrections target exact phrases across the batch. They do not teach the detector or establish PDF layout fidelity or anonymity.</span></div></aside></div>
          {excludedIds.length > 0 && <div className="exclusion-notice"><CircleAlert size={19} /><label className="check-label"><input type="checkbox" checked={exclusionAcknowledged} onChange={event => setExclusionAcknowledged(event.target.checked)} /><span>I confirm the {excludedIds.length} excluded {excludedIds.length === 1 ? 'signal is' : 'signals are'} a false positive for this synthetic batch. Its source values will remain visible in the proposed candidate.</span></label></div>}
          <section className="batch-card reference-card" aria-labelledby="reference-heading"><div className="card-header"><div><p className="overline">OPTIONAL MEASUREMENT</p><h2 id="reference-heading">Reference labels</h2></div><span className="quiet-tag">{referenceManifest ? 'Attached' : 'Not supplied'}</span></div>
            <p>To measure exact-span agreement, attach a complete annotation manifest for all staged files. The built-in sample includes demo-authored labels. Uploaded labels are reviewer-attested, not independently verified.</p>
            <div className="reference-actions"><label className="file-button">Attach labels JSON<input type="file" accept=".json" onChange={event => { const file = event.target.files?.[0]; if (file) void loadReference(file); event.target.value = '' }} /></label>{referenceManifest && <button type="button" className="text-button" onClick={() => { setReferenceManifest(null); setReferenceAttested(false) }}>Remove labels</button>}</div>
            {referenceManifest?.basis === 'REVIEWER_ATTESTED_EXHAUSTIVE' && <label className="check-label reference-attestation"><input type="checkbox" checked={referenceAttested} onChange={event => setReferenceAttested(event.target.checked)} /><span>I reviewed the synthetic batch and attest that these labels cover every relevant sensitive span for this measurement.</span></label>}
            <details><summary>Annotation file format</summary><pre>{'{"schema_version":"batch-reference-v1","documents":[{"name":"file.txt","annotations":[{"start":0,"end":4,"entity_type":"PERSON_NAME"}]}]}'}</pre><small>List every staged filename once, including files with zero labels. Offsets are half-open Unicode character positions in source text; for PDFs, they refer to extracted text shown here.</small></details>
          </section>
          <section className="batch-card document-coverage"><div className="card-header"><div><p className="overline">FILE COVERAGE</p><h2>What the detector reviewed</h2></div></div><div className="coverage-list">{inspection.documents.map(document => <div key={document.id}><span className="file-type-icon">{fileIcon(document.name)}</span><div><strong>{document.name}</strong><span>{document.mediaPreview ? `Rasterized and OCR-reviewed · ${document.mediaPreview.pages.length} ${document.mediaPreview.pages.length === 1 ? 'page' : 'pages'}` : 'Source text reviewed'}</span></div><strong>{document.matches.length} matches</strong></div>)}</div></section>
          <div className="page-actions"><button type="button" className="back-button" onClick={() => setStep('upload')}><ArrowLeft size={17} /> Edit batch</button><button type="button" className="primary-button" disabled={busy} onClick={() => void inspect(manualNames, aliasOverrides, 'results', excludedIds)}>{busy ? 'Applying changes…' : hasPendingAliases || hasPendingExclusions ? 'Apply decisions & review candidate' : 'Review candidate'} <ArrowRight size={18} /></button></div>
        </>}

        {step === 'results' && inspection && <>
          <div className="page-heading"><div><p className="overline">03 / RESULTS & VERIFICATION</p><h1>Review the proposed output.</h1><p>Trace every replacement, inspect explicit relationships, and understand what this run did—and did not—prove.</p></div><div className="heading-icon"><ShieldCheck size={29} /></div></div>
          <div className="result-alert"><CircleAlert size={21} /><div><strong>Review required · not anonymous or export-ready</strong><span>This is a synthetic review preview. OCR coverage, residual visual content, privacy risk, layout fidelity, and release eligibility are not certified.</span></div></div>
          <div className="metrics-grid"><div className="metric-card"><span>Files processed</span><strong>{inspection.summary.files}</strong><small>In this batch</small></div><div className="metric-card"><span>Mentions transformed</span><strong>{inspection.summary.transformedMentions}</strong><small>Selected spans only</small></div><div className="metric-card"><span>Unique signals</span><strong>{visibleEntities.length}</strong><small>Tracked across files</small></div><div className="metric-card"><span>Source values retained</span><strong>{inspection.verification.sourceValueResiduals}</strong><small>Detected exact values only</small></div></div>
          {inspection.summary.suppressedMentions > 0 && <div className="result-alert exclusion-result"><CircleAlert size={19} /><div><strong>{inspection.summary.suppressedMentions} detected {inspection.summary.suppressedMentions === 1 ? 'mention was' : 'mentions were'} retained after reviewer exclusion</strong><span>Those original values remain in the proposed text. This preview cannot be exported or treated as anonymized.</span></div></div>}
          <div className="result-tabs" role="tablist" aria-label="Batch result views">{([['documents', 'Documents', Files], ['relationships', 'Entities & relationships', Link2], ['verification', 'Verification scorecard', ShieldCheck]] as const).map(([key, label, Icon]) => <button key={key} type="button" role="tab" aria-selected={resultTab === key} className={resultTab === key ? 'selected' : ''} onClick={() => setResultTab(key)}><Icon size={17} /> {label}</button>)}</div>
          {resultTab === 'documents' && selected && <section className="batch-card result-panel">
            <div className="card-header"><div><p className="overline">DOCUMENT COMPARISON</p><h2>Inspect the source and proposed candidate</h2></div><span className="quiet-tag">{selected.matches.length} matches in this file</span></div>
            <div className="doc-selector" role="tablist" aria-label="Documents">{inspection.documents.map(document => <button type="button" role="tab" aria-selected={selected.id === document.id} className={selected.id === document.id ? 'selected' : ''} key={document.id} onClick={() => { setProvenanceTarget(null); setSelectedDoc(document.id) }}>{fileIcon(document.name)}<span>{document.name}</span><small>{document.matches.length}</small></button>)}</div>
            {provenanceTarget?.documentId === selected.id && <p className={`provenance-navigation ${provenanceTarget.locator.status === 'SUPPORTED' ? 'is-precise' : ''}`} role="status">{provenanceTarget.locator.status !== 'SUPPORTED' ? <>Graph evidence supports this document only. No defensible text span, PDF page, or bounding box is available for this relationship.</> : provenanceTarget.locator.kind === 'ocr_line_boxes' ? <>Opened page {provenanceTarget.locator.page} at approximate OCR line boxes. These boxes locate recognized text, not exact glyphs or independently verified relationship proof.</> : <>Opened graph evidence at source lines {provenanceTarget.locator.lineStart}{provenanceTarget.locator.lineEnd === provenanceTarget.locator.lineStart ? '' : `–${provenanceTarget.locator.lineEnd}`}. The highlighted text is a navigation aid, not a release-safety finding.</>}</p>}
            <div className="comparison-toolbar">
              <div className="comparison-layout" role="group" aria-label="Comparison layout">
                {([['split', 'Side by side'], ['original', 'Original only'], ['candidate', 'Candidate only']] as const).map(([mode, label]) =>
                  <button key={mode} type="button" aria-pressed={comparisonMode === mode}
                    className={comparisonMode === mode ? 'selected' : ''} onClick={() => setComparisonMode(mode)}>{label}</button>)}
              </div>
              {selected.mediaPreview && <div className="zoom-controls" role="group" aria-label="Document zoom">
                <button type="button" aria-label="Zoom out" title="Zoom out" disabled={mediaZoom === 50}
                  onClick={() => changeMediaZoom(-1)}><ZoomOut size={17} /></button>
                <select aria-label="Document zoom" value={String(mediaZoom)}
                  onChange={event => setMediaZoom(event.target.value === 'fit' ? 'fit' : Number(event.target.value) as MediaZoom)}>
                  <option value="fit">Fit width</option>
                  {MEDIA_ZOOMS.map(zoom => <option key={zoom} value={zoom}>{zoom}%</option>)}
                </select>
                <button type="button" aria-label="Zoom in" title="Zoom in" disabled={mediaZoom === 200}
                  onClick={() => changeMediaZoom(1)}><ZoomIn size={17} /></button>
              </div>}
            </div>
            {selected.mediaPreview && <p className="zoom-hint">100% shows native preview pixels. Fit width may shrink text; zoom above 100% magnifies raster pixels. Scroll to pan, with panes synchronized side by side.</p>}
            {selected.mediaPreview && <div className="pdf-note"><CircleAlert size={16} /> {selected.kind === 'pdf' ? 'Pages were rebuilt as pixels in a new image-only PDF held in memory.' : 'The image was re-encoded without source metadata.'} {selected.mediaPreview.candidateLowConfidenceLines > 0 ? `${selected.mediaPreview.candidateLowConfidenceLines} candidate OCR lines have low confidence. ` : ''}OCR may miss visible text; this same-engine visual check is not independent validation.</div>}
            {selected.mediaPreview && <section className="coordinate-review" aria-label="Coordinate redaction review">
              <div><strong>Reviewer coordinate regions</strong><p>Drag on the source page or enter native top-left raster pixels. Staged regions are not applied until you rescan.</p></div>
              <div className="coordinate-inputs"><label>Page<select value={coordinateDraft.page} disabled={coordinateRescanRequired} onChange={event => setCoordinateDraft(current => ({ ...current, page: Number(event.target.value) }))}>{selected.mediaPreview.pages.map(page => <option key={page.number} value={page.number}>{page.number}</option>)}</select></label>{(['x0', 'y0', 'x1', 'y1'] as const).map(field => <label key={field}>{field.toUpperCase()}<input inputMode="numeric" pattern="[0-9]*" disabled={coordinateRescanRequired} value={coordinateDraft[field]} onChange={event => setCoordinateDraft(current => ({ ...current, [field]: event.target.value.replace(/[^0-9]/g, '') }))} /></label>)}<label>Category<select value={coordinateDraft.kind} disabled={coordinateRescanRequired} onChange={event => setCoordinateDraft(current => ({ ...current, kind: event.target.value as BatchManualFinding['kind'] }))}>{MANUAL_FINDING_OPTIONS.map(option => <option key={option.kind} value={option.kind}>{option.label}</option>)}</select></label><button type="button" className="secondary-button" disabled={busy || coordinateRescanRequired} onClick={() => { if ((['x0', 'y0', 'x1', 'y1'] as const).some(field => coordinateDraft[field] === '')) { setError('Enter all four pixel coordinates.'); return } stageCoordinate(selected.id, coordinateDraft.page, Number(coordinateDraft.x0), Number(coordinateDraft.y0), Number(coordinateDraft.x1), Number(coordinateDraft.y1)) }}>Stage region</button></div>
              {selectedAppliedCoordinates.length > 0 && <div className="applied-regions"><strong>{selectedAppliedCoordinates.length} applied in this document · rescan to change</strong>{selectedAppliedCoordinates.map(region => {
                const index = appliedCoordinates.indexOf(region)
                return <span key={`${region.documentId}-${region.page}-${region.x0}-${region.y0}-${index}`}>Page {region.page}: ({region.x0}, {region.y0})–({region.x1}, {region.y1}) {shortType(region.kind)} <button type="button" aria-label={`Remove applied region ${index + 1}`} disabled={busy || coordinateRescanRequired} onClick={() => removeAppliedCoordinate(index)}><X size={14} /></button></span>
              })}</div>}
              {coordinateCorrections.length > 0 && <div className="pending-regions"><strong>{coordinateCorrections.length} staged · not applied</strong>{coordinateCorrections.map((region, index) => <span key={`${region.documentId}-${region.page}-${region.x0}-${index}`}>Page {region.page}: ({region.x0}, {region.y0})–({region.x1}, {region.y1}) {shortType(region.kind)} <button type="button" aria-label={`Remove staged region ${index + 1}`} disabled={busy || coordinateRescanRequired} onClick={() => setCoordinateCorrections(current => current.filter((_, itemIndex) => itemIndex !== index))}><X size={14} /></button></span>)}<button type="button" className="primary-button" disabled={busy || coordinateRescanRequired} onClick={() => rescanCoordinates()}>{busy ? 'Rescanning…' : 'Rescan and apply staged regions'}</button></div>}
              {coordinateRescanRequired && <div className="coordinate-rescan-warning"><CircleAlert size={16} /><span>The prior candidate remains visible. Retry the exact coordinate change, or keep the previous candidate before making another edit.</span><button type="button" className="secondary-button" disabled={busy || !coordinateRescanTarget} onClick={retryCoordinateRescan}>Retry rescan</button><button type="button" className="text-button" disabled={busy} onClick={keepPreviousCoordinateCandidate}>Keep previous candidate</button></div>}
            </section>}
            <div className={`comparison ${comparisonMode !== 'split' ? 'is-single' : ''}`}>
              {comparisonMode !== 'candidate' && <div className="comparison-column"><div className="pane-heading"><span>ORIGINAL · SYNTHETIC INPUT</span><span>{selected.matches.length} highlighted matches</span></div>
                <div className="document-pane" ref={sourcePane} onScroll={event => syncPaneScroll(event.currentTarget, candidatePane.current)}>
                  {selected.mediaPreview && <MediaPages document={selected} candidate={false} zoom={mediaZoom} pending={coordinateCorrections} provenance={provenanceTarget?.documentId === selected.id ? provenanceTarget : null} onDraw={(page, x0, y0, x1, y1) => stageCoordinate(selected.id, page, x0, y0, x1, y1)} />}
                  <details className="ocr-transcript" open={!selected.mediaPreview}><summary>{selected.mediaPreview ? 'OCR transcript' : 'Source text'}</summary><HighlightedSource document={selected} provenance={provenanceTarget?.documentId === selected.id ? provenanceTarget : null} /></details>
                </div></div>}
              {comparisonMode === 'split' && <div className="compare-divider"><ArrowDown size={17} /></div>}
              {comparisonMode !== 'original' && <div className="comparison-column"><div className="pane-heading"><span>{selected.mediaPreview ? 'RASTER CANDIDATE' : 'PROPOSED TEXT CANDIDATE'}</span><span>Demo review only</span></div>
                <div className="document-pane candidate" ref={candidatePane} onScroll={event => syncPaneScroll(event.currentTarget, sourcePane.current)}>
                  {selected.mediaPreview && <MediaPages document={selected} candidate={true} zoom={mediaZoom} pending={coordinateCorrections} />}
                  <details className="ocr-transcript" open={!selected.mediaPreview}><summary>{selected.mediaPreview ? 'Proposed OCR text' : 'Candidate text'}</summary><pre>{selected.candidateText}</pre></details>
                </div></div>}
            </div>
            <div className="card-footnote"><CircleAlert size={16} /> Highlighting shows selected rule or reviewer spans only. Unmarked content has not been certified safe.</div>
            <div className="demo-download-actions">
              <label className="check-label"><input type="checkbox" checked={demoDownloadAcknowledged}
                onChange={event => setDemoDownloadAcknowledged(event.target.checked)} />
                I confirm this batch contains synthetic test data only. The candidate is unverified and must not be shared or used as a release artifact.</label>
              <button type="button" className="demo-download-button" disabled={!demoDownloadAcknowledged || busy || coordinateCorrections.length > 0 || coordinateRescanRequired || Boolean(demoDownloadBlockReason)}
                onClick={() => void downloadDemoCandidate(selected).catch(cause => setError(cause instanceof Error ? cause.message : 'Could not save the demo candidate.'))}>
                <Download size={17} /> Download this demo candidate
              </button>
            </div>
            {(demoDownloadBlockReason || coordinateCorrections.length > 0 || coordinateRescanRequired) && <p className="download-blocked">{coordinateRescanRequired ? 'Download is blocked until the coordinate rescan succeeds. Previous applied regions remain visible while you retry.' : coordinateCorrections.length > 0 ? 'Download is disabled while coordinate regions are staged. Rescan to apply or remove them.' : demoDownloadBlockReason}</p>}
          </section>}
          {resultTab === 'relationships' && <section className="batch-card result-panel relationship-panel">
            <div className="card-header"><div><p className="overline">CROSS-DOCUMENT CONTEXT</p><h2>Entity relationship map</h2></div><span className="quiet-tag">Explicit evidence only</span></div>
            <p className="panel-intro">This map separates people, organizations, and projects. Arrows carry a typed relationship; it never derives a tie from proximity or co-mentions.</p>
            <RelationshipGraph graph={inspection.entityGraph} documentNames={new Map(inspection.documents.map((document, index) => [document.id, `Document ${String(index + 1).padStart(2, '0')} · ${document.kind.toUpperCase()}`]))} onInspectDocument={(id, evidence) => { setProvenanceTarget(evidence); setSelectedDoc(id); setComparisonMode('split'); setResultTab('documents') }} />
          </section>}
          {resultTab === 'verification' && <section className="batch-card result-panel"><div className="card-header"><div><p className="overline">EVIDENCE, NOT A VANITY SCORE</p><h2>Verification scorecard</h2></div><span className="status-pill">REVIEW REQUIRED</span></div>
            <p className="panel-intro">These are observable checks for this run. Reference-label agreement appears only when complete synthetic labels were supplied; it does not measure anonymity or performance on other datasets.</p>
            {inspection.verification.annotationScore ? (() => { const score = inspection.verification.annotationScore; return <div className="annotation-panel"><div className="annotation-heading"><div><span className="overline">EXACT-SPAN AGREEMENT</span><h3>Reviewed candidate vs reference labels</h3></div><span className="quiet-tag">{score.basis === 'CURATED_SYNTHETIC_SAMPLE' ? 'Demo-authored sample' : 'Reviewer-attested labels'}</span></div>
              <div className="automatic-baseline"><div><strong>Automatic baseline</strong><span>Before manual additions or false-positive exclusions</span></div><div><span>Precision</span><strong>{percent(score.automaticExact.truePositives, score.automaticExact.truePositives + score.automaticExact.falsePositives)}</strong></div><div><span>Recall</span><strong>{percent(score.automaticExact.truePositives, score.automaticExact.truePositives + score.automaticExact.falseNegatives)}</strong></div></div>
              <div className="annotation-metrics"><div><span>Precision after review</span><strong>{percent(score.exact.truePositives, score.exact.truePositives + score.exact.falsePositives)}</strong><small>{score.exact.falsePositives} unmatched predictions</small></div><div><span>Recall after review</span><strong>{percent(score.exact.truePositives, score.exact.truePositives + score.exact.falseNegatives)}</strong><small>{score.exact.falseNegatives} missed reference spans</small></div><div><span>Labelled spans</span><strong>{score.goldAnnotations}</strong><small>Across {score.labelledDocuments} documents</small></div></div>
              <div className="table-scroll"><table><thead><tr><th>Reference category</th><th>Matched</th><th>False positives</th><th>Missed</th></tr></thead><tbody>{Object.entries(score.perType).sort(([a], [b]) => a.localeCompare(b)).map(([kind, counts]) => <tr key={kind}><td>{shortType(kind)}</td><td>{counts.truePositives}</td><td>{counts.falsePositives}</td><td>{counts.falseNegatives}</td></tr>)}{Object.keys(score.perType).length === 0 && <tr><td colSpan={4}>No labelled or predicted spans. Precision and recall are undefined.</td></tr>}</tbody></table></div>
              <FileScorecard score={score} documents={inspection.documents} onInspect={id => { setSelectedDoc(id); setResultTab('documents') }} onCorrect={finding => { void addManualFinding(finding) }} />
              <p className="annotation-caveat">Counts include manual corrections made before this review. They depend on the supplied labels being complete and are not an independent holdout test, a residual-disclosure test, or release approval.</p>
            </div> })() : <div className="unmeasured-panel"><strong>Precision and recall not measured</strong><span>No complete reference-label set was attached. Return to Detection review to add one; zero retained detected values cannot substitute for labelled ground truth.</span></div>}
            {inspection.verification.aggregateScorecard && (() => { const score = inspection.verification.aggregateScorecard; const residuals = Object.values(score.finalTextValidation.residualUnitsByCategory).reduce((sum, value) => sum + value, 0); return <section className="aggregate-scorecard" aria-label="Aggregate synthetic scorecard"><div className="annotation-heading"><div><span className="overline">AGGREGATE-ONLY · SYNTHETIC</span><h3>Automatic versus reviewer-corrected spans</h3></div><span className="quiet-tag">Not qualified</span></div><p>These counts summarize only the supplied labels in this batch. They contain no document IDs or source values.</p><div className="annotation-metrics"><div><span>Automatic misses</span><strong>{score.automaticExact.falseNegatives}</strong><small>{score.automaticExact.falsePositives} unmatched predictions</small></div><div><span>After-review misses</span><strong>{score.reviewerCorrectedExact.falseNegatives}</strong><small>{score.reviewerCorrectedExact.falsePositives} unmatched predictions</small></div><div><span>Identifier-shaped text flags</span><strong>{residuals}</strong><small>{score.finalTextValidation.boundArtifacts} final text artifacts; {score.finalTextValidation.abstainedArtifacts} abstained; not OCR or media pixels.</small></div><div><span>Final media validation</span><strong>Abstained</strong><small>No executable independent validator is bound to final media pixels.</small></div></div><p className="annotation-caveat">The separate rule scanner is text-only and not anonymization certification. Relationship correction state is unavailable, so relationship agreement is not scored. This observational synthetic report does not authorize release.</p></section> })()}
            <div className="scorecard-list">{inspection.verification.checks.map((check, index) => <div key={`${check.name}-${index}`}><span className={`check-status status-${check.status.toLowerCase()}`}>{check.status === 'PASS' ? <Check size={15} /> : <CircleAlert size={15} />}{check.status.replaceAll('_', ' ')}</span><div><strong>{check.name}</strong><p>{check.detail}</p></div></div>)}</div><div className="limitations-panel"><h3>What remains unproven</h3><ul>{inspection.limitations.map((item, index) => <li key={index}>{item}</li>)}</ul></div></section>}
          <div className="page-actions"><button type="button" className="back-button" onClick={() => { setStep('detect'); setResultTab('documents') }}><ArrowLeft size={17} /> Back to detection</button><span className="no-export"><LockKeyhole size={16} /> Buyer release and production export remain disabled</span></div>
        </>}
        {error && <div className="batch-error" role="alert"><CircleAlert size={19} /><span>{error}</span><button type="button" aria-label="Dismiss error" onClick={() => setError('')}><X size={17} /></button></div>}
        {busy && <div className="batch-working" role="status"><RefreshCw size={18} className="spinning" /> Inspecting synthetic files… <button type="button" onClick={() => request.current?.abort()}>Cancel</button></div>}
      </div>
    </main>
  </div>
}
