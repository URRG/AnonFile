import React, { useEffect, useRef, useState } from 'react'
import { inspectDocument, type DocumentReview } from './document-review-api'
import './document-review.css'

export function DocumentReviewPage() {
  const [token, setToken] = useState('')
  const [files, setFiles] = useState<File[]>([])
  const [acknowledged, setAcknowledged] = useState(false)
  const [corrections, setCorrections] = useState('')
  const [results, setResults] = useState<DocumentReview[]>([])
  const [selected, setSelected] = useState(0)
  const [surfaceIndex, setSurfaceIndex] = useState(0)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const active = useRef<AbortController | null>(null)
  useEffect(() => () => active.current?.abort(), [])
  const result = results[selected]
  const surface = result?.surfaces[surfaceIndex]

  function invalidate() { active.current?.abort(); active.current = null; setBusy(''); setResults([]); setError(''); setSelected(0); setSurfaceIndex(0) }
  async function inspect() {
    const controller = new AbortController()
    active.current?.abort(); active.current = controller
    setResults([]); setError(''); setSelected(0); setSurfaceIndex(0)
    try {
      for (const file of files) {
        setBusy(file.name)
        const review = await inspectDocument(import.meta.env.VITE_API_URL || 'http://localhost:8000', token, file,
          corrections.split('\n').map(value => value.trim()).filter(Boolean), controller.signal)
        if (active.current !== controller) return
        setResults(current => [...current, review])
      }
    } catch (failure) {
      if (active.current === controller && !controller.signal.aborted) setError(failure instanceof Error ? failure.message : 'Document review failed.')
    } finally {
      if (active.current === controller) { active.current = null; setBusy('') }
    }
  }

  return <main className="document-review">
    <a href="?">← Synthetic batch workbench</a>
    <h1>Document coverage review</h1>
    <p>Inspect PDFs, Word documents, presentations and spreadsheets. Compare extracted text with a candidate and check which content still needs review.</p>
    <form onSubmit={event => { event.preventDefault(); void inspect() }}>
      <label>Processor token<input type="password" autoComplete="off" value={token} onChange={event => { invalidate(); setToken(event.target.value) }} required /></label>
      <label>Documents · up to 8 files, 8 MB each<input type="file" multiple accept=".pdf,.docx,.pptx,.xlsx" onChange={event => {
        invalidate(); const chosen = Array.from(event.target.files || []); setFiles(chosen.length <= 8 ? chosen : []);
        if (chosen.length > 8) setError('Choose up to eight documents.')
      }} /></label>
      <details><summary>Additional values to remove from text</summary><label>One exact value per line. Each value must occur in each selected document; review one file at a time for document-specific corrections.
        <textarea value={corrections} onChange={event => { invalidate(); setCorrections(event.target.value) }} rows={4} /></label></details>
      <label className="document-ack"><input type="checkbox" checked={acknowledged} onChange={event => { invalidate(); setAcknowledged(event.target.checked) }} />I have permission to review these documents. Text candidates are unverified; original files remain unchanged.</label>
      <div className="document-actions"><button disabled={!!busy || !files.length || !acknowledged || !token.trim()}>Review documents</button>
        {!!busy && <button type="button" onClick={() => { active.current?.abort(); active.current = null; setBusy(''); setError('Stopped waiting. The server may finish its current document; unfinished documents have no coverage result here.') }}>Cancel</button>}</div>
    </form>
    <p role="status" aria-live="polite">{busy ? `Reviewing ${busy}. OCR may take a few minutes.` : results.length ? `${results.length} document review(s) completed.` : ''}</p>
    {error && <p role="alert" className="document-warning">{error}</p>}
    {result && <section aria-label="Document results">
      <label htmlFor="document-selection">Document</label><select id="document-selection" value={selected} onChange={event => { setSelected(Number(event.target.value)); setSurfaceIndex(0) }}>{results.map((item, index) => <option key={index} value={index}>{item.name}</option>)}</select>
      <h2>{result.name}</h2>
      <p className="document-warning"><strong>Review required.</strong> No cleaned original-format file has been produced. Zero findings do not establish that a document is safe to share.</p>
      <p>{result.summary.pages} PDF pages · {result.summary.surfaces} text surfaces · {result.summary.matches} candidate findings · {result.summary.residual_units} surfaces with residual findings · {result.summary.known_values_remaining} known values remaining</p>
      <details open><summary>Coverage gaps ({result.gaps.length})</summary><ul>{result.gaps.map(gap => <li key={gap}>{gap.toLowerCase().replaceAll('_', ' ')}</li>)}</ul></details>
      <details><summary>All pages and package parts ({result.inventory.length})</summary><div className="document-table"><table><thead><tr><th>Page or part</th><th>Text status</th><th>Visibility / OCR</th></tr></thead><tbody>{result.inventory.map((item, index) => <tr key={index}><td>{item.id}</td><td>{item.status}</td><td>{item.visibility || ''}{item.ocr ? ` OCR: ${item.ocr}; pixels: ${item.visual}` : ''}</td></tr>)}</tbody></table></div></details>
      <label htmlFor="surface-selection">Text surface</label><select id="surface-selection" value={surfaceIndex} onChange={event => setSurfaceIndex(Number(event.target.value))}>{result.surfaces.map((item, index) => <option key={index} value={index}>{item.id} · {item.kind} · {item.matches.length} findings</option>)}</select>
      {surface && <>
        <p>{surface.status} · {surface.matches.length} proposals · {surface.known_values_remaining} known values remaining</p>
        <div className="document-comparison"><section><h3>Extracted source</h3><pre>{surface.text || '(empty)'}</pre></section><section><h3>Unverified text candidate</h3><pre>{surface.candidate || '(empty)'}</pre></section></div>
        <details><summary>Finding locations and reasons</summary><ul>{surface.matches.map((match, index) => <li key={index}>{match.kind} · characters {match.start}–{match.end} · {match.basis}</li>)}</ul></details>
      </>}
      <ul>{result.limitations.map(message => <li key={message}>{message}</li>)}</ul>
    </section>}
  </main>
}
