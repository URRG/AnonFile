import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, ChevronUp, Focus, Minus, Plus } from 'lucide-react'
import type { EntityGraph, EntityGraphEdge, EntityGraphEvidence, EntityGraphNode } from './api'
import { isDenseReviewGraph, moveReviewFocus, readableReviewZoom } from './review-navigation'
import './relationship-graph.css'

const edgeLabel: Record<EntityGraphEdge['type'], string> = {
  assistant_to: 'assistant to', assistant_for: 'assistant for', works_at: 'works at', client_of: 'client of', works_on: 'works on', assigned_to: 'assigned to', sent_to: 'sent to',
}
const kindLabel: Record<EntityGraphNode['kind'], string> = { person: 'Person', organization: 'Organization', project: 'Project' }
const evidenceLabel: Record<string, string> = {
  explicit_mail_header: 'Mail header', explicit_structured_field_pair: 'Structured fields',
  explicit_signature_block: 'Named signature', explicit_signature_title: 'Signature role', explicit_role_statement: 'Explicit role statement',
}

function layout(nodes: EntityGraphNode[]) {
  const positions = new Map<string, { x: number; y: number }>()
  const people = nodes.filter(node => node.kind === 'person'); const hubs = nodes.filter(node => node.kind !== 'person')
  const extra = Math.max(0, people.length - 6); const radiusX = 390 + extra * 28; const radiusY = 300 + extra * 18
  const width = Math.max(1100, radiusX * 2 + 260); const height = Math.max(850, radiusY * 2 + 230); const centerX = width / 2; const centerY = height / 2
  hubs.forEach((node, index) => { const column = index % 2; const row = Math.floor(index / 2); positions.set(node.id, { x: centerX + (column ? 130 : -130), y: centerY + (row - Math.floor((hubs.length - 1) / 2)) * 118 }) })
  people.forEach((node, index) => { const angle = -Math.PI / 2 + index * (Math.PI * 2 / Math.max(people.length, 1)); positions.set(node.id, { x: centerX + Math.cos(angle) * radiusX, y: centerY + Math.sin(angle) * radiusY }) })
  return { positions, width, height }
}

function evidenceLocation(item: EntityGraphEvidence) {
  if (item.locator.status !== 'SUPPORTED') return 'Document-level only · no defensible precise locator'
  if (item.locator.kind === 'ocr_line_boxes') return `Page ${item.locator.page} · approximate OCR line boxes · open source page`
  return `Lines ${item.locator.lineStart}${item.locator.lineEnd === item.locator.lineStart ? '' : `–${item.locator.lineEnd}`} · open exact evidence`
}

function nodeDescription(node: EntityGraphNode, isSelected: boolean) {
  return `${kindLabel[node.kind]} ${node.label}. ${node.documentIds.length} supporting ${node.documentIds.length === 1 ? 'document' : 'documents'}.${isSelected ? ' Selected.' : ''} Use arrow keys to move between nodes.`
}

export function RelationshipGraph({ graph, documentNames, onInspectDocument }: { graph: EntityGraph; documentNames: Map<string, string>; onInspectDocument: (id: string, evidence: EntityGraphEvidence) => void }) {
  const [selectedId, setSelectedId] = useState<string | null>(graph.nodes[0]?.id ?? null)
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null)
  const [showCommunication, setShowCommunication] = useState(false)
  const [zoom, setZoom] = useState(1)
  const [tableOpen, setTableOpen] = useState(false)
  const [compact, setCompact] = useState(false)
  const viewport = useRef<HTMLDivElement | null>(null)
  const nodeButtons = useRef(new Map<string, HTMLButtonElement>())
  const visibleEdges = useMemo(() => graph.edges.filter(edge => showCommunication || edge.type !== 'sent_to'), [graph.edges, showCommunication])
  const visibleNodes = useMemo(() => {
    if (showCommunication || !visibleEdges.length) return graph.nodes
    const connected = new Set(visibleEdges.flatMap(edge => [edge.sourceId, edge.targetId]))
    return graph.nodes.filter(node => connected.has(node.id))
  }, [graph.nodes, visibleEdges, showCommunication])
  const dense = isDenseReviewGraph(visibleNodes.length, visibleEdges.length)
  const { positions, width, height } = useMemo(() => layout(visibleNodes), [visibleNodes])
  const selected = visibleNodes.find(node => node.id === selectedId) ?? visibleNodes[0] ?? null
  const selectedEdges = selected ? visibleEdges.filter(edge => edge.sourceId === selected.id || edge.targetId === selected.id) : []
  const selectNode = (id: string, focus = false) => {
    setSelectedId(id); setSelectedEdgeId(null)
    if (focus) requestAnimationFrame(() => nodeButtons.current.get(id)?.focus())
  }
  const selectEdge = (edge: EntityGraphEdge) => { setSelectedId(edge.sourceId); setSelectedEdgeId(edge.id) }
  const focusGraph = () => {
    const bounds = viewport.current?.getBoundingClientRect()
    if (!bounds) return
    setZoom(readableReviewZoom(bounds.width, width))
  }
  useLayoutEffect(() => {
    const element = viewport.current
    if (!element) return
    const update = () => { setZoom(readableReviewZoom(element.clientWidth, width)); setCompact(element.clientWidth < 760) }
    update()
    const observer = new ResizeObserver(update)
    observer.observe(element)
    return () => observer.disconnect()
  }, [width])
  useEffect(() => { if (dense || compact) setTableOpen(true) }, [dense, compact])
  useEffect(() => {
    if (selectedId && visibleNodes.some(node => node.id === selectedId)) return
    setSelectedId(visibleNodes[0]?.id ?? null); setSelectedEdgeId(null)
  }, [selectedId, visibleNodes])

  if (!graph.nodes.length) return <div className="relationship-graph-empty"><strong>No structured relationship map yet</strong><p>Only explicit fields can create a node or link; nothing is inferred from nearby text.</p></div>
  return <section className="relationship-map" aria-label="Entity relationship map">
    <p className="relationship-screenreader-status" aria-live="polite" aria-atomic="true">{selected ? `${nodeDescription(selected, true)} ${selectedEdges.length} visible explicit relationships.` : 'No node selected.'}</p>
    <div className="relationship-map-toolbar">
      <label className="relationship-toggle"><input type="checkbox" checked={showCommunication} onChange={event => setShowCommunication(event.target.checked)} /> Include mail links (sent to)</label>
      <div role="group" aria-label="Map view controls" className="relationship-map-controls">
        <button type="button" onClick={() => setZoom(value => Math.max(.8, value - .15))} aria-label="Zoom out" title="Zoom out"><Minus aria-hidden="true" size={16} /></button>
        <span aria-live="polite" aria-label={`Map zoom ${Math.round(zoom * 100)} percent`}>{Math.round(zoom * 100)}%</span>
        <button type="button" onClick={() => setZoom(value => Math.min(1.5, value + .15))} aria-label="Zoom in" title="Zoom in"><Plus aria-hidden="true" size={16} /></button>
        <button type="button" onClick={focusGraph}><Focus aria-hidden="true" size={16} /> Fit map</button>
      </div>
    </div>
    {(dense || compact) && <p className="relationship-density-notice" role="status">{dense ? 'This batch has a dense map.' : 'This view is narrow.'} The accessible relationship table is open below for faster review.</p>}
    <p id="relationship-map-instructions" className="relationship-keyboard-help">Select a node to inspect its facts. Use Left/Right or Up/Down arrow keys to move between map nodes; Home and End jump to the first or last node.</p>
    <div className="relationship-map-layout">
      <div ref={viewport} className="relationship-map-viewport" role="region" tabIndex={0} aria-label="Directed relationship graph" aria-describedby="relationship-map-instructions">
        <div className="relationship-map-stage" style={{ width: width * zoom, height: height * zoom }}>
          <svg viewBox={`0 0 ${width} ${height}`} width={width * zoom} height={height * zoom} aria-hidden="true" className="relationship-map-lines">
            <defs><marker id="relationship-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8z" /></marker></defs>
            {visibleEdges.map(edge => { const from = positions.get(edge.sourceId)!; const to = positions.get(edge.targetId)!; const dx = to.x - from.x; const dy = to.y - from.y; const distance = Math.max(1, Math.hypot(dx, dy)); const x1 = from.x + dx / distance * 88; const y1 = from.y + dy / distance * 34; const x2 = to.x - dx / distance * 88; const y2 = to.y - dy / distance * 34; const midX = (x1 + x2) / 2; const midY = (y1 + y2) / 2; return <g key={edge.id} className={selectedEdgeId === edge.id ? 'is-selected' : ''}><path d={`M${x1} ${y1} Q${midX - dy * .14} ${midY + dx * .14} ${x2} ${y2}`} markerEnd="url(#relationship-arrow)" /><text x={midX - dy * .1} y={midY + dx * .1 - 8} textAnchor="middle">{edgeLabel[edge.type]}</text></g> })}
          </svg>
          {visibleNodes.map((node, index) => { const position = positions.get(node.id)!; return <button type="button" key={node.id} ref={element => { if (element) nodeButtons.current.set(node.id, element); else nodeButtons.current.delete(node.id) }} aria-pressed={selected?.id === node.id} aria-label={nodeDescription(node, selected?.id === node.id)} className={`relationship-map-node kind-${node.kind} ${selected?.id === node.id ? 'is-selected' : ''}`} style={{ left: (position.x - 88) * zoom, top: (position.y - 34) * zoom, transform: `scale(${zoom})`, transformOrigin: 'top left' }} onClick={() => selectNode(node.id)} onKeyDown={event => { const nextIndex = moveReviewFocus(index, visibleNodes.length, event.key); if (nextIndex === null) return; event.preventDefault(); selectNode(visibleNodes[nextIndex].id, true) }}><span>{kindLabel[node.kind]}</span><strong>{node.label}</strong></button> })}
        </div>
      </div>
      <aside className="relationship-map-detail" aria-live="polite" aria-atomic="true">
        {selected ? <><span className="relationship-detail-kind">{kindLabel[selected.kind]}</span><h3>{selected.label}</h3><p>{selected.documentIds.length} supporting {selected.documentIds.length === 1 ? 'document' : 'documents'}</p>
          {selectedEdges.length ? <ul>{selectedEdges.map(edge => { const isSource = edge.sourceId === selected.id; const peer = graph.nodes.find(node => node.id === (isSource ? edge.targetId : edge.sourceId)); return <li key={edge.id}><button type="button" onClick={() => selectEdge(edge)}><strong>{isSource ? edgeLabel[edge.type] : `${edgeLabel[edge.type]} from`}</strong><span>{peer?.label ?? 'Unavailable node'}</span></button><div className="relationship-evidence-list">{edge.evidence.map((item, evidenceIndex) => <button type="button" key={`${item.documentId}-${evidenceIndex}`} aria-label={`${item.locator.status !== 'SUPPORTED' ? 'Open document-level evidence in' : item.locator.kind === 'text_span' ? 'Open exact text evidence in' : 'Open approximate OCR evidence in'} ${documentNames.get(item.documentId) ?? 'supporting document'}`} onClick={() => onInspectDocument(item.documentId, item)}><strong>{documentNames.get(item.documentId) ?? 'Supporting document'} · {evidenceLabel[item.rule] ?? 'Explicit evidence'}</strong><small>{evidenceLocation(item)}</small></button>)}</div></li> })}</ul> : <p>No visible explicit links for this node.</p>}</> : <p>Select a node to inspect its explicit relationships.</p>}
      </aside>
    </div>
    <button type="button" className="relationship-fallback-toggle" aria-expanded={tableOpen} aria-controls="relationship-table" onClick={() => setTableOpen(open => !open)}>{tableOpen ? <ChevronUp aria-hidden="true" size={16} /> : <ChevronDown aria-hidden="true" size={16} />} Accessible relationship table{dense ? ' (recommended)' : ''}</button>
    {tableOpen && <div id="relationship-table" className="relationship-table-scroll" tabIndex={0} aria-label="Scrollable relationship review table"><table className="relationship-fallback-table"><caption>Explicit directed relationships in this review batch. Select a source or target to inspect it, or open supporting evidence.</caption><thead><tr><th scope="col">Source</th><th scope="col">Relationship</th><th scope="col">Target</th><th scope="col">Evidence</th></tr></thead><tbody>{visibleEdges.map(edge => { const source = graph.nodes.find(node => node.id === edge.sourceId); const target = graph.nodes.find(node => node.id === edge.targetId); return <tr key={edge.id}><td><button type="button" onClick={() => selectNode(edge.sourceId)}>{source?.label ?? 'Unavailable node'}</button></td><td>{edgeLabel[edge.type]}</td><td><button type="button" onClick={() => selectNode(edge.targetId)}>{target?.label ?? 'Unavailable node'}</button></td><td><ul>{edge.evidence.map((item, evidenceIndex) => <li key={`${item.documentId}-${evidenceIndex}`}><button type="button" onClick={() => onInspectDocument(item.documentId, item)}>{documentNames.get(item.documentId) ?? 'Supporting document'}: {evidenceLocation(item)}</button></li>)}</ul></td></tr> })}{!visibleEdges.length && <tr><td colSpan={4}>No visible relationship edges in this batch.</td></tr>}</tbody></table></div>}
    <p className="relationship-map-note">Arrows represent only documented, typed facts. Where role links exist, mail-only people are hidden until mail links are shown. Labels and evidence use generated aliases and rule names—not source contact details.</p>
  </section>
}
