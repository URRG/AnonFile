import React, { useLayoutEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, ChevronUp, Focus, Minus, Plus } from 'lucide-react'
import type { EntityGraph, EntityGraphEdge, EntityGraphEvidence, EntityGraphNode } from './api'
import './relationship-graph.css'

const edgeLabel: Record<EntityGraphEdge['type'], string> = {
  assistant_to: 'assistant to', assistant_for: 'assistant for', works_at: 'works at', client_of: 'client of', works_on: 'works on', assigned_to: 'assigned to', sent_to: 'sent to',
}
const kindLabel: Record<EntityGraphNode['kind'], string> = { person: 'Person', organization: 'Organization', project: 'Project' }
const evidenceLabel: Record<string, string> = {
  explicit_mail_header: 'Mail header', explicit_structured_field_pair: 'Structured fields',
  explicit_signature_block: 'Named signature', explicit_signature_title: 'Signature role',
  explicit_role_statement: 'Explicit role statement',
}

function layout(nodes: EntityGraphNode[]) {
  const positions = new Map<string, { x: number; y: number }>()
  const people = nodes.filter(n => n.kind === 'person'); const hubs = nodes.filter(n => n.kind !== 'person')
  const extra = Math.max(0, people.length - 6); const radiusX = 390 + extra * 28; const radiusY = 300 + extra * 18
  const width = Math.max(1100, radiusX * 2 + 260); const height = Math.max(850, radiusY * 2 + 230); const centerX = width / 2; const centerY = height / 2
  // Put affiliation/project hubs in a calm central grid. People form a generous outer ring,
  // which keeps node cards and the directed edge labels from occupying the same territory.
  hubs.forEach((node, index) => { const column = index % 2; const row = Math.floor(index / 2); positions.set(node.id, { x: centerX + (column ? 130 : -130), y: centerY + (row - Math.floor((hubs.length - 1) / 2)) * 118 }) })
  people.forEach((node, index) => { const angle = -Math.PI / 2 + index * (Math.PI * 2 / Math.max(people.length, 1)); positions.set(node.id, { x: centerX + Math.cos(angle) * radiusX, y: centerY + Math.sin(angle) * radiusY }) })
  return { positions, width, height }
}

function evidenceLocation(item: EntityGraphEvidence) {
  if (item.locator.status !== 'SUPPORTED') return 'Document-level only · no defensible precise locator'
  if (item.locator.kind === 'ocr_line_boxes') return `Page ${item.locator.page} · approximate OCR line boxes · open source page`
  return `Lines ${item.locator.lineStart}${item.locator.lineEnd === item.locator.lineStart ? '' : `–${item.locator.lineEnd}`} · open exact evidence`
}

export function RelationshipGraph({ graph, documentNames, onInspectDocument }: { graph: EntityGraph; documentNames: Map<string, string>; onInspectDocument: (id: string, evidence: EntityGraphEvidence) => void }) {
  const [selectedId, setSelectedId] = useState<string | null>(graph.nodes[0]?.id ?? null)
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null)
  const [showCommunication, setShowCommunication] = useState(false)
  const [zoom, setZoom] = useState(1)
  const [fallbackOpen, setFallbackOpen] = useState(false)
  const viewport = useRef<HTMLDivElement | null>(null)
  const visibleEdges = useMemo(() => graph.edges.filter(edge => showCommunication || edge.type !== 'sent_to'), [graph.edges, showCommunication])
  const visibleNodes = useMemo(() => {
    if (showCommunication || !visibleEdges.length) return graph.nodes
    const connected = new Set(visibleEdges.flatMap(edge => [edge.sourceId, edge.targetId]))
    return graph.nodes.filter(node => connected.has(node.id))
  }, [graph.nodes, visibleEdges, showCommunication])
  const { positions, width, height } = useMemo(() => layout(visibleNodes), [visibleNodes])
  const selected = visibleNodes.find(node => node.id === selectedId) ?? visibleNodes[0] ?? null
  const selectedEdges = selected ? visibleEdges.filter(edge => edge.sourceId === selected.id || edge.targetId === selected.id) : []
  const selectEdge = (edge: EntityGraphEdge) => { setSelectedId(edge.sourceId); setSelectedEdgeId(edge.id) }
  const focusGraph = () => {
    const bounds = viewport.current?.getBoundingClientRect()
    if (!bounds) return
    setZoom(Math.max(.35, Math.min(1, (bounds.width - 36) / width, (bounds.height - 36) / height)))
  }
  useLayoutEffect(() => {
    // Start with every node visible horizontally. Reviewers can zoom to read
    // details; the fixed-height viewport keeps Fit map from shrinking itself
    // on repeated clicks as the stage dimensions change.
    const available = viewport.current?.clientWidth
    if (available) setZoom(Math.max(.35, Math.min(1, (available - 20) / width)))
  }, [width])

  if (!graph.nodes.length) return <div className="relationship-graph-empty"><strong>No structured relationship map yet</strong><p>Only explicit fields can create a node or link; nothing is inferred from nearby text.</p></div>
  return <section className="relationship-map" aria-label="Entity relationship map">
    <div className="relationship-map-toolbar">
      <label className="relationship-toggle"><input type="checkbox" checked={showCommunication} onChange={event => setShowCommunication(event.target.checked)} /> Include mail links (sent to)</label>
      <div role="group" aria-label="Map view controls" className="relationship-map-controls">
        <button type="button" onClick={() => setZoom(value => Math.max(.35, value - .15))} aria-label="Zoom out"><Minus size={16} /></button>
        <span aria-live="polite">{Math.round(zoom * 100)}%</span>
        <button type="button" onClick={() => setZoom(value => Math.min(1.5, value + .15))} aria-label="Zoom in"><Plus size={16} /></button>
        <button type="button" onClick={focusGraph}><Focus size={16} /> Fit map</button>
      </div>
    </div>
    <div className="relationship-map-layout">
      <div ref={viewport} className="relationship-map-viewport" aria-label="Directed relationship graph. Select a node for details.">
        <div className="relationship-map-stage" style={{ width: width * zoom, height: height * zoom }}>
          <svg viewBox={`0 0 ${width} ${height}`} width={width * zoom} height={height * zoom} aria-hidden="true" className="relationship-map-lines">
            <defs><marker id="relationship-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8z" /></marker></defs>
            {visibleEdges.map(edge => { const from = positions.get(edge.sourceId)!; const to = positions.get(edge.targetId)!; const dx = to.x - from.x; const dy = to.y - from.y; const distance = Math.max(1, Math.hypot(dx, dy)); const x1 = from.x + dx / distance * 88; const y1 = from.y + dy / distance * 34; const x2 = to.x - dx / distance * 88; const y2 = to.y - dy / distance * 34; const midX = (x1 + x2) / 2; const midY = (y1 + y2) / 2; return <g key={edge.id} className={selectedEdgeId === edge.id ? 'is-selected' : ''}><path d={`M${x1} ${y1} Q${midX - dy * .14} ${midY + dx * .14} ${x2} ${y2}`} markerEnd="url(#relationship-arrow)" /><text x={midX - dy * .1} y={midY + dx * .1 - 8} textAnchor="middle">{edgeLabel[edge.type]}</text></g> })}
          </svg>
          {visibleNodes.map(node => { const position = positions.get(node.id)!; return <button type="button" key={node.id} aria-pressed={selected?.id === node.id} className={`relationship-map-node kind-${node.kind} ${selected?.id === node.id ? 'is-selected' : ''}`} style={{ left: (position.x - 88) * zoom, top: (position.y - 34) * zoom, transform: `scale(${zoom})`, transformOrigin: 'top left' }} onClick={() => setSelectedId(node.id)}><span>{kindLabel[node.kind]}</span><strong>{node.label}</strong></button> })}
        </div>
      </div>
      <aside className="relationship-map-detail" aria-live="polite">
        {selected ? <><span className="relationship-detail-kind">{kindLabel[selected.kind]}</span><h3>{selected.label}</h3><p>{selected.documentIds.length} supporting {selected.documentIds.length === 1 ? 'document' : 'documents'}</p>
          {selectedEdges.length ? <ul>{selectedEdges.map(edge => { const isSource = edge.sourceId === selected.id; const peer = graph.nodes.find(node => node.id === (isSource ? edge.targetId : edge.sourceId)); return <li key={edge.id}><button type="button" onClick={() => selectEdge(edge)}><strong>{isSource ? edgeLabel[edge.type] : `${edgeLabel[edge.type]} from`}</strong><span>{peer?.label ?? 'Unavailable node'}</span></button><div className="relationship-evidence-list">{edge.evidence.map((item, index) => <button type="button" key={`${item.documentId}-${index}`} aria-label={`${item.locator.status !== 'SUPPORTED' ? 'Open document-level evidence in' : item.locator.kind === 'text_span' ? 'Open exact text evidence in' : 'Open approximate OCR evidence in'} ${documentNames.get(item.documentId) ?? 'supporting document'}`} onClick={() => onInspectDocument(item.documentId, item)}><strong>{documentNames.get(item.documentId) ?? 'Supporting document'} · {evidenceLabel[item.rule] ?? 'Explicit evidence'}</strong><small>{evidenceLocation(item)}</small></button>)}</div></li> })}</ul> : <p>No visible explicit links for this node.</p>}</> : <p>Select a node to inspect its explicit relationships.</p>}
      </aside>
    </div>
    <button type="button" className="relationship-fallback-toggle" aria-expanded={fallbackOpen} onClick={() => setFallbackOpen(open => !open)}>{fallbackOpen ? <ChevronUp size={16} /> : <ChevronDown size={16} />} Accessible relationship list</button>
    {fallbackOpen && <ul className="relationship-fallback-list" aria-label="Accessible directed relationship list">{visibleEdges.map(edge => { const source = graph.nodes.find(node => node.id === edge.sourceId); const target = graph.nodes.find(node => node.id === edge.targetId); return <li key={edge.id}><button type="button" onClick={() => setSelectedId(edge.sourceId)}>{source?.label} <strong>{edgeLabel[edge.type]}</strong> {target?.label}</button><span>{edge.evidence.map(item => `${documentNames.get(item.documentId) ?? `Document ${item.documentId}`} (${item.locator.status !== 'SUPPORTED' ? 'document-level only' : item.locator.kind === 'ocr_line_boxes' ? `page ${item.locator.page}, approximate OCR boxes` : `lines ${item.locator.lineStart}${item.locator.lineEnd === item.locator.lineStart ? '' : `–${item.locator.lineEnd}`}`})`).join(', ')}</span></li> })}{!visibleEdges.length && <li>No visible relationship edges in this batch.</li>}</ul>}
    <p className="relationship-map-note">Arrows represent only documented, typed facts. Where role links exist, mail-only people are hidden until mail links are shown. Labels and evidence use generated aliases and rule names—not source contact details.</p>
  </section>
}
