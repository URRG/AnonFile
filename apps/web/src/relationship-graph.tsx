import React, { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, ChevronUp, Focus, Minus, Plus } from 'lucide-react'
import { decideRecordedGraphClaim, getRecordedGraphReview, mergeRecordedGraphIdentities, splitRecordedGraphIdentity, GraphReviewFailure, type BatchGraphReviewBinding, type EntityGraph, type EntityGraphEdge, type EntityGraphEvidence, type EntityGraphNode, type RecordedGraphReview } from './api'
import { isDenseReviewGraph, moveReviewFocus, readableReviewZoom } from './review-navigation'
import { relationshipConflictCues, reviewStatusFor, selectionForGraph, validateMergeProposal, type EphemeralEdgeReview, type GraphSelection, type RelationshipConflictCue } from './relationship-review'
import './relationship-graph.css'

const edgeLabel: Record<EntityGraphEdge['type'], string> = {
  assistant_to: 'assistant to', assistant_for: 'assistant for', works_at: 'works at', client_of: 'client of', works_on: 'works on', assigned_to: 'assigned to', sent_to: 'sent to',
}
const kindLabel: Record<EntityGraphNode['kind'], string> = { person: 'Person', organization: 'Organization', project: 'Project' }
const evidenceLabel: Record<string, string> = {
  explicit_mail_header: 'Mail header', explicit_structured_field_pair: 'Structured fields',
  explicit_signature_block: 'Named signature', explicit_signature_title: 'Signature role', explicit_role_statement: 'Explicit role statement',
}
const reviewLabel: Record<EphemeralEdgeReview, string> = { pending: 'Pending', accepted: 'Accepted', rejected: 'Rejected' }
const conflictLabel: Record<RelationshipConflictCue['code'], string> = {
  MULTIPLE_WORKS_AT: 'Multiple explicit affiliation claims need review.',
  MULTIPLE_ASSIGNED_TO: 'Multiple explicit assignment claims need review.',
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

function EdgeReviewControls({ edge, sourceLabel, targetLabel, status, cue, onStatusChange }: { edge: EntityGraphEdge; sourceLabel: string; targetLabel: string; status: EphemeralEdgeReview; cue?: RelationshipConflictCue; onStatusChange: (status: EphemeralEdgeReview) => void }) {
  return <div className="relationship-edge-review">
    <span className={`relationship-review-status is-${status}`}>Review: {reviewLabel[status]}</span>
    <select className="relationship-review-select" aria-label={`Temporary review: ${sourceLabel} ${edgeLabel[edge.type]} ${targetLabel}`} value={status} onChange={event => onStatusChange(event.target.value as EphemeralEdgeReview)}>
      {(['pending', 'accepted', 'rejected'] as const).map(next => <option key={next} value={next}>{reviewLabel[next]}</option>)}
    </select>
    {cue && <p className="relationship-conflict-cue" role="status">{conflictLabel[cue.code]}</p>}
  </div>
}

function RecordedGraphReviewPanel({ graph, binding, apiBase }: { graph: EntityGraph; binding: BatchGraphReviewBinding; apiBase: string }) {
  const [token, setToken] = useState(''); const [review, setReview] = useState<RecordedGraphReview | null>(null); const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('Enter a reviewer token, then load the recorded development review.')
  const [mergeDraft, setMergeDraft] = useState({ canonical: '', member: '' }); const [splitDraft, setSplitDraft] = useState({ source: '', first: '', second: '', assignments: {} as Record<string, string> })
  const claimToEdge = useMemo(() => new Map(binding.claims.map(item => [item.claimRef, graph.edges.find(edge => edge.id === item.graphEdgeId)])), [binding, graph])
  const people = useMemo(() => { const result = new Map<string, EntityGraphNode>(); for (const item of binding.nodes) { const node = graph.nodes.find(candidate => candidate.id === item.graphNodeId); if (node?.kind === 'person') result.set(item.nodeRef, node) } return result }, [binding, graph])
  // Durable review must not turn a graph's public labels back into a source
  // display. These aliases are generated from the response-local binding only.
  const aliases = useMemo(() => { const counts: Record<string, number> = { person: 0, organization: 0, project: 0 }; const result = new Map<string, string>(); for (const item of binding.nodes) { const kind = graph.nodes.find(node => node.id === item.graphNodeId)?.kind; if (!kind) continue; counts[kind] += 1; result.set(item.nodeRef, `${kindLabel[kind]} alias ${counts[kind]}`) } return result }, [binding, graph])
  const activePeople = useMemo(() => { const active = new Set(people.keys()); for (const action of review?.identityActions ?? []) { if (action.action === 'MERGE') { action.memberPersonRefs.forEach(ref => active.delete(ref)); active.add(action.canonicalPersonRef) } else { active.delete(action.sourcePersonRef); action.replacementPersonRefs.forEach(ref => active.add(ref)) } } return [...active] }, [people, review])
  const splitEndpoints = useMemo(() => {
    if (!review || !splitDraft.source) return [] as { claimRef: string; endpoint: 'source' | 'target' }[]
    const refs = new Map(binding.nodes.map(item => [item.graphNodeId, item.nodeRef])); const effective = new Map<string, string>(); const rejected = new Set(review.decisions.filter(item => item.decision === 'REJECT').map(item => item.claimRef))
    for (const item of binding.claims) { const edge = claimToEdge.get(item.claimRef); if (!edge) continue; const source = refs.get(edge.sourceId), target = refs.get(edge.targetId); if (source && people.has(source)) effective.set(`${item.claimRef}:source`, source); if (target && people.has(target)) effective.set(`${item.claimRef}:target`, target) }
    for (const action of review.identityActions) { if (action.action === 'MERGE') { for (const [key, value] of effective) if (action.memberPersonRefs.includes(value)) effective.set(key, action.canonicalPersonRef) } else for (const assignment of action.endpointAssignments) effective.set(`${assignment.claimRef}:${assignment.endpoint}`, assignment.replacementPersonRef) }
    return [...effective].filter(([key, ref]) => ref === splitDraft.source && !rejected.has(key.slice(0, key.lastIndexOf(':')))).map(([key]) => { const marker = key.lastIndexOf(':'); return { claimRef: key.slice(0, marker), endpoint: key.slice(marker + 1) as 'source' | 'target' } })
  }, [binding, claimToEdge, people, review, splitDraft.source])
  const resetDrafts = () => { setMergeDraft({ canonical: '', member: '' }); setSplitDraft({ source: '', first: '', second: '', assignments: {} }) }
  const load = async () => { if (busy) return; setBusy(true); setMessage('Loading recorded review…'); try { setReview(await getRecordedGraphReview({ apiBase, token, binding, graph })); resetDrafts(); setMessage('Recorded review loaded. Actions write only to the configured encrypted development store.') } catch (cause) { setReview(null); resetDrafts(); setMessage(cause instanceof Error ? cause.message : 'Recorded review could not be loaded.') } finally { setBusy(false) } }
  const decide = async (claimRef: string, decision: 'ACCEPT' | 'REJECT') => { if (!review || busy) return; setBusy(true); setMessage('Saving recorded decision…'); try { setReview(await decideRecordedGraphClaim({ apiBase, token, binding, graph, claimRef, decision, expectedRevision: review.revision })); setMessage('Recorded decision saved. It is not a release, delivery, export, or identity-resolution decision.') } catch (cause) { if (cause instanceof GraphReviewFailure && cause.status !== undefined) { if (cause.status === 404 || cause.status === 409) setReview(null); setMessage(cause.message) } else { setReview(null); setMessage('Recorded decision outcome may be unverified. Reload the graph before retrying.') } } finally { setBusy(false) } }
  const identityFailure = (cause: unknown) => { if (cause instanceof GraphReviewFailure && cause.status !== undefined) { if (cause.status === 404 || cause.status === 409) setReview(null); setMessage(cause.message) } else { setReview(null); setMessage('Recorded identity outcome may be unverified. Reload the graph before retrying.') } }
  const merge = async () => { if (!review || busy || !mergeDraft.canonical || !mergeDraft.member || mergeDraft.canonical === mergeDraft.member) return; setBusy(true); setMessage('Saving recorded identity merge…'); try { setReview(await mergeRecordedGraphIdentities({ apiBase, token, binding, graph, canonicalPersonRef: mergeDraft.canonical, memberPersonRefs: [mergeDraft.canonical, mergeDraft.member], expectedRevision: review.revision })); resetDrafts(); setMessage('Recorded identity merge saved. It changes only reviewer-recorded graph endpoints, never source evidence or release authority.') } catch (cause) { identityFailure(cause) } finally { setBusy(false) } }
  const split = async () => { if (!review || busy || !splitDraft.source || !splitDraft.first || !splitDraft.second || splitDraft.first === splitDraft.second || splitDraft.source === splitDraft.first || splitDraft.source === splitDraft.second || splitEndpoints.some(item => !splitDraft.assignments[`${item.claimRef}:${item.endpoint}`])) return; setBusy(true); setMessage('Saving recorded identity split…'); try { setReview(await splitRecordedGraphIdentity({ apiBase, token, binding, graph, sourcePersonRef: splitDraft.source, replacementPersonRefs: [splitDraft.first, splitDraft.second], endpointAssignments: splitEndpoints.map(item => ({ ...item, replacementPersonRef: splitDraft.assignments[`${item.claimRef}:${item.endpoint}`] })), expectedRevision: review.revision })); resetDrafts(); setMessage('Recorded identity split saved. It changes only reviewer-recorded graph endpoints, never source evidence or release authority.') } catch (cause) { identityFailure(cause) } finally { setBusy(false) } }
  const decisionFor = (claimRef: string) => review?.decisions.find(item => item.claimRef === claimRef)?.decision ?? 'UNDECIDED'
  const claimControl = (claimRef: string) => { const edge = claimToEdge.get(claimRef); if (!edge) return null; const refs = new Map(binding.nodes.map(item => [item.graphNodeId, item.nodeRef])); const state = decisionFor(claimRef); return <article key={claimRef}><div><strong>{aliases.get(refs.get(edge.sourceId) ?? '') ?? 'Unavailable alias'} {edgeLabel[edge.type]} {aliases.get(refs.get(edge.targetId) ?? '') ?? 'Unavailable alias'}</strong><span className={`recorded-decision is-${state.toLowerCase()}`}>Recorded: {state}</span></div><div className="recorded-actions"><button type="button" disabled={busy} onClick={() => void decide(claimRef, 'ACCEPT')}>Accept claim</button><button type="button" disabled={busy} onClick={() => void decide(claimRef, 'REJECT')}>Reject claim</button></div></article> }
  return <section className="recorded-graph-review" aria-label="Recorded graph review"><div className="recorded-graph-heading"><div><p className="overline">RECORDED DEVELOPMENT REVIEW</p><h3>Reviewer decisions</h3></div><span className="recorded-status">{review ? `Recorded · revision ${review.revision}` : 'Not loaded'}</span></div><p>This optional panel is available only for the graph recorded with this inspection. It shows generated aliases and typed claims only; it does not show source evidence.</p><label className="recorded-token">Reviewer token<input type="password" value={token} autoComplete="off" spellCheck={false} onChange={event => { setToken(event.target.value); setReview(null); resetDrafts(); setMessage('Token changed. Reload the recorded review before making a decision.') }} /></label><button type="button" className="recorded-load" disabled={busy || !token.trim()} onClick={() => void load()}>{busy ? 'Working…' : review ? 'Reload recorded review' : 'Load recorded review'}</button><p className="recorded-message" role="status" aria-live="polite">{message}</p>{review && <div className="recorded-claim-list"><p className="recorded-scope">Claims and identity actions are bound to this graph response. A stale revision or uncertain outcome fails closed; reload before retrying.</p>{review.conflictGroups.length > 0 && <section className="recorded-conflict-groups" aria-label="Typed conflict groups"><h4>Typed conflict groups</h4>{review.conflictGroups.map(group => <div key={`${group.kind}:${group.subjectRef}`}><strong>{group.kind === 'POTENTIAL_MULTIPLE_WORKS_AT' ? 'Multiple affiliations' : 'Multiple assignments'} · {aliases.get(group.subjectRef) ?? 'Unavailable alias'}</strong><p>Review the bound accepted claims below. This remains an unresolved review prompt, not a release decision.</p>{group.claimRefs.map(claimControl)}</div>)}</section>}<details><summary>All bound claims</summary>{binding.claims.map(item => claimControl(item.claimRef))}</details><div className="recorded-identity"><strong>Recorded identity overlays</strong><p>Aliases are generated for this loaded snapshot. These actions do not merge source records or expose evidence.</p><div className="recorded-identity-controls"><label>Keep alias<select value={mergeDraft.canonical} onChange={event => setMergeDraft({ canonical: event.target.value, member: '' })}><option value="">Choose a person</option>{activePeople.map(ref => <option key={ref} value={ref}>{aliases.get(ref) ?? 'Unavailable alias'}</option>)}</select></label><label>Merge alias<select value={mergeDraft.member} onChange={event => setMergeDraft({ ...mergeDraft, member: event.target.value })}><option value="">Choose a different person</option>{activePeople.filter(ref => ref !== mergeDraft.canonical).map(ref => <option key={ref} value={ref}>{aliases.get(ref) ?? 'Unavailable alias'}</option>)}</select></label><button type="button" disabled={busy || !mergeDraft.canonical || !mergeDraft.member} onClick={() => void merge()}>Record merge</button></div><div className="recorded-identity-controls"><label>Split alias<select value={splitDraft.source} onChange={event => setSplitDraft({ source: event.target.value, first: '', second: '', assignments: {} })}><option value="">Choose a person</option>{activePeople.map(ref => <option key={ref} value={ref}>{aliases.get(ref) ?? 'Unavailable alias'}</option>)}</select></label><label>First replacement<select value={splitDraft.first} onChange={event => setSplitDraft({ ...splitDraft, first: event.target.value, assignments: {} })}><option value="">Choose a person</option>{activePeople.filter(ref => ref !== splitDraft.source && ref !== splitDraft.second).map(ref => <option key={ref} value={ref}>{aliases.get(ref) ?? 'Unavailable alias'}</option>)}</select></label><label>Second replacement<select value={splitDraft.second} onChange={event => setSplitDraft({ ...splitDraft, second: event.target.value, assignments: {} })}><option value="">Choose a different person</option>{activePeople.filter(ref => ref !== splitDraft.source && ref !== splitDraft.first).map(ref => <option key={ref} value={ref}>{aliases.get(ref) ?? 'Unavailable alias'}</option>)}</select></label></div>{splitDraft.source && splitDraft.first && splitDraft.second && <div className="recorded-split-assignments">{splitEndpoints.length ? splitEndpoints.map(item => <label key={`${item.claimRef}:${item.endpoint}`}>Assign claim {item.endpoint}<select value={splitDraft.assignments[`${item.claimRef}:${item.endpoint}`] ?? ''} onChange={event => setSplitDraft({ ...splitDraft, assignments: { ...splitDraft.assignments, [`${item.claimRef}:${item.endpoint}`]: event.target.value } })}><option value="">Choose replacement</option><option value={splitDraft.first}>{aliases.get(splitDraft.first) ?? 'Unavailable alias'}</option><option value={splitDraft.second}>{aliases.get(splitDraft.second) ?? 'Unavailable alias'}</option></select></label>) : <p>No accepted current-person claim endpoints require reassignment.</p>}<button type="button" disabled={busy || splitEndpoints.some(item => !splitDraft.assignments[`${item.claimRef}:${item.endpoint}`])} onClick={() => void split()}>Record split</button></div>}</div></div>}<p className="recorded-limit">Recorded decisions and identity overlays do not authorize release, delivery, export, or a source-record identity claim.</p></section>
}

export function RelationshipGraph({ graph, documentNames, onInspectDocument, graphReview, apiBase }: { graph: EntityGraph; documentNames: Map<string, string>; onInspectDocument: (id: string, evidence: EntityGraphEvidence) => void; graphReview?: BatchGraphReviewBinding | null; apiBase?: string }) {
  const [selectionState, setSelectionState] = useState<GraphSelection>({ graph, nodeId: graph.nodes[0]?.id ?? null, edgeId: null })
  const selection = selectionForGraph(graph, selectionState)
  const selectedId = selection.nodeId
  const selectedEdgeId = selection.edgeId
  const [showCommunication, setShowCommunication] = useState(false)
  const [zoom, setZoom] = useState(1)
  const [tableOpen, setTableOpen] = useState(false)
  const [compact, setCompact] = useState(false)
  const [reviewState, setReviewState] = useState<{ graph: EntityGraph; reviews: Record<string, EphemeralEdgeReview> }>({ graph, reviews: {} })
  const [mergeDraftState, setMergeDraftState] = useState<{ graph: EntityGraph; firstId: string; secondId: string }>({ graph, firstId: '', secondId: '' })
  const [mergeProposalState, setMergeProposalState] = useState<{ graph: EntityGraph; pair: readonly [string, string] | null }>({ graph, pair: null })
  // Treat an incoming graph object as a new inspection immediately, before
  // effects or paint. Response-local edge IDs may recur for unrelated data.
  const edgeReviews = reviewState.graph === graph ? reviewState.reviews : {}
  const mergeDraft = mergeDraftState.graph === graph ? mergeDraftState : { graph, firstId: '', secondId: '' }
  const mergeProposal = mergeProposalState.graph === graph ? mergeProposalState.pair : null
  const personNodes = graph.nodes.filter(node => node.kind === 'person')
  const recordedMode = Boolean(graphReview && apiBase)
  const mergeIssue = mergeDraft.firstId && mergeDraft.secondId ? validateMergeProposal(graph, mergeDraft.firstId, mergeDraft.secondId) : null
  const mergeIssueMessage = mergeIssue === 'SAME_PERSON' ? 'Choose two different people.' : mergeIssue === 'SELF_LINK' ? 'These people have a direct relationship that would become a self-link.' : mergeIssue ? 'Only current person aliases can be proposed.' : null
  const viewport = useRef<HTMLDivElement | null>(null)
  const nodeButtons = useRef(new Map<string, HTMLButtonElement>())
  const visibleEdges = useMemo(() => graph.edges.filter(edge => showCommunication || edge.type !== 'sent_to'), [graph.edges, showCommunication])
  const visibleNodes = useMemo(() => {
    if (showCommunication || !visibleEdges.length) return graph.nodes
    const connected = new Set(visibleEdges.flatMap(edge => [edge.sourceId, edge.targetId]))
    return graph.nodes.filter(node => connected.has(node.id))
  }, [graph.nodes, visibleEdges, showCommunication])
  const dense = isDenseReviewGraph(visibleNodes.length, visibleEdges.length)
  const conflictCues = useMemo(() => relationshipConflictCues(visibleEdges, edgeReviews), [visibleEdges, edgeReviews])
  const { positions, width, height } = useMemo(() => layout(visibleNodes), [visibleNodes])
  const selected = visibleNodes.find(node => node.id === selectedId) ?? visibleNodes[0] ?? null
  const selectedEdges = selected ? visibleEdges.filter(edge => edge.sourceId === selected.id || edge.targetId === selected.id) : []
  const selectNode = (id: string, focus = false) => {
    setSelectionState({ graph, nodeId: id, edgeId: null })
    if (focus) requestAnimationFrame(() => nodeButtons.current.get(id)?.focus())
  }
  const selectEdge = (edge: EntityGraphEdge) => setSelectionState({ graph, nodeId: edge.sourceId, edgeId: edge.id })
  const setEdgeReview = (edgeId: string, status: EphemeralEdgeReview) => setReviewState(current => ({ graph,
    reviews: { ...(current.graph === graph ? current.reviews : {}), [edgeId]: status } }))
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
    if (typeof ResizeObserver === 'undefined') {
      window.addEventListener('resize', update)
      return () => window.removeEventListener('resize', update)
    }
    const observer = new ResizeObserver(update)
    observer.observe(element)
    return () => observer.disconnect()
  }, [width])
  useEffect(() => { if (dense || compact) setTableOpen(true) }, [dense, compact])
  useEffect(() => {
    if (selectedId && visibleNodes.some(node => node.id === selectedId)) return
    setSelectionState({ graph, nodeId: visibleNodes[0]?.id ?? null, edgeId: null })
  }, [graph, selectedId, visibleNodes])

  if (!graph.nodes.length) return <div className="relationship-graph-empty"><strong>No structured relationship map yet</strong><p>Only explicit fields can create a node or link; nothing is inferred from nearby text.</p></div>
  return <section className="relationship-map" aria-label="Entity relationship map">
    <p className="relationship-screenreader-status" role="status" aria-live="polite">{selected ? `Selected ${selected.label}. ${selectedEdges.length} visible explicit ${selectedEdges.length === 1 ? 'relationship' : 'relationships'}.` : 'No node selected.'}</p>
    <div className="relationship-map-toolbar">
      <label className="relationship-toggle"><input type="checkbox" checked={showCommunication} onChange={event => setShowCommunication(event.target.checked)} /> Include mail links (sent to)</label>
      <div role="group" aria-label="Map view controls" className="relationship-map-controls">
        <button type="button" onClick={() => setZoom(value => Math.max(.8, value - .15))} aria-label="Zoom out" title="Zoom out"><Minus aria-hidden="true" size={16} /></button>
        <span aria-live="polite" aria-label={`Map zoom ${Math.round(zoom * 100)} percent`}>{Math.round(zoom * 100)}%</span>
        <button type="button" onClick={() => setZoom(value => Math.min(1.5, value + .15))} aria-label="Zoom in" title="Zoom in"><Plus aria-hidden="true" size={16} /></button>
        <button type="button" onClick={focusGraph}><Focus aria-hidden="true" size={16} /> Fit map</button>
      </div>
    </div>
    {graphReview && apiBase && <RecordedGraphReviewPanel graph={graph} binding={graphReview} apiBase={apiBase} />}
    {!recordedMode && <section className="relationship-identity-review" aria-label="Temporary identity merge proposal">
      <div><strong>Identity review · proposal only</strong><p>Compare two generated person aliases. A proposal does not merge nodes, rewrite evidence, or authorize release.</p></div>
      <div className="relationship-identity-controls">
        <label>First person<select value={mergeDraft.firstId} onChange={event => { setMergeDraftState({ graph, firstId: event.target.value, secondId: mergeDraft.secondId }); setMergeProposalState({ graph, pair: null }) }}><option value="">Choose a person</option>{personNodes.map(node => <option key={node.id} value={node.id}>{node.label}</option>)}</select></label>
        <label>Second person<select value={mergeDraft.secondId} onChange={event => { setMergeDraftState({ graph, firstId: mergeDraft.firstId, secondId: event.target.value }); setMergeProposalState({ graph, pair: null }) }}><option value="">Choose a person</option>{personNodes.map(node => <option key={node.id} value={node.id}>{node.label}</option>)}</select></label>
        <button type="button" disabled={!mergeDraft.firstId || !mergeDraft.secondId || mergeIssue !== null} onClick={() => setMergeProposalState({ graph, pair: [mergeDraft.firstId, mergeDraft.secondId] })}>Propose merge</button>
        {mergeProposal && <button type="button" onClick={() => setMergeProposalState({ graph, pair: null })}>Clear proposal</button>}
      </div>
      <p className="relationship-identity-status" role="status" aria-live="polite">{mergeIssueMessage ?? (mergeProposal ? `Proposal only: ${graph.nodes.find(node => node.id === mergeProposal[0])?.label} and ${graph.nodes.find(node => node.id === mergeProposal[1])?.label} may refer to one person. No graph change was made.` : 'No identity merge proposed. Identity split is not available in this preview.')}</p>
    </section>}
    {(dense || compact) && <p className="relationship-density-notice" role="status">{dense ? 'This batch has a dense map.' : 'This view is narrow.'} The accessible relationship table is open below for faster review.</p>}
    <p id="relationship-map-instructions" className="relationship-keyboard-help">Select a node to inspect its facts. Use Left/Right or Up/Down arrow keys to move between map nodes; Home and End jump to the first or last node.</p>
    <div className="relationship-map-layout">
      <div ref={viewport} className="relationship-map-viewport" role="region" aria-label="Directed relationship graph" aria-describedby="relationship-map-instructions">
        <div className="relationship-map-stage" style={{ width: width * zoom, height: height * zoom }}>
          <svg viewBox={`0 0 ${width} ${height}`} width={width * zoom} height={height * zoom} aria-hidden="true" className="relationship-map-lines">
            <defs><marker id="relationship-arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8z" /></marker></defs>
            {visibleEdges.map(edge => { const from = positions.get(edge.sourceId)!; const to = positions.get(edge.targetId)!; const dx = to.x - from.x; const dy = to.y - from.y; const distance = Math.max(1, Math.hypot(dx, dy)); const x1 = from.x + dx / distance * 88; const y1 = from.y + dy / distance * 34; const x2 = to.x - dx / distance * 88; const y2 = to.y - dy / distance * 34; const midX = (x1 + x2) / 2; const midY = (y1 + y2) / 2; return <g key={edge.id} className={selectedEdgeId === edge.id ? 'is-selected' : ''}><path d={`M${x1} ${y1} Q${midX - dy * .14} ${midY + dx * .14} ${x2} ${y2}`} markerEnd="url(#relationship-arrow)" /><text x={midX - dy * .1} y={midY + dx * .1 - 8} textAnchor="middle">{edgeLabel[edge.type]}</text></g> })}
          </svg>
          {visibleNodes.map((node, index) => { const position = positions.get(node.id)!; const isSelected = selected?.id === node.id; return <button type="button" key={node.id} ref={element => { if (element) nodeButtons.current.set(node.id, element); else nodeButtons.current.delete(node.id) }} tabIndex={isSelected ? 0 : -1} aria-pressed={isSelected} aria-label={nodeDescription(node, isSelected)} className={`relationship-map-node kind-${node.kind} ${isSelected ? 'is-selected' : ''}`} style={{ left: (position.x - 88) * zoom, top: (position.y - 34) * zoom, transform: `scale(${zoom})`, transformOrigin: 'top left' }} onClick={() => selectNode(node.id)} onKeyDown={event => { const nextIndex = moveReviewFocus(index, visibleNodes.length, event.key); if (nextIndex === null) return; event.preventDefault(); selectNode(visibleNodes[nextIndex].id, true) }}><span>{kindLabel[node.kind]}</span><strong>{node.label}</strong></button> })}
        </div>
      </div>
      <aside className="relationship-map-detail">
        {selected ? <><span className="relationship-detail-kind">{kindLabel[selected.kind]}</span><h3>{selected.label}</h3><p>{selected.documentIds.length} supporting {selected.documentIds.length === 1 ? 'document' : 'documents'}</p>
          {selectedEdges.length ? <ul>{selectedEdges.map(edge => { const isSource = edge.sourceId === selected.id; const peer = graph.nodes.find(node => node.id === (isSource ? edge.targetId : edge.sourceId)); const status = reviewStatusFor(edge.id, edgeReviews); return <li key={edge.id}><button type="button" onClick={() => selectEdge(edge)}><strong>{isSource ? edgeLabel[edge.type] : `${edgeLabel[edge.type]} from`}</strong><span>{peer?.label ?? 'Unavailable node'}</span></button>{!recordedMode && <EdgeReviewControls edge={edge} sourceLabel={graph.nodes.find(node => node.id === edge.sourceId)?.label ?? 'Unavailable source'} targetLabel={graph.nodes.find(node => node.id === edge.targetId)?.label ?? 'Unavailable target'} status={status} cue={conflictCues.get(edge.id)} onStatusChange={next => setEdgeReview(edge.id, next)} />}<div className="relationship-evidence-list">{edge.evidence.map((item, evidenceIndex) => <button type="button" key={`${item.documentId}-${evidenceIndex}`} aria-label={`${item.locator.status !== 'SUPPORTED' ? 'Open document-level evidence in' : item.locator.kind === 'text_span' ? 'Open exact text evidence in' : 'Open approximate OCR evidence in'} ${documentNames.get(item.documentId) ?? 'supporting document'}`} onClick={() => onInspectDocument(item.documentId, item)}><strong>{documentNames.get(item.documentId) ?? 'Supporting document'} · {evidenceLabel[item.rule] ?? 'Explicit evidence'}</strong><small>{evidenceLocation(item)}</small></button>)}</div></li> })}</ul> : <p>No visible explicit links for this node.</p>}</> : <p>Select a node to inspect its explicit relationships.</p>}
      </aside>
    </div>
    <button type="button" className="relationship-fallback-toggle" aria-expanded={tableOpen} aria-controls="relationship-table" onClick={() => setTableOpen(open => !open)}>{tableOpen ? <ChevronUp aria-hidden="true" size={16} /> : <ChevronDown aria-hidden="true" size={16} />} Accessible relationship table{dense ? ' (recommended)' : ''}</button>
    {tableOpen && <div id="relationship-table" className="relationship-table-scroll" tabIndex={0} aria-label="Scrollable relationship review table"><table className="relationship-fallback-table"><caption>{recordedMode ? 'Explicit directed relationships in this recorded review batch. Select a source, target, or supporting evidence to inspect it.' : 'Explicit directed relationships in this review batch. Select a source or target to inspect it, mark a temporary review state, or open supporting evidence.'}</caption><thead><tr><th scope="col">Source</th><th scope="col">Relationship</th><th scope="col">Target</th>{!recordedMode && <th scope="col">Review</th>}<th scope="col">Evidence</th></tr></thead><tbody>{visibleEdges.map(edge => { const source = graph.nodes.find(node => node.id === edge.sourceId); const target = graph.nodes.find(node => node.id === edge.targetId); const status = reviewStatusFor(edge.id, edgeReviews); return <tr key={edge.id}><td><button type="button" onClick={() => selectNode(edge.sourceId)}>{source?.label ?? 'Unavailable node'}</button></td><td>{edgeLabel[edge.type]}</td><td><button type="button" onClick={() => selectNode(edge.targetId)}>{target?.label ?? 'Unavailable node'}</button></td>{!recordedMode && <td><EdgeReviewControls edge={edge} sourceLabel={source?.label ?? 'Unavailable source'} targetLabel={target?.label ?? 'Unavailable target'} status={status} cue={conflictCues.get(edge.id)} onStatusChange={next => setEdgeReview(edge.id, next)} /></td>}<td><ul>{edge.evidence.map((item, evidenceIndex) => <li key={`${item.documentId}-${evidenceIndex}`}><button type="button" onClick={() => onInspectDocument(item.documentId, item)}>{documentNames.get(item.documentId) ?? 'Supporting document'}: {evidenceLocation(item)}</button></li>)}</ul></td></tr> })}{!visibleEdges.length && <tr><td colSpan={recordedMode ? 4 : 5}>No visible relationship edges in this batch.</td></tr>}</tbody></table></div>}
    <p className="relationship-review-note">{recordedMode ? 'Recorded mode is active: use the reviewer decision panel above. The map and table remain navigation-only until a recorded review is loaded.' : 'Review choices are local to this open synthetic batch and reset after reload or a changed graph. They are not stored adjudications, release decisions, or identity merges/splits.'}</p>
    <p className="relationship-map-note">Arrows represent only documented, typed facts. Where role links exist, mail-only people are hidden until mail links are shown. Labels and evidence use generated aliases and rule names—not source contact details.</p>
  </section>
}
