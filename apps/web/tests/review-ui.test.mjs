import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const navigationSource = readFileSync(new URL('../src/review-navigation.ts', import.meta.url), 'utf8')
const navigationCompiled = ts.transpileModule(navigationSource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { isDenseReviewGraph, moveReviewFocus, readableReviewZoom } = await import(`data:text/javascript;base64,${Buffer.from(navigationCompiled).toString('base64')}`)
const reviewSource = readFileSync(new URL('../src/relationship-review.ts', import.meta.url), 'utf8')
const reviewCompiled = ts.transpileModule(reviewSource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { relationshipConflictCues, reviewStatusFor, selectionForGraph, validateMergeProposal } = await import(`data:text/javascript;base64,${Buffer.from(reviewCompiled).toString('base64')}`)
const graphSource = readFileSync(new URL('../src/relationship-graph.tsx', import.meta.url), 'utf8')
const graphCss = readFileSync(new URL('../src/relationship-graph.css', import.meta.url), 'utf8')
const batchSource = readFileSync(new URL('../src/batch-demo.tsx', import.meta.url), 'utf8')

test('graph node keyboard navigation wraps and supports Home and End', () => {
  assert.equal(moveReviewFocus(0, 3, 'ArrowRight'), 1)
  assert.equal(moveReviewFocus(2, 3, 'ArrowDown'), 0)
  assert.equal(moveReviewFocus(0, 3, 'ArrowLeft'), 2)
  assert.equal(moveReviewFocus(1, 3, 'ArrowUp'), 0)
  assert.equal(moveReviewFocus(1, 3, 'Home'), 0)
  assert.equal(moveReviewFocus(1, 3, 'End'), 2)
  assert.equal(moveReviewFocus(0, 0, 'ArrowRight'), null)
  assert.equal(moveReviewFocus(0, 3, 'Enter'), null)
})

test('larger relationship batches select the accessible table fallback', () => {
  assert.equal(isDenseReviewGraph(24, 36), false)
  assert.equal(isDenseReviewGraph(25, 1), true)
  assert.equal(isDenseReviewGraph(1, 37), true)
})

test('narrow layouts scroll a readable map instead of shrinking node text to an illegible overview', () => {
  assert.equal(readableReviewZoom(320, 1100), .8)
  assert.equal(readableReviewZoom(1100, 1100), .9818181818181818)
  assert.equal(readableReviewZoom(1200, 1100), 1)
})

test('review graph exposes accessible navigation, live updates, and evidence controls', () => {
  for (const required of ['aria-live="polite"', 'aria-atomic="true"', 'relationship-map-instructions', 'moveReviewFocus', 'onKeyDown', 'aria-controls="relationship-table"', '<table className="relationship-fallback-table">', 'onInspectDocument(item.documentId, item)', 'relationship-edge-review', 'relationship-review-select', 'sourceLabel} ${edgeLabel[edge.type]} ${targetLabel}', 'relationship-review-note', "typeof ResizeObserver === 'undefined'", "window.addEventListener('resize', update)"]) {
    assert.match(graphSource, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  }
})

test('three-document synthetic graph keeps review state ephemeral and cues only typed conflicts', () => {
  const edges = [
    { id: 'edge_a', type: 'works_at', sourceId: 'alias_person_01', targetId: 'alias_org_01', evidence: [{ documentId: 'document_01' }] },
    { id: 'edge_b', type: 'works_at', sourceId: 'alias_person_01', targetId: 'alias_org_02', evidence: [{ documentId: 'document_02' }] },
    { id: 'edge_c', type: 'assigned_to', sourceId: 'alias_project_01', targetId: 'alias_person_02', evidence: [{ documentId: 'document_03' }] },
  ]
  const freshReview = {}
  assert.equal(reviewStatusFor('edge_a', freshReview), 'pending')
  const cues = relationshipConflictCues(edges, freshReview)
  assert.deepEqual(cues.get('edge_a'), { code: 'MULTIPLE_WORKS_AT', edgeIds: ['edge_a', 'edge_b'] })
  assert.equal(cues.has('edge_c'), false)
  // Rejecting one claim removes the temporary cue. Reload starts from the
  // empty object again; no identity or adjudication is persisted here.
  assert.equal(relationshipConflictCues(edges, { edge_b: 'rejected' }).has('edge_a'), false)
  assert.equal(reviewStatusFor('edge_a', {}), 'pending')
  // The response object, not response-local edge IDs, controls reset. A new
  // batch may reuse the same edge IDs for entirely different people.
  assert.match(graphSource, /reviewState\.graph === graph \? reviewState\.reviews : \{\}/)
  assert.match(graphSource, /current\.graph === graph \? current\.reviews : \{\}/)
  assert.doesNotMatch(graphSource, /graphReviewKey/)
})

test('a changed graph clears selection even when response-local IDs recur', () => {
  const original = { nodes: [{ id: 'person_1' }] }
  const replacement = { nodes: [{ id: 'person_1' }, { id: 'person_2' }] }
  const oldSelection = { graph: original, nodeId: 'person_2', edgeId: 'edge_1' }
  assert.equal(selectionForGraph(original, oldSelection), oldSelection)
  assert.deepEqual(selectionForGraph(replacement, oldSelection), { graph: replacement, nodeId: 'person_1', edgeId: null })
  assert.match(graphSource, /const selection = selectionForGraph\(graph, selectionState\)/)
  assert.doesNotMatch(graphSource, /aria-pressed=\{status === next\}/)
})

test('identity merge proposal requires two current people and rejects a collapsed direct link', () => {
  const graph = { nodes: [{ id: 'E1', kind: 'person' }, { id: 'E2', kind: 'person' }, { id: 'E3', kind: 'person' },
    { id: 'organization_1', kind: 'organization' }], edges: [
    { id: 'edge_1', type: 'works_at', sourceId: 'E1', targetId: 'organization_1', evidence: [{ documentId: 'document_1' }] },
    { id: 'edge_2', type: 'works_at', sourceId: 'E2', targetId: 'organization_1', evidence: [{ documentId: 'document_2' }] },
    { id: 'edge_3', type: 'sent_to', sourceId: 'E1', targetId: 'E3', evidence: [{ documentId: 'document_3' }] },
  ] }
  assert.equal(validateMergeProposal(graph, 'E1', 'E2'), null)
  assert.equal(validateMergeProposal(graph, 'E1', 'E1'), 'SAME_PERSON')
  assert.equal(validateMergeProposal(graph, 'E1', 'E3'), 'SELF_LINK')
  assert.equal(validateMergeProposal(graph, 'E1', 'organization_1'), 'MISSING_PERSON')
  assert.match(graphSource, /mergeProposalState\.graph === graph \? mergeProposalState\.pair : null/)
  assert.match(graphSource, /Identity split is not available in this preview/)
})

test('each successful inspection remounts ephemeral relationship review state', () => {
  // A -> B -> A can reuse the exact same graph object and response-local IDs.
  // The parent inspection epoch must still discard every draft and proposal.
  assert.match(batchSource, /const \[inspectionEpoch, setInspectionEpoch\] = useState\(0\)/)
  assert.match(batchSource, /setInspection\(value\)\s*setInspectionEpoch\(epoch => epoch \+ 1\)/)
  assert.match(batchSource, /<RelationshipGraph key=\{inspectionEpoch\} graph=\{inspection\.entityGraph\}/)
})

test('review graph preserves visible focus, touch-sized controls, responsive layout, and reduced-motion support', () => {
  for (const required of ['min-height:44px', ':focus-visible', '@media (prefers-reduced-motion:reduce)', '@media(max-width:760px)', 'overflow:auto']) {
    assert.match(graphCss, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  }
})

test('every actionable relationship evidence and table control has a 44px target', () => {
  for (const selector of ['.relationship-map-detail li>button', '.relationship-evidence-list button', '.relationship-fallback-table button']) {
    const rule = new RegExp(`${selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\{[^}]*min-width:44px[^}]*min-height:44px`)
    assert.match(graphCss, rule)
  }
  assert.match(graphCss, /\.relationship-evidence-list button\{[^}]*flex-direction:column[^}]*align-items:flex-start/)
})

test('evidence navigation avoids smooth motion when reduced motion is requested', () => {
  assert.match(batchSource, /matchMedia\?\.\('\(prefers-reduced-motion: reduce\)'\)\.matches \?\? false/)
  assert.match(batchSource, /behavior: reduceMotion \? 'auto' : 'smooth'/)
})
