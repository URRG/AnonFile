import type { EntityGraph, EntityGraphEdge } from './api'

export type EphemeralEdgeReview = 'pending' | 'accepted' | 'rejected'
export type RelationshipConflictCode = 'MULTIPLE_WORKS_AT' | 'MULTIPLE_ASSIGNED_TO'

export interface RelationshipConflictCue {
  code: RelationshipConflictCode
  edgeIds: string[]
}

export interface GraphSelection {
  graph: EntityGraph
  nodeId: string | null
  edgeId: string | null
}

export function selectionForGraph(graph: EntityGraph, state: GraphSelection): GraphSelection {
  // Graph IDs are response-local. Never apply an old selection to a new response.
  return state.graph === graph ? state : { graph, nodeId: graph.nodes[0]?.id ?? null, edgeId: null }
}

export type MergeProposalIssue = 'MISSING_PERSON' | 'SAME_PERSON' | 'SELF_LINK'

export function validateMergeProposal(graph: EntityGraph, firstId: string, secondId: string): MergeProposalIssue | null {
  const people = new Set(graph.nodes.filter(node => node.kind === 'person').map(node => node.id))
  if (!people.has(firstId) || !people.has(secondId)) return 'MISSING_PERSON'
  if (firstId === secondId) return 'SAME_PERSON'
  if (graph.edges.some(edge => (edge.type === 'sent_to' || edge.type === 'assistant_to') &&
      ((edge.sourceId === firstId && edge.targetId === secondId) || (edge.sourceId === secondId && edge.targetId === firstId)))) return 'SELF_LINK'
  return null
}

export function reviewStatusFor(edgeId: string, reviews: Readonly<Record<string, EphemeralEdgeReview>>): EphemeralEdgeReview {
  return reviews[edgeId] ?? 'pending'
}

/**
 * Return narrowly typed review cues without inspecting node labels or source
 * evidence. A cue asks the reviewer to reconcile explicit claims; it does not
 * assert that the claims are mutually exclusive in the real world.
 */
export function relationshipConflictCues(edges: readonly EntityGraphEdge[], reviews: Readonly<Record<string, EphemeralEdgeReview>>): Map<string, RelationshipConflictCue> {
  const cues = new Map<string, RelationshipConflictCue>()
  for (const [type, code] of [
    ['works_at', 'MULTIPLE_WORKS_AT'],
    ['assigned_to', 'MULTIPLE_ASSIGNED_TO'],
  ] as const) {
    const bySource = new Map<string, EntityGraphEdge[]>()
    for (const edge of edges) {
      if (edge.type !== type || reviewStatusFor(edge.id, reviews) === 'rejected') continue
      const group = bySource.get(edge.sourceId) ?? []
      group.push(edge)
      bySource.set(edge.sourceId, group)
    }
    for (const group of bySource.values()) {
      if (new Set(group.map(edge => edge.targetId)).size < 2) continue
      const cue = { code, edgeIds: group.map(edge => edge.id) }
      for (const edge of group) cues.set(edge.id, cue)
    }
  }
  return cues
}
