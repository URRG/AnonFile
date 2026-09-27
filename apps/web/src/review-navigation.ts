export type ReviewNavigationKey = 'ArrowDown' | 'ArrowLeft' | 'ArrowRight' | 'ArrowUp' | 'End' | 'Home'

/** Returns the next node index for a roving, keyboard-navigable graph. */
export function moveReviewFocus(currentIndex: number, itemCount: number, key: string): number | null {
  if (!itemCount || !(['ArrowDown', 'ArrowLeft', 'ArrowRight', 'ArrowUp', 'End', 'Home'] as string[]).includes(key)) return null
  if (key === 'Home') return 0
  if (key === 'End') return itemCount - 1
  const direction = key === 'ArrowDown' || key === 'ArrowRight' ? 1 : -1
  const normalized = Math.max(0, Math.min(currentIndex, itemCount - 1))
  return (normalized + direction + itemCount) % itemCount
}

/** At this size, the semantic relationship table should be opened for review. */
export function isDenseReviewGraph(nodeCount: number, edgeCount: number) {
  return nodeCount > 24 || edgeCount > 36
}
