import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const navigationSource = readFileSync(new URL('../src/review-navigation.ts', import.meta.url), 'utf8')
const navigationCompiled = ts.transpileModule(navigationSource, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ES2022 } }).outputText
const { isDenseReviewGraph, moveReviewFocus, readableReviewZoom } = await import(`data:text/javascript;base64,${Buffer.from(navigationCompiled).toString('base64')}`)
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
  for (const required of ['aria-live="polite"', 'aria-atomic="true"', 'relationship-map-instructions', 'moveReviewFocus', 'onKeyDown', 'aria-controls="relationship-table"', '<table className="relationship-fallback-table">', 'onInspectDocument(item.documentId, item)', "typeof ResizeObserver === 'undefined'", "window.addEventListener('resize', update)"]) {
    assert.match(graphSource, new RegExp(required.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')))
  }
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
