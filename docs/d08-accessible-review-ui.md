# D08 accessible and scalable review UI

The relationship review surface remains synthetic-only and review-required. It
does not authorize release, export, or processing of real supplier data.

## Implemented checks

- Map nodes are buttons with an announced selected state. Left/Right and
  Up/Down move focus through visible nodes; Home and End move to the bounds.
- The selected node and its visible explicit links are announced in a polite
  live region. Zoom percentage, evidence buttons, map controls, and table
  controls have accessible labels.
- Strong `:focus-visible` outlines are present for the map, node controls,
  evidence buttons, table scroller, and controls. Motion is disabled when the
  operating system requests reduced motion.
- The layout collapses from the map/detail columns at narrow widths and keeps
  the large map and relationship table horizontally scrollable. Resize-driven
  zoom never shrinks map labels below 80%; narrow views open the table instead
  of making an illegible whole-map overview. Controls meet a 44px minimum
  height. Automated checks cover these rules, not actual 200–400% use.
- A batch with more than 24 visible nodes or 36 visible edges opens the
  semantic relationship table automatically. Each table source/target selects
  that node; each evidence button opens the same precise evidence workflow as
  the detail panel.

Automated evidence: `npm test` includes `tests/review-ui.test.mjs`, which
checks keyboard focus movement, the dense-batch threshold, and the required
accessibility and responsive source contracts. `npm run build` type-checks and
bundles the UI.

## Human walkthrough status: NOT PERFORMED

No human walkthrough is claimed for D08. Before closing the checklist item,
perform and record the following on a current browser using only the synthetic
demo batch:

1. At keyboard-only input, tab to a graph node; verify arrow keys, Home/End,
   selected-detail updates, evidence navigation, and a visible focus outline.
2. With a screen reader, verify the map instructions, selected-node live
   update, relationship count, zoom percentage, table headers, and evidence
   button names. Confirm no source contact values are announced.
3. At 200%, 300%, and 400% browser zoom and at a 320 CSS-pixel viewport,
   verify controls stay reachable, content does not overlap, and both map and
   table can be scrolled and reviewed.
4. Use a synthetic batch beyond the dense threshold. Verify the table opens,
   source/target buttons select nodes, and each evidence link navigates to its
   bounded evidence or explicitly document-level-only fallback.

Attach the browser, assistive technology/version, zoom/viewports, date, and
results to this document when the walkthrough is actually completed.
