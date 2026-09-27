# D08 accessible and scalable review UI

The relationship review surface remains synthetic-only and review-required. It
does not authorize release, export, or processing of real supplier data.

## Implemented checks

- Map nodes use roving `tabIndex`: exactly the selected visible node is in the
  tab order. Left/Right and Up/Down move focus through visible nodes; Home and
  End move to the bounds, including in dense graphs.
- The result views and document selector are roving ARIA tab lists with
  labelled tab-panel ownership and Left/Right, Home, and End navigation. The
  selected node and its relationship count are announced in a concise polite
  status region; the interactive detail panel is not a live region. Zoom
  percentage, evidence buttons, map controls, and table controls have
  accessible labels.
- Strong `:focus-visible` outlines are present for the map, node controls,
  evidence buttons, table scroller, and controls. Every actionable
  detail/evidence/table control has a 44px minimum target. Motion is disabled
  or made instant when the operating system requests reduced motion.
- The layout collapses from the map/detail columns at narrow widths and keeps
  the large map and relationship table horizontally scrollable. Resize-driven
  zoom never shrinks map labels below 80%; narrow views open the table instead
  of making an illegible whole-map overview. Controls meet a 44px minimum
  height. Automated checks cover these rules, not actual 200–400% use.
- A batch with more than 24 visible nodes or 36 visible edges opens the
  semantic relationship table automatically. Each table source/target selects
  that node; each evidence button opens the same precise evidence workflow as
  the detail panel.
- Document-level-only evidence moves focus to the persistent result status
  after the graph view unmounts, instead of losing it to the document body.

Automated evidence: `npm test` includes `tests/review-ui.test.mjs`, which
checks the focus helper, dense-batch threshold, roving graph/result/document tabs,
durable document-level focus fallback, target-size and reduced-motion
contracts, and required accessibility/responsive source contracts. These are
static source-contract checks, not rendered browser interaction tests. `npm run
build` type-checks and bundles the UI.

On 2026-09-27, an automated rendered walkthrough in the Codex in-app browser
used the built-in three-file fictional batch. Enter activated the upload and
review actions, Space toggled the synthetic-data acknowledgement and mail-link
filter, Right Arrow moved between result tabs and graph nodes, and the text
evidence control opened the first document with its exact source span focused.
At 640, 427, and 320 CSS-pixel viewports, the document scroll width equalled
its client width (625, 412, and 305 pixels respectively); result/document tabs
and the narrow relationship table scrolled within their own containers. This
walkthrough exposed a 21-pixel page-level header overflow at 320 pixels; the
breadcrumb now shrinks before the fixed demo badge, and the measured page
overflow is zero. Viewport emulation is not a 200–400% browser-zoom test, and
browser accessibility-tree inspection is not a screen-reader walkthrough.

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
