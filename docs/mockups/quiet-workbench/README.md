# Quiet workbench — design preview

A working, self-contained mockup of a simpler AnonFlow review flow. Open
`index.html` in a browser, or serve this directory with a local static server.
It needs no packages, fonts, API, authentication, or network requests.

This is a design proposal, not a change to the production web app. The sample
starts on **Review** so the main interaction is immediately visible. All data
is fictional; no uploads, detection, or verification run here.

![Desktop review preview](preview.png)

## Direction

Calm, compact, and focused on the document. The existing AnonFlow teal remains,
with pale neutral surfaces and a smaller sidebar. System sans-serif type keeps
controls familiar; a serif document title separates content from controls.
Spacing follows an 8px scale, with 8px controls and 16px panel corners.

| Screen | Main action | Content kept visible |
| --- | --- | --- |
| Files | Load sample | Three file names and the fictional-data boundary |
| Review | Confirm change | Document, selected suggestion, replacement, progress |
| Summary | Continue review / Download sample | Reviewed decisions and files |

The former overview paragraphs, strategy descriptions, and metric cards are
replaced by shorter labels and a **Details** dialog. The review-copy limitation
remains visible: **“Not cleared for sharing.”** Finishing the review never
changes this into a sharing or verification claim.

## Try the flow

1. Select a highlighted mention or suggestion. Choose a file or switch to
   **Review copy** to inspect the proposed replacement in context.
2. Edit **Replace with**, then **Confirm change**, or **Keep original**.
   Decisions apply to all exact matching mentions in the fictional batch.
3. Open **Summary**. Unreviewed suggestions lead back to review. After all four
   are reviewed, **Download sample** requires acknowledgment and produces a JSON
   sample with `verified: false` and `clearedForSharing: false`.
4. **Files → Reset sample** clears the decisions. **Load sample** demonstrates
   a short loading state without uploading anything.

No state persists across a reload. HTML-like replacement text is rendered as
text, never markup. Email examples must use the reserved `.test` domain.

## Responsive behavior and states

- Wide desktop: file list, document, and inspector in three columns.
- Tablet: file list becomes a horizontal strip above document and inspector.
- Phone: document and inspector stack; the file strip scrolls independently.
- Keyboard focus, dialog dismissal, active selection, loading, invalid input,
  reviewed/retained decisions, and incomplete/complete summary states are shown.
- Reduced-motion preferences disable progress transitions.

Independent Chromium QA passed all three screens at 320px, 390px, and 1440px.
Checks covered keyboard focus after list selection, dialogs, edit/keep/reset,
review and download gating, and JSON/CSV escaping for quoted and comma-bearing
names. The preview made no external requests and raised no browser errors.

## Implementation boundary

Before adopting this in the product, wire these controls to the existing API,
authorization, batch limits, correction/exclusion semantics, and download gate.
Keep the complete evidence, relationship, metadata, hidden-content, and media
review tools reachable through secondary views. This small concept does not
claim parity with those production workflows or measure detector quality.
