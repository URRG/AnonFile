# Run the local synthetic demo

This demo is **not** suitable for customer, employee, passenger, payment,
health, credential, or confidential company data. The input may contain
identifiers the bounded rules do not detect. The transformed preview is not
anonymity qualification and cannot be sold or released by this application.

On Windows, install Python 3.12 and Node 22, then from the repository root:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r services\api\requirements-dev.txt
npm ci --prefix apps\web --ignore-scripts
.\scripts\start-synthetic-demo.ps1
```

The launcher generates a fresh in-memory processor token, starts the API and
UI on loopback, and prints the URL and token. Paste the token into the UI,
choose **Use sample batch**, acknowledge that the data is fictional, and click
**Analyze batch**. The sample has a fictional email thread, a CSV passenger
list with names, email addresses, fictional passport numbers and birth dates,
and a JSON support record. The next screen groups detected values by people,
contacts, identifiers and other signals; search and eight-row pagination keep
larger batches reviewable without hiding the totals. It lists proposed
replacements. You can add a missed exact person name, add a bounded
non-name sensitive phrase, or change a person alias (the alias must have the
same character length); then review the
candidate. The final screen has document comparisons, an evidence-backed
entity map, and a verification scorecard. The map separates people,
organizations and projects; it supports typed role edges from explicit
structured fields, labelled signatures or complete role statements, and
mail-header delivery edges behind a separate toggle. Selecting an evidence
reference opens the source document comparison. It does not infer employment
or client relationships from email domains, proximity or a mere conversation.
See the [graph contract](entity-relationship-graph.md). The
reproducible three-file [rich relationship batch](rich-relationship-demo-fixtures.md)
exercises the map with a client email thread, developer conversation PDF, and
calendar TXT export. The
comparison has 50–200% zoom, fit width, synchronized side-by-side panning, and
single-pane original/candidate views. A separately acknowledged **Download this
demo candidate** action saves only the unverified synthetic review copy; it is
not a release or production export. The old same-record account-owner/client
edge is retained for API compatibility, but the map uses its own typed,
source-free graph payload. Identity resolution remains batch-local and may
merge homonyms; the map is not a verified social or corporate directory.
If a name, email, phone, or IP address is a confirmed false positive in this
synthetic batch, Detection review can exclude that signal across every file
after a separate acknowledgment. Excluded values remain visible in the
candidate, are counted separately, and keep the result review-required.
The demo download is blocked for reviewer-excluded or still-detected source
values, structured-output failure, or a same-engine visual residual finding.
Credentials, payment secrets, government IDs, birth dates, and other
unsupported categories cannot be excluded through this demo control.
The built-in batch also carries a fixed set of demo-authored reference spans.
Its scorecard shows exact matched, false-positive, and missed spans for this
fictional example. It separates the automatic baseline from the reviewed
candidate score, breaks results down by file, and lets you promote a missed
supported span into an exact manual correction. Try `DEMO-4821` and
`DEMO-4822`: the reviewed sample recall rises, while the automatic baseline
remains unchanged. These corrections do not teach the detector to recognize
unseen values. The backend accepts that label basis only for the exact
built-in files and labels; changing the sample invalidates it.

To demonstrate actual raster rewriting, choose **Use PDF + image sample** on
the upload screen instead. This loads a fictional email PDF, an image service
note, and a JSON record. Analyze the batch, inspect the two explicit
relationships, and open both media documents in the side-by-side comparison.
The image intentionally retains fictional booking code `DEMO-4822` until you
add it as **Other sensitive** in Detection review and rescan. This is a visible
example of the detector's limitations, not a claim that all PII is found.
The media scorecard remains **not measured** because OCR transcript matches
are not an independently annotated pixel-level holdout.

You may instead select two or three synthetic TXT, CSV, JSON, JSONL, PDF,
PNG, or JPEG files (100 KB per text file, 500 KB per PDF/image, 1.5 MB combined). The demo rasterizes up to
two PDF pages per file and OCRs each raster page or image. The entire batch is
limited to three million media pixels. Detected spans are applied to the OCR
lines on a new pixel image, with side-by-side source and candidate page views.
PDF pages are rendered at a bounded 1.7× raster scale. At 100% zoom the UI
shows native preview pixels rather than squeezing the full page into a narrow
pane; higher zoom magnifies pixels but cannot recover detail absent from the
source raster. The PDF candidate is reconstructed as an image-only PDF in
memory. Its bytes and digest are returned for a local, digest-checked demo
download. Original PDF objects and metadata are not copied into that
candidate. Image input downloads as candidate PNG; text formats download as
candidate text files. Unreadable, oversized, or ambiguous media are rejected.

On a PDF/image result, a reviewer can draw or enter a bounded top-left pixel
rectangle over a sensitive region that was **not** captured in the OCR
transcript, then rescan. The candidate paints that region opaque black in a
new PNG/image-only PDF. The browser verifies that every requested candidate
pixel is opaque black. For a corrected PDF download it rebuilds a lossless
raster-only PDF from the verified candidate PNG pages instead of trusting an
unbound server PDF. This path requires browser image decoding, canvas,
cryptography and compression support, and fails closed when any is absent.
Staged boxes are shown separately and block download until applied or removed;
applied boxes persist across further rescans and can be removed by rescanning.
A batch
accepts at most 20 boxes, each at least 4 × 4 pixels and no more than 25% of
its page (50% total per page). Boxes cannot overlap one another or any OCR
line; use the text correction workflow for recognized lines. The review
response binds uploaded source bytes and raster source/candidate pages with
SHA-256 digests. These visual-only corrections do not become entities, text
matches, or scorecard true positives; the proposed OCR transcript can remain
unchanged while pixels are blacked out. Review the before/after page closely:
this is not proof that all sensitive pixels were found or that the result is
safe to release.

This is a visual *review candidate*, not safe redaction certification. OCR can
miss or misread visible sensitive content; no detection outside recognized
lines is assured. The candidate is rechecked only by the same OCR engine, so
zero retained *detected source values* is not independent assurance.
Materially overlapping OCR ink, padded repaint regions that touch neighboring
OCR ink, some isolated two-cell/column layouts, and a
replacement that cannot fit its line cause an abstention instead of a guessed
reading order or an unreadable whole-line mark. This is deliberately partial:
larger tables, forms, screenshots and multi-column reading order are not
qualified, and close line padding can still affect nearby content. Inspect
the original and candidate at native pixels before using even synthetic
review copies; see the [fictional layout corpus](media-layout-corpus.md).
Input OCR lines below 0.60 confidence reject the batch. A lower-confidence
candidate OCR line is counted and shown for review: a replacement can change
recognizer confidence without restoring source pixels, but that recheck cannot
establish the absence of other sensitive content. Names are replaced with
same-length, readable name pseudonyms. Unsupported name
shapes fail closed instead of turning into `Axxxxx`-style tokens. Emails linked
by explicit mail headers, one unambiguous structured record, or a Slack-style
name/address roster row use the person's pseudonym as
their local part, for example `Riya <riya@example.test>` becomes
`Gita <gita@example.test>` consistently across the batch. Other source domains
are mapped consistently to reserved `.test` domains rather than potentially
deliverable addresses. An email with no evidenced owner gets a generic
`contactN@orgN.test` surrogate. The scorecard separates retained source values
from expected PII-shaped surrogate matches. Neither metric proves complete
detection or anonymity. The page rasterization
also loses selectable text and can change fidelity. Never use this demo for
real supplier data or treat the candidate preview as releasable. Without
complete reference labels, precision and recall remain **not measured**. The
bounded detector can miss prose names and other sensitive information. CSV
review is limited to one-line cells, and ambiguous or unsupported structured
values are rejected. Replacements are proposals for human review only.
The current rules do not automatically classify every employee ID, internal
URL, postal address, or phone broken across OCR lines. A narrow contextual
demo recognizer now handles labelled employee IDs and EMP-tagged identifiers,
internal/synthetic HTTP hosts or explicitly internal/intranet-labelled links,
bounded US-style prose street addresses, and explicit structured
`office_address`/`mailing_address` fields regardless of locale.
It emits review-only references and reserved `.invalid` URLs; it does not infer
ordinary public links, other international free-text addresses, or issuer-valid
employee IDs. Structured address replacements are review labels, not usable
postal addresses.
Use the manual
exact-value review control where a supported correction is possible; do not
interpret a clean selected-span count as complete coverage.

The entity register also shows the replacement strategy. PAN-shaped values,
explicitly identified US SSNs, and explicit `+1` North American phones get
non-issuable or fictional examples with the same basic syntax. Other
government IDs, driving licences, regional phone numbers, and unsupported
values remain opaque rather than being replaced with plausible live numbers.
For a born-digital PDF, a text-layer/OCR disagreement on a recognized
sensitive signal now rejects the candidate; this does not validate scanned
pixels. See the [format-aware replacement policy](format-aware-pseudonyms.md).

For a different synthetic batch, the Detection review page can attach a
separate reference-label JSON file. It is not counted as one of the source
documents. The manifest must list every staged filename exactly once, even
when a document has no labels. The reviewer must separately confirm the
completeness checkbox before the score is calculated. For example, with two
files named `a.txt` and
`b.txt`:

```json
{"schema_version":"batch-reference-v1","documents":[
  {"name":"a.txt","annotations":[{"start":0,"end":4,"entity_type":"PERSON_NAME"}]},
  {"name":"b.txt","annotations":[]}
]}
```

`start` and `end` are half-open Unicode code-point offsets in the original
text. For PDF/image input they refer to the OCR transcript displayed by the
workbench, not page coordinates or hidden source text. The reviewer must establish that the labels cover all
relevant spans; the application cannot verify that assertion. The resulting
precision/recall show both the **automatic baseline** and the **reviewed
candidate** (including manual corrections) against the supplied labels.
They are neither an independent
holdout benchmark nor a test of residual disclosure, re-identification risk,
utility, pixel-level disclosure, PDF layout, or release eligibility.

The previous one-file inspector and metadata-only control-plane workbench are
still available at `http://127.0.0.1:5173/?mode=advanced` for development.
That path has different contracts; neither path authorizes a release.

If Python dependencies are already installed in another environment, pass
`-PythonPath C:\path\to\python.exe` to the launcher. Press Enter in the
launcher terminal to stop both services. Its `.demo-run` logs are local and
ignored by Git. The API's ordinary development workflows remain separate;
production mode never exposes either demo route, even if the demo opt-in is set.

The runnable demo is one milestone in the wider
[product-readiness plan](demo-to-product-roadmap.md), not a production setup.
