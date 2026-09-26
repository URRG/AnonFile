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
and a JSON support record. The next screen lists detected values and
proposed replacements. You can add a missed exact person name, add a bounded
non-name sensitive phrase, or change a person alias (the alias must have the
same character length); then review the
candidate. The final screen has document comparisons, explicit mail-header and
same-record account-owner/client links, and a verification scorecard. It
deliberately has no export. Structured role links require `account_owner` and
`client_name` in the same parsed CSV, JSON, or JSONL record; the workbench does
not infer roles from nearby prose or combine unrelated rows.
If a name, email, phone, or IP address is a confirmed false positive in this
synthetic batch, Detection review can exclude that signal across every file
after a separate acknowledgment. Excluded values remain visible in the
candidate, are counted separately, and keep the result review-required.
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
The PDF candidate is reconstructed as an image-only PDF in memory; its digest
and page count, but **not a downloadable PDF**, are returned. Metadata and
original PDF objects are not copied into that candidate. Unreadable, oversized,
or ambiguous media are rejected.

This is a visual *review candidate*, not safe redaction certification. OCR can
miss or misread visible sensitive content; no detection outside recognized
lines is assured. The candidate is rechecked only by the same OCR engine, so
zero retained *detected source values* is not independent assurance. Names
are replaced with same-length pseudonyms. Emails linked by explicit mail
headers or one unambiguous structured record use the person's pseudonym as
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
