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
proposed replacements. You can add a missed exact person name or change a
person alias (the alias must have the same character length); then review the
candidate. The final screen has document comparisons, explicit mail-header
relationships, and a verification scorecard. It deliberately has no export.

You may instead select two or three synthetic TXT, CSV, JSON, JSONL, or
text-based PDF files (100 KB each, 300 KB combined). A PDF contributes
extracted text to the side-by-side review; **the PDF itself is not modified**.
Scanned PDFs and images are rejected because this demo has no OCR or visual
residual check. PDF extraction may lose layout, embedded images, annotations,
and metadata. No score estimates detection recall, precision, anonymity, or
sale readiness. The bounded detector can miss prose names and other sensitive
information. CSV review is limited to one-line cells, and ambiguous or
unsupported structured values are rejected. Replacements are proposals for
human review only.

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
