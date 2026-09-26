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
select `demo-data/synthetic-airline-passengers.csv` (or another entirely
synthetic UTF-8 file), acknowledge the synthetic-data restriction, and run
the inspection. The result shows rule findings, applied operations, and a
transformed preview. CSV and JSONL inputs appear as normalized JSON records
in the preview, not in their original file layout. A field such as
`booking_reference` may remain unchanged;
that visibly demonstrates why the preview is not certified anonymous.

If Python dependencies are already installed in another environment, pass
`-PythonPath C:\path\to\python.exe` to the launcher. Press Enter in the
launcher terminal to stop both services. Its `.demo-run` logs are local and
ignored by Git. The API's ordinary development workflows remain separate;
production mode never exposes the demo route, even if the demo opt-in is set.

The runnable demo is one milestone in the wider
[product-readiness plan](demo-to-product-roadmap.md), not a production setup.
