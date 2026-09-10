# AnonFlow web

The browser dashboard for the AnonFlow data-release pipeline. It lets a user paste or import a small text export, choose a release policy, request anonymization, then inspect transformed data, findings, scores, and release evidence.

## Run locally

```bash
npm install
cp .env.example .env
npm run dev
```

Set `VITE_API_URL` to the AnonFlow API origin (for example `http://localhost:8000`). The application calls `POST /v1/anonymize` with `{ content, policy, release_mode }`. If the API is not available, it deliberately shows a labelled local demonstration result so the interface remains explorable; it must not be treated as a production anonymization result.

## Design decisions

- The UI never persists source content in browser storage and avoids printing it to the console.
- Output decisions and scores are evidence views, not legal/compliance declarations.
- The backend is authoritative for all transformation, risk calculation, access control, audit evidence, and downloadable release artifacts.
- Imports are limited to text-like files under 2 MB in the browser demo; production ingestion belongs in the backend quarantine pipeline.
