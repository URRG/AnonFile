# Synthetic development workbench

Run `npm ci --ignore-scripts`, `npm test`, `npm run build`, then `npm run dev` for local work. `VITE_API_URL` is injected at build time; its localhost default is port 8000.

Supply an explicitly configured processor token in the password field. Tokens stay in React memory only and are sent as bearer credentials to the configured API. Use localhost exclusively for M1. No customer data, offline processing fallback, output preview, clipboard export or successful-release state is supported.

Client tests exercise the actual request/validation module and a static UI regression guard. `npm run test:integration` also runs the real client against a temporary localhost Python API (install API dependencies first; optionally set `ANONFLOW_TEST_PYTHON`). These are not rendered-browser end-to-end tests. See [development guide](../../docs/development-m1.md).
