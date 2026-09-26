# Synthetic development workbench

Run `npm ci --ignore-scripts`, `npm test`, `npm run build`, then `npm run dev` for local work. `VITE_API_URL` is injected at build time; its localhost default is port 8000.

Supply an explicitly configured processor token in the password field. Tokens stay in React memory only and are sent as bearer credentials to the configured API. The main route offers an opt-in, synthetic-only batch **text preview** for two or three files; the previous metadata-only developer controls remain at `?mode=advanced`. Use localhost exclusively. No customer data, offline processing fallback, clipboard export or successful-release state is supported. The text preview is not a safe output artifact or anonymity certification.

The built-in sample includes fixed synthetic reference labels. For other synthetic batches, Detection review accepts a separate complete-label JSON manifest after an explicit reviewer attestation. The scorecard reports exact-span agreement for that labelled batch only; it is not an independent model benchmark. See [synthetic demo instructions](../../docs/synthetic-demo.md) for the manifest format.

Detection review can also exclude a confirmed noncritical false-positive signal across the batch. That action is explicit and visible in the scorecard; the source values remain in the preview. Critical and unsupported categories are not suppressible, and exclusion does not authorize an export or release.

Do not submit customer data: the API cannot establish that input is synthetic. The batch inspection endpoint does not persist submitted content, while the separate advanced development workflows may temporarily store it. The client enforces a 30-second deadline for batch inspection. Cancellation clears the busy state, never fabricates a result and does not undo data already received by the server. Unmounting the workbench cancels the active client request; late responses cannot replace current UI state.

Client tests exercise the actual request/validation module and a static UI regression guard. `npm run test:integration` also runs the real client against a temporary localhost Python API (install API dependencies first; optionally set `ANONFLOW_TEST_PYTHON`). These are not rendered-browser end-to-end tests. See [development guide](../../docs/development-m1.md).
