# Local validation while hosted Actions is unavailable

## Live PostgreSQL

The complete API suite ran against a real, disposable **PostgreSQL 16.14** server:
**1,881 passed, 6 skipped**, in 179.08 seconds. This exercised 55 database tests
that skipped without `ANONFLOW_POSTGRES_TEST_DSN`. No database test failed.
The product source was main `3321153001c94caede35c64ced8d34acebbd5b2a`.

The remaining skips were the separately pinned D07 Tesseract check and five
OpenBao/S3/worker checks requiring their own disposable TLS services. Those five
service checks passed separately against verified native OpenBao 2.5.5 and
RustFS 1.0.0 in the preceding validation. They did not run in this PostgreSQL
invocation. Native service results do not establish CI-image equivalence.

### Reproduce with installed PostgreSQL 16

Use the API virtualenv with `requirements-dev.txt` installed:

```bash
cd services/api
PG_BIN=/path/to/postgresql-16/bin python scripts/run-postgres-integration.py
```

The helper initializes a temporary UTF-8 cluster as the current non-root user,
binds an ephemeral loopback port, uses a generated SCRAM password, creates a
disposable test database, and passes its DSN only to the test process. It
redacts that password from captured test output, preserves pytest's exit code,
and stops its own database before deleting the temporary cluster. Explicit
pytest arguments can select focused checks. It does not use an existing DB or
change product configuration.

The final helper passed a fresh-install 8-test PostgreSQL rerun, an actual
pytest exit-code/temporary-cluster cleanup check, and independent failure
injection covering normal shutdown, failed/timed-out/missing `pg_ctl`, and
forced child termination. Its fallback reaps only its own server process before
removing data, while preserving pytest's result and redacting the generated
password.

### Package provenance in this environment

Official PostgreSQL downloads and the configured Debian package cache were
unavailable through the current egress policy. The allowed npm package route
provided `@embedded-postgres/linux-x64@16.14.0-beta.17`, a third-party distribution
of Zonky PostgreSQL binaries. Package lifecycle scripts were disabled on
installation. Before execution, the tarball's SHA-512 and the npm registry's
ECDSA signature were independently verified using the registry's HTTPS key
endpoint. Only the inspected relative-library-symlink hydration script then ran.

```text
sha512-8fr7hEiI7XlbPDPsLZJ4RU1NR6jTIDWpf81Sfiwk3T845V0yJJGxjawjkQZmIWVgPW/qY/dMSv0o08FRWJ/zsg==
```

`npm audit signatures` could not download its verification prerequisite; it is
not reported as passing. The independent ECDSA/SHA-512 check above passed. This
proves the downloaded package's registry signature and integrity, not the
official PostgreSQL container's build provenance.

## Pinned containers

Independent QA verified Docker Engine 28.4.0, BuildKit 0.24.0, and a passing
`docker compose config --quiet`. A writable, isolated `DOCKER_CONFIG` resolves
Buildx's inability to write into the cloud user's home directory.

Actual `docker compose build api web` requests the unchanged pinned Python and
Node base images, then fails at Docker Hub with **Forbidden**. Exact OpenBao and
RustFS image pulls likewise fail. HTTPS probes return proxy **CONNECT 403** for
`registry-1.docker.io` and `auth.docker.io`. There are no cached images or
configured registry mirrors to use. Container builds, runtime smoke tests, and
the pinned PostgreSQL image therefore remain **blocked**, not passed.

The reusable environment draft adds those two exact Docker Hub destinations
while preserving the package-manager preset and existing GitHub rule. Saving
the draft does not apply it to the running environment. Apply it in environment
settings before retrying. Successful manifest resolution may reveal additional
blob-storage destinations; do not guess or allow arbitrary mirrors. All digest,
TLS, and package verification requirements remain unchanged.

```bash
# Use a fresh task-local configuration directory, retaining any required
# registry authentication through the platform's supported configuration.
mkdir -p /tmp/anonflow-docker-config
export DOCKER_CONFIG=/tmp/anonflow-docker-config
docker compose config --quiet
docker compose build api web
```

After image access succeeds, run the existing OpenBao, S3, and encrypted-worker
integration scripts under `services/api/scripts/`, followed by application
container smoke checks. Local logs must filter `::add-mask::` lines: GitHub
interprets them as masking commands, but ordinary terminals expose their values.
The existing CI workflow remains the authoritative pinned-container recipe.

## Hosted CI and UI work

GitHub Actions has separately reported account billing/spending-limit failures
before jobs execute. Local evidence is recorded explicitly; no failed hosted
check is described as passed and no protection or workflow is disabled.

The accompanying [quiet workbench](mockups/quiet-workbench/README.md) is a
standalone UI design preview. It does not change product detection, storage, or
release behavior. Browser QA covers its actual interactions and responsive
layout separately from the API/database tests.
