# Local validation while hosted Actions is unavailable

## Historical native PostgreSQL validation

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
unavailable through the then-current egress policy. The allowed npm package route
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

## Pinned containers — completed follow-up

The saved Docker Hub rules are active. Authenticated registry responses exposed
one additional blob destination, `production.cloudfront.docker.com`; that exact
host was added alongside `registry-1.docker.io` and `auth.docker.io`, preserving
the package-manager preset and `api.github.com`. Actual digest-checked image
pulls and builds now succeed. No mirror, wildcard, or verification bypass was
used.

| Check | Result |
| --- | --- |
| PostgreSQL CI image, full host API suite | 1,881 passed, 6 skipped; 190.10 s |
| OpenBao container integration | 2 passed |
| RustFS S3 ciphertext integration | 2 passed |
| RustFS encrypted-worker integration | 1 passed |
| API, web, and web-test image builds | Passed with unchanged base-image pins |
| Web tests inside built test image | 112 passed, no skips |
| API tests inside final image | 1,826 passed, 61 skipped; 147.18 s |
| Final application container smoke | Passed: auth/CORS, redaction, release gates, web assets, real PNG OCR, non-root users, runtime CA absence |

The exact PostgreSQL pin
`postgres:16-alpine@sha256:721873c34ceb9f8d8fc265984940dc982404c105f19ad51be9fdc5970a6080ea`
resolves to **PostgreSQL 16.15 on Alpine**. Its recorded RepoDigest matches.
The six skips in that invocation were five separately run service checks and
the D07 pinned Tesseract check. The five service checks above used the repository's
unchanged OpenBao 2.5.5 and RustFS 1.0.0 CI image digests, generated credentials,
and verified TLS certificates. The D07 runtime remains unverified; the Debian
Tesseract installed in the API image is not evidence for that separate pin.
All disposable service containers and their volumes were removed.

The API image suite's 61 skips are the 55 PostgreSQL tests, five separate TLS
service tests, and D07. PostgreSQL and those five TLS checks passed in the
separate container runs above; D07 remains unverified. The image suite ran as
`anonflow` against the image's actual application, with successful cleanup.

### Build fixes and environment configuration

Docker Engine 28.4.0, BuildKit 0.24.0 and Compose configuration validation pass.
A task-local writable `DOCKER_CONFIG` avoids writes into the cloud user's
read-only home. Build containers also require the platform proxy's existing
hostname mapping, proxy variables, and trusted certificate bundle. Forwarding
proxy variables alone failed because the hostname was present in the host's
`/etc/hosts`, rather than DNS. Host networking did not supply that mapping.

The Dockerfiles accept an optional **BuildKit `package_ca` secret** for pip/npm
installation. It uses the existing host trust bundle while keeping certificate
verification enabled. The mounted certificate and trust variables do not persist
in either runtime image. Without the secret, installation uses the original
standard trust configuration. Runtime certificate scans independently confirmed
the platform proxy CA is absent from the finished images.

Image testing also exposed a missing `libGL.so.1` dependency for OpenCV. The API
image now installs `libgl1`; media imports and real synthetic OCR are checked in
the final image. Dependency declarations, lockfiles, image digests, authentication
and release gates remain unchanged.

Reproduce the supported cloud build from the repository root, using the
platform's existing proxy and trust bindings. Required registry authentication
must be retained through supported platform configuration; none was needed for
these public images.

```bash
BUILD_STATE=$(mktemp -d /tmp/anonfile-build.XXXXXX)
export DOCKER_CONFIG="$BUILD_STATE/docker-config"
export ANONFILE_BUILD_OVERRIDE="$BUILD_STATE/override.json"
mkdir -p "$DOCKER_CONFIG"
python - <<'PY'
import json, os, socket
from pathlib import Path
from urllib.parse import urlsplit
hosts = {urlsplit(os.environ[k]).hostname
         for k in ('HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy')
         if os.environ.get(k)}
mappings = [f'{host}={socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]}'
            for host in sorted(hosts)]
ca = os.environ.get('SSL_CERT_FILE') or '/etc/ssl/certs/ca-certificates.crt'
assert Path(ca).is_file(), 'Existing platform trust bundle required'
config = {
    'secrets': {'package_ca': {'file': ca}},
    'services': {name: {'build': {'extra_hosts': mappings,
                                 'secrets': ['package_ca']}}
                 for name in ('api', 'web', 'web-test')},
}
Path(os.environ['ANONFILE_BUILD_OVERRIDE']).write_text(json.dumps(config))
PY
docker compose -f docker-compose.yml -f "$ANONFILE_BUILD_OVERRIDE" config --quiet
docker compose -f docker-compose.yml -f "$ANONFILE_BUILD_OVERRIDE" build \
  --build-arg HTTP_PROXY --build-arg HTTPS_PROXY --build-arg NO_PROXY \
  --build-arg http_proxy --build-arg https_proxy --build-arg no_proxy \
  api web web-test
```

The full API image suite copies repository test fixtures, migrations, synthetic
sample assets, and the corpus generator into a disposable container under
`/validation`. These root-relative test inputs are outside the API build context.
Product imports are asserted to resolve to `/app/app` in the built image; no host
application module is copied over it. Pytest cache output is disabled. This layout
resolves the initial `/app/tests` collection error from tests expecting a
repository root. The cloud Docker daemon has a separate filesystem, so a bind
mount of the client's checkout cannot provide these inputs; `docker cp` transfers
the explicit fixture staging tree instead.

The existing integration scripts under `services/api/scripts/` remain the pinned
TLS container recipes. When capturing them locally, filter `::add-mask::` lines:
GitHub treats them as masking commands, while ordinary terminals print their
credential values. Preserve the underlying command's exit status.

## Hosted CI and UI work

GitHub Actions has separately reported account billing/spending-limit failures
before jobs execute. Local evidence is recorded explicitly; no failed hosted
check is described as passed and no protection or workflow is disabled.

The accompanying [quiet workbench](mockups/quiet-workbench/README.md) is a
standalone UI design preview. It does not change product detection, storage, or
release behavior. Browser QA covers its actual interactions and responsive
layout separately from the API/database tests.

### Restored workbench preview

The follow-up mockup restores the earlier entity register/correction layout and
the Documents, Relationships, and Evaluation result tabs. Independent GPT-6.1
Sol browser QA accepted the final source after correcting an existing-finding
category/reconfirmation issue. It covers 15 viewport/view combinations, keyboard
controls, graph evidence, score arithmetic, safe downloads, and reset. Its fixed
fictional scorecard remains separate from actual product validation results.
