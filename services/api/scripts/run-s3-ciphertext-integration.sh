#!/usr/bin/env bash
# Exercise M32 against one exact, disposable S3-compatible server in CI.
# This is an interoperability check, never a production deployment recipe.
set -euo pipefail
umask 077

# This exact MinIO release includes its conditional-write fixes.  The image is
# pinned to the published Quay manifest digest, not a mutable tag.
image="${S3_INTEGRATION_IMAGE:-quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2}"
name="m34-s3-$RANDOM-$RANDOM"
tmp_dir="$(mktemp -d)"
cert_dir="$tmp_dir/certs"
root_user="m34$(openssl rand -hex 12)"
root_password="m34-$(openssl rand -hex 32)"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

command -v docker >/dev/null
command -v openssl >/dev/null
command -v curl >/dev/null
command -v python >/dev/null

install -d -m 755 "$cert_dir"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -keyout "$cert_dir/private.key" -out "$cert_dir/public.crt" \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
chmod 600 "$cert_dir/private.key"
chmod 644 "$cert_dir/public.crt"
printf '::add-mask::%s\n::add-mask::%s\n' "$root_user" "$root_password"

docker run --detach --rm --name "$name" --publish 127.0.0.1::9000 \
  --env "MINIO_ROOT_USER=$root_user" --env "MINIO_ROOT_PASSWORD=$root_password" \
  --volume "$cert_dir:/certs:ro" \
  "$image" server --certs-dir /certs --address ':9000' --console-address ':9001' /data >/dev/null

port="$(docker port "$name" 9000/tcp | sed 's/.*://')"
endpoint="https://127.0.0.1:$port"
for _ in $(seq 1 30); do
  if curl --silent --show-error --fail --cacert "$cert_dir/public.crt" "$endpoint/minio/health/live" >/dev/null; then
    break
  fi
  sleep 1
done
curl --silent --show-error --fail --cacert "$cert_dir/public.crt" "$endpoint/minio/health/live" >/dev/null

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root/services/api"
S3_CIPHERTEXT_INTEGRATION=1 \
S3_CIPHERTEXT_INTEGRATION_ENDPOINT="$endpoint" \
S3_CIPHERTEXT_INTEGRATION_CA_FILE="$cert_dir/public.crt" \
S3_CIPHERTEXT_INTEGRATION_ACCESS_KEY="$root_user" \
S3_CIPHERTEXT_INTEGRATION_SECRET_KEY="$root_password" \
python -m pytest -q tests/test_s3_ciphertext_integration.py tests/test_s3_versioned_ciphertext_integration.py
