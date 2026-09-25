#!/usr/bin/env bash
# Exercise M32 against one exact, disposable S3-compatible server in CI.
# This is an interoperability check, never a production deployment recipe.
set -euo pipefail
umask 077

# The former MinIO Quay manifest is no longer anonymously accessible. Keep
# this synthetic interoperability gate on a versioned, digest-pinned image.
image="${S3_INTEGRATION_IMAGE:-rustfs/rustfs:1.0.0@sha256:8cc9801755448b71a786705ce76692c77e14936cccd87cf2fc31842e58f4d1ff}"
name="m34-s3-$RANDOM-$RANDOM"
tmp_dir="$(mktemp -d)"
cert_dir="$tmp_dir/certs"
data_dir="$tmp_dir/data"
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

install -d -m 700 "$cert_dir" "$data_dir"
install -d -m 700 "$data_dir/logs"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -keyout "$cert_dir/rustfs_key.pem" -out "$cert_dir/rustfs_cert.pem" \
  -subj '/CN=localhost' \
  -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
chmod 600 "$cert_dir/rustfs_key.pem"
chmod 644 "$cert_dir/rustfs_cert.pem"
printf '::add-mask::%s\n::add-mask::%s\n' "$root_user" "$root_password"

docker run --detach --rm --name "$name" --publish 127.0.0.1::9000 \
  --user "$(id -u):$(id -g)" \
  --env "RUSTFS_ACCESS_KEY=$root_user" --env "RUSTFS_SECRET_KEY=$root_password" \
  --env RUSTFS_TLS_PATH=/certs --env RUSTFS_VOLUMES=/data \
  --env RUSTFS_OBS_LOG_DIRECTORY=/data/logs \
  --volume "$cert_dir:/certs:ro" --volume "$data_dir:/data" \
  "$image" >/dev/null

port="$(docker port "$name" 9000/tcp | sed 's/.*://')"
endpoint="https://127.0.0.1:$port"
for _ in $(seq 1 30); do
  if curl --silent --show-error --fail --cacert "$cert_dir/rustfs_cert.pem" "$endpoint/health" >/dev/null; then
    break
  fi
  sleep 1
done
curl --silent --show-error --fail --cacert "$cert_dir/rustfs_cert.pem" "$endpoint/health" >/dev/null

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root/services/api"
S3_CIPHERTEXT_INTEGRATION=1 \
S3_CIPHERTEXT_INTEGRATION_ENDPOINT="$endpoint" \
S3_CIPHERTEXT_INTEGRATION_CA_FILE="$cert_dir/rustfs_cert.pem" \
S3_CIPHERTEXT_INTEGRATION_ACCESS_KEY="$root_user" \
S3_CIPHERTEXT_INTEGRATION_SECRET_KEY="$root_password" \
python -m pytest -q tests/test_s3_ciphertext_integration.py tests/test_s3_versioned_ciphertext_integration.py
