#!/usr/bin/env bash
# Exercise the M33 worker composition against disposable TLS OpenBao and MinIO.
# This CI-only dev setup is not a production deployment recipe.
set -euo pipefail
umask 077

openbao_image="${OPENBAO_IMAGE:-openbao/openbao:2.5.5@sha256:e59b4c73cfce6875363d25548222819433c6ce0af9c6d3ec9ede220e905723f9}"
minio_image="${S3_INTEGRATION_IMAGE:-quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z@sha256:a1a8bd4ac40ad7881a245bab97323e18f971e4d4cba2c2007ec1bedd21cbaba2}"
bao_name="m36-bao-$RANDOM-$RANDOM"
s3_name="m36-s3-$RANDOM-$RANDOM"
tmp_dir="$(mktemp -d)"
bao_tls_dir="$tmp_dir/bao-tls"
s3_cert_dir="$tmp_dir/s3-certs"
root_token="$(openssl rand -hex 32)"
s3_access_key="m36$(openssl rand -hex 12)"
s3_secret_key="m36-$(openssl rand -hex 32)"

cleanup() {
  docker rm -f "$bao_name" "$s3_name" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

command -v docker >/dev/null
command -v openssl >/dev/null
command -v curl >/dev/null
command -v python >/dev/null
install -d -m 700 "$bao_tls_dir"
install -d -m 755 "$s3_cert_dir"
[[ "$(stat -c '%a' "$bao_tls_dir")" == "700" ]] || { echo 'OpenBao TLS directory permissions are unsafe' >&2; exit 1; }
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
  -keyout "$s3_cert_dir/private.key" -out "$s3_cert_dir/public.crt" \
  -subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' >/dev/null 2>&1
chmod 600 "$s3_cert_dir/private.key"
chmod 644 "$s3_cert_dir/public.crt"
printf '::add-mask::%s\n::add-mask::%s\n::add-mask::%s\n' "$root_token" "$s3_access_key" "$s3_secret_key"

docker run --detach --rm --name "$bao_name" --publish 127.0.0.1::8200 \
  --user "$(id -u):$(id -g)" --volume "$bao_tls_dir:/tls" \
  "$openbao_image" server -dev-tls -dev-tls-cert-dir=/tls -dev-no-store-token \
  -dev-root-token-id="$root_token" -dev-listen-address=0.0.0.0:8200 >/dev/null
docker run --detach --rm --name "$s3_name" --publish 127.0.0.1::9000 \
  --env "MINIO_ROOT_USER=$s3_access_key" --env "MINIO_ROOT_PASSWORD=$s3_secret_key" \
  --volume "$s3_cert_dir:/certs:ro" \
  "$minio_image" server --certs-dir /certs --address ':9000' --console-address ':9001' /data >/dev/null

bao_ca="$bao_tls_dir/vault-ca.pem"
root_bao=(docker exec --interactive --env BAO_ADDR=https://127.0.0.1:8200 --env BAO_CACERT=/tls/vault-ca.pem --env "BAO_TOKEN=$root_token" "$bao_name" bao)
for _ in $(seq 1 30); do
  if [[ -s "$bao_ca" ]] && "${root_bao[@]}" token lookup >/dev/null 2>&1; then break; fi
  sleep 1
done
[[ -s "$bao_ca" ]] || { echo 'OpenBao TLS CA was not generated' >&2; exit 1; }
s3_endpoint="https://127.0.0.1:$(docker port "$s3_name" 9000/tcp | sed 's/.*://')"
for _ in $(seq 1 30); do
  if curl --silent --show-error --fail --cacert "$s3_cert_dir/public.crt" "$s3_endpoint/minio/health/live" >/dev/null; then break; fi
  sleep 1
done
curl --silent --show-error --fail --cacert "$s3_cert_dir/public.crt" "$s3_endpoint/minio/health/live" >/dev/null

"${root_bao[@]}" token lookup >/dev/null
"${root_bao[@]}" secrets enable transit >/dev/null
"${root_bao[@]}" write transit/keys/m36-worker-envelope type=aes256-gcm96 derived=false exportable=false allow_plaintext_backup=false >/dev/null
cat <<'POLICY' | "${root_bao[@]}" policy write m36-worker-full - >/dev/null
path "transit/keys/m36-worker-envelope" {
  capabilities = ["read"]
}
path "transit/datakey/plaintext/m36-worker-envelope" {
  capabilities = ["update"]
}
path "transit/decrypt/m36-worker-envelope" {
  capabilities = ["update"]
}
POLICY
cat <<'POLICY' | "${root_bao[@]}" policy write m36-worker-no-decrypt - >/dev/null
path "transit/keys/m36-worker-envelope" {
  capabilities = ["read"]
}
POLICY
full_json="$("${root_bao[@]}" token create -format=json -no-default-policy -policy=m36-worker-full -ttl=5m)"
no_decrypt_json="$("${root_bao[@]}" token create -format=json -no-default-policy -policy=m36-worker-no-decrypt -ttl=5m)"
metadata_json="$("${root_bao[@]}" read -format=json transit/keys/m36-worker-envelope)"
full_token="$(python -c 'import json,sys; print(json.loads(sys.stdin.read())["auth"]["client_token"])' <<<"$full_json")"
no_decrypt_token="$(python -c 'import json,sys; print(json.loads(sys.stdin.read())["auth"]["client_token"])' <<<"$no_decrypt_json")"
key_version="$(python -c 'import json,sys; print(json.loads(sys.stdin.read())["data"]["latest_version"])' <<<"$metadata_json")"
printf '::add-mask::%s\n::add-mask::%s\n' "$full_token" "$no_decrypt_token"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root/services/api"
M36_LIVE_OBJECT_PATH=1 \
M36_OPENBAO_ENDPOINT="https://127.0.0.1:$(docker port "$bao_name" 8200/tcp | sed 's/.*://')" \
M36_OPENBAO_CA_FILE="$bao_ca" \
M36_OPENBAO_TOKEN="$full_token" \
M36_OPENBAO_NO_DECRYPT_TOKEN="$no_decrypt_token" \
M36_OPENBAO_KEY_VERSION="$key_version" \
M36_S3_ENDPOINT="$s3_endpoint" \
M36_S3_CA_FILE="$s3_cert_dir/public.crt" \
M36_S3_ACCESS_KEY="$s3_access_key" \
M36_S3_SECRET_KEY="$s3_secret_key" \
SSL_CERT_FILE="$bao_ca" \
python -m pytest -q tests/test_worker_encrypted_objects_integration.py
