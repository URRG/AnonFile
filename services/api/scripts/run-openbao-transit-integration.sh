#!/usr/bin/env bash
# Start a disposable, TLS-enabled OpenBao dev server and run the opt-in check.
# Dev mode is for CI/local experimentation only; never use this script in production.
set -euo pipefail
umask 077

image="${OPENBAO_IMAGE:-openbao/openbao:2.5.5@sha256:e59b4c73cfce6875363d25548222819433c6ce0af9c6d3ec9ede220e905723f9}"
name="m29-openbao-$RANDOM-$RANDOM"
tmp_dir="$(mktemp -d)"
tls_dir="$tmp_dir/tls"
root_token="$(openssl rand -hex 32)"

cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

command -v docker >/dev/null
command -v openssl >/dev/null
command -v python >/dev/null
install -d -m 700 "$tls_dir"
[[ "$(stat -c '%a' "$tls_dir")" == "700" ]] || { echo 'TLS directory permissions are unsafe' >&2; exit 1; }
printf '::add-mask::%s\n' "$root_token"

docker run --detach --rm --name "$name" --publish 127.0.0.1::8200 \
  --user "$(id -u):$(id -g)" \
  --volume "$tls_dir:/tls" \
  "$image" server -dev-tls -dev-tls-cert-dir=/tls -dev-no-store-token \
  -dev-root-token-id="$root_token" \
  -dev-listen-address=0.0.0.0:8200 >/dev/null

ca_cert="$tmp_dir/tls/vault-ca.pem"
root_bao=(docker exec --interactive --env BAO_ADDR=https://127.0.0.1:8200 --env BAO_CACERT=/tls/vault-ca.pem --env "BAO_TOKEN=$root_token" "$name" bao)
for _ in $(seq 1 30); do
  if [[ -s "$ca_cert" ]] && "${root_bao[@]}" token lookup >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
[[ -s "$ca_cert" ]] || { echo 'OpenBao TLS CA was not generated' >&2; exit 1; }

"${root_bao[@]}" token lookup >/dev/null
"${root_bao[@]}" secrets enable transit >/dev/null
"${root_bao[@]}" write transit/keys/m29-integration-ed25519 type=ed25519 exportable=false allow_plaintext_backup=false >/dev/null

cat <<'POLICY' | "${root_bao[@]}" policy write m29-transit-integration - >/dev/null
path "transit/keys/m29-integration-ed25519" {
  capabilities = ["read"]
}
path "transit/sign/m29-integration-ed25519" {
  capabilities = ["update"]
}
path "transit/verify/m29-integration-ed25519" {
  capabilities = ["update"]
}
POLICY
cat <<'POLICY' | "${root_bao[@]}" policy write m29-transit-sign-only - >/dev/null
path "transit/keys/m29-integration-ed25519" {
  capabilities = ["read"]
}
path "transit/sign/m29-integration-ed25519" {
  capabilities = ["update"]
}
POLICY

primary_json="$("${root_bao[@]}" token create -format=json -no-default-policy -policy=m29-transit-integration -ttl=5m)"
sign_only_json="$("${root_bao[@]}" token create -format=json -no-default-policy -policy=m29-transit-sign-only -ttl=5m)"
metadata_json="$("${root_bao[@]}" read -format=json transit/keys/m29-integration-ed25519)"
primary_token="$(python -c 'import json,sys; print(json.loads(sys.stdin.read())["auth"]["client_token"])' <<<"$primary_json")"
sign_only_token="$(python -c 'import json,sys; print(json.loads(sys.stdin.read())["auth"]["client_token"])' <<<"$sign_only_json")"
read -r public_key key_version < <(python -c 'import json,sys; data=json.loads(sys.stdin.read())["data"]; version=str(data["latest_version"]); print(data["keys"][version]["public_key"], version)' <<<"$metadata_json")
printf '::add-mask::%s\n::add-mask::%s\n' "$primary_token" "$sign_only_token"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$repo_root/services/api"
OPENBAO_TRANSIT_INTEGRATION=1 \
OPENBAO_INTEGRATION_URL=https://127.0.0.1:"$(docker port "$name" 8200/tcp | sed 's/.*://')" \
OPENBAO_INTEGRATION_TOKEN="$primary_token" \
OPENBAO_INTEGRATION_SIGN_ONLY_TOKEN="$sign_only_token" \
OPENBAO_INTEGRATION_PUBLIC_KEY="$public_key" \
OPENBAO_INTEGRATION_KEY_VERSION="$key_version" \
SSL_CERT_FILE="$ca_cert" \
python -m pytest -q tests/test_openbao_transit_integration.py
