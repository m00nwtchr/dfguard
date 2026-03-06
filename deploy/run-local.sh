#!/usr/bin/env bash
set -euo pipefail

NS="${NS:-database}"
CTX="${CTX:-}"
OUT="${OUT:-/tmp/dfguard}"

mkdir -p "${OUT}/"{server,client,dragonfly,ca,config}

CTX_ARGS=()
if [[ -n "${CTX}" ]]; then
	CTX_ARGS=(--context "${CTX}")
fi

kubectl "${CTX_ARGS[@]}" -n "${NS}" get secret dfguard-server-cert -o jsonpath='{.data.tls\.crt}' | base64 -d >"${OUT}/server/tls.crt"
kubectl "${CTX_ARGS[@]}" -n "${NS}" get secret dfguard-server-cert -o jsonpath='{.data.tls\.key}' | base64 -d >"${OUT}/server/tls.key"

kubectl "${CTX_ARGS[@]}" -n "${NS}" get secret dfguard-client-ca -o jsonpath='{.data.ca\.crt}' | base64 -d >"${OUT}/client/ca.crt"

kubectl "${CTX_ARGS[@]}" -n "${NS}" get secret dfguard-client-cert -o jsonpath='{.data.tls\.crt}' | base64 -d >"${OUT}/dragonfly/tls.crt"
kubectl "${CTX_ARGS[@]}" -n "${NS}" get secret dfguard-client-cert -o jsonpath='{.data.tls\.key}' | base64 -d >"${OUT}/dragonfly/tls.key"

kubectl "${CTX_ARGS[@]}" -n "${NS}" get configmap root-ca -o jsonpath='{.data.ca\.crt}' >"${OUT}/ca/ca.crt"

kubectl "${CTX_ARGS[@]}" -n "${NS}" get secret dragonfly-acls -o jsonpath='{.data.acl\.conf}' | base64 -d >"${OUT}/config/acl.conf"

RUST_LOG="${RUST_LOG:-debug}" \
	cargo run -p dfguard -- \
	--listen "[::]:6380" \
	--upstream localhost:6379 \
	--acl "${OUT}/config/acl.conf" \
	--server-cert "${OUT}/server/tls.crt" \
	--server-key "${OUT}/server/tls.key" \
	--server-ca "${OUT}/client/ca.crt" \
	--upstream-cert "${OUT}/dragonfly/tls.crt" \
	--upstream-key "${OUT}/dragonfly/tls.key" \
	--upstream-ca "${OUT}/ca/ca.crt" \
	--insecure-upstream
