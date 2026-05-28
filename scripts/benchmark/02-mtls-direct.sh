#!/usr/bin/env bash
#
# 02-mtls-direct.sh - Benchmark: client -(mtls)-> server
#
# Dragonfly: mTLS on 127.0.0.1:6379
#   (--tls, --tls-auth-clients, --tls-ca-cert-file)
# memtier:   connects with --tls, --cert, --key, --cacert
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

trap cleanup_on_exit EXIT

cleanup_containers
start_dragonfly_mtls

run_memtier_with_json "02-mtls-direct" "$DF_HOST" "$DF_PORT" \
	--tls \
	--cert=/certs/benchmark-client.crt \
	--key=/certs/benchmark-client.key \
	--cacert=/certs/ca.crt

print_summary "${BENCH_OUT_DIR}/02-mtls-direct"
