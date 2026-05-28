#!/usr/bin/env bash
#
# 01-plain-direct.sh - Benchmark: client -(plain)-> server
#
# Dragonfly: plain TCP on 127.0.0.1:6379
# memtier:   connects with no TLS flags
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

trap cleanup_on_exit EXIT

cleanup_containers
start_dragonfly_plain

run_memtier_with_json "01-plain-direct" "$DF_HOST" "$DF_PORT"

print_summary "${BENCH_OUT_DIR}/01-plain-direct"
