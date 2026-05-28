#!/usr/bin/env bash
#
# run-all.sh - Orchestrator: runs all benchmark scenarios sequentially
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/common.sh"

echo "========================================================"
echo "  dfguard Benchmark Suite"
echo "========================================================"
echo "  Output directory: ${BENCH_OUT_DIR}"
echo "  Clients:          ${BENCH_CLIENTS}"
echo "  Threads:          ${BENCH_THREADS}"
echo "  Requests:         ${BENCH_REQUESTS}"
echo "  Data size:        ${BENCH_DATA_SIZE} bytes"
echo "  Ratio (SET:GET):  ${BENCH_RATIO}"
echo "========================================================"

SCENARIOS=(
	"01-plain-direct.sh"
	"02-mtls-direct.sh"
)

for script in "${SCENARIOS[@]}"; do
	echo ""
	echo "========================================================"
	echo "  Running: $script"
	echo "========================================================"
	bash "${SCRIPT_DIR}/${script}"
done

echo ""
echo "========================================================"
echo "  Comparison Summary"
echo "========================================================"

for scenario_dir in "${BENCH_OUT_DIR}"/*/; do
	print_summary "$scenario_dir"
done

echo "All results saved to: ${BENCH_OUT_DIR}"
