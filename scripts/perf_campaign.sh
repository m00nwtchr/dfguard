#!/usr/bin/env bash
set -euo pipefail

if ! command -v cargo >/dev/null 2>&1; then
	echo "cargo is required" >&2
	exit 1
fi

if ! cargo flamegraph --help >/dev/null 2>&1; then
	echo "cargo flamegraph is required (cargo install flamegraph)" >&2
	exit 1
fi

timestamp="$(date +%Y%m%d-%H%M%S)"
out_dir="${PERF_OUT_DIR:-perf-results/$timestamp}"
freq="${PERF_FREQ:-199}"
load_clients="${DFGUARD_ITEST_LOAD_CLIENTS:-256}"
load_requests="${DFGUARD_ITEST_LOAD_REQUESTS:-5000}"
mixed_cycles="${DFGUARD_ITEST_MIXED_CYCLES:-30000}"

mkdir -p "$out_dir"

echo "Output directory: $out_dir"
echo "Sampling frequency: $freq"
echo "Ping load: clients=$load_clients requests=$load_requests"
echo "Mixed load: cycles=$mixed_cycles"

echo "[1/4] Warm up ping load test"
DFGUARD_ITEST_LOAD_CLIENTS="$load_clients" \
	DFGUARD_ITEST_LOAD_REQUESTS="$load_requests" \
	cargo test --test load_integration --release -- load_profile_ping_through_proxy |
	tee "$out_dir/warmup-ping.log"

echo "[2/4] Flamegraph ping load test"
CARGO_PROFILE_RELEASE_DEBUG=true \
	DFGUARD_ITEST_LOAD_CLIENTS="$load_clients" \
	DFGUARD_ITEST_LOAD_REQUESTS="$load_requests" \
	cargo flamegraph --test load_integration -F "$freq" \
	--output "$out_dir/flamegraph-load-ping-long.svg" \
	-- load_profile_ping_through_proxy |
	tee "$out_dir/flamegraph-ping.log"

echo "[3/4] Warm up mixed load test"
DFGUARD_ITEST_MIXED_CYCLES="$mixed_cycles" \
	cargo test --test load_integration --release -- load_profile_mixed_command_classes_and_reset_reauth |
	tee "$out_dir/warmup-mixed.log"

echo "[4/4] Flamegraph mixed load test"
CARGO_PROFILE_RELEASE_DEBUG=true \
	DFGUARD_ITEST_MIXED_CYCLES="$mixed_cycles" \
	cargo flamegraph --test load_integration -F "$freq" \
	--output "$out_dir/flamegraph-load-mixed-long.svg" \
	-- load_profile_mixed_command_classes_and_reset_reauth |
	tee "$out_dir/flamegraph-mixed.log"

if [[ -f perf.data ]]; then
	mv perf.data "$out_dir/perf.data"
fi
if [[ -f perf.data.old ]]; then
	mv perf.data.old "$out_dir/perf.data.old"
fi

echo "Done. Results are in: $out_dir"
