#!/usr/bin/env bash
#
# common.sh - Shared functions for dfguard benchmark suite
#

set -euo pipefail

# ---------------------------------------------------------------------------
# Configurable parameters (env overrides)
# ---------------------------------------------------------------------------
BENCH_CLIENTS="${BENCH_CLIENTS:-50}"
BENCH_THREADS="${BENCH_THREADS:-4}"
BENCH_REQUESTS="${BENCH_REQUESTS:-100000}"
BENCH_DATA_SIZE="${BENCH_DATA_SIZE:-32}"
BENCH_RATIO="${BENCH_RATIO:-1:10}"
BENCH_OUT_DIR="${BENCH_OUT_DIR:-benchmark-results/$(date +%Y%m%d-%H%M%S)}"
DRAGONFLY_IMAGE="${DRAGONFLY_IMAGE:-docker.dragonflydb.io/dragonflydb/dragonfly}"
MEMTIER_IMAGE="${MEMTIER_IMAGE:-redislabs/memtier_benchmark:latest}"

# Container naming
DF_CONTAINER="df-bench-server"
MEMTIER_CONTAINER="df-bench-client"

# Dragonfly resource limits
DF_MAX_MEMORY="${DF_MAX_MEMORY:-2gb}"
DF_PROACTOR_THREADS="${DF_PROACTOR_THREADS:-4}"

# Host ports used with --network host
DF_PORT=6379
DF_HOST="127.0.0.1"

# Paths to certs (resolved relative to project root)
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CERTS_DIR="${PROJECT_ROOT}/certs"

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
log_info() {
	echo "[INFO]  $(date '+%H:%M:%S') $*"
}

log_ok() {
	echo "[OK]    $(date '+%H:%M:%S') $*"
}

log_err() {
	echo "[ERROR] $(date '+%H:%M:%S') $*" >&2
}

# ---------------------------------------------------------------------------
# Cleanup helpers
# ---------------------------------------------------------------------------
cleanup_containers() {
	log_info "Cleaning up containers..."
	podman rm -f "$DF_CONTAINER" >/dev/null 2>&1 || true
	podman rm -f "$MEMTIER_CONTAINER" >/dev/null 2>&1 || true
}

cleanup_on_exit() {
	cleanup_containers
}

# ---------------------------------------------------------------------------
# Wait helpers
# ---------------------------------------------------------------------------
wait_for_dragonfly() {
	local port="${1:-$DF_PORT}"
	local tls="${2:-false}"
	local max_retries=30
	local retry=0

	log_info "Waiting for Dragonfly on port $port..."
	while ((retry < max_retries)); do
		local args=(-h "$DF_HOST" -p "$port" --no-auth-warning ping)
		if [[ "$tls" == "true" ]]; then
			args=(--tls --cert "${CERTS_DIR}/benchmark-client.crt" --key "${CERTS_DIR}/benchmark-client.key" --cacert "${CERTS_DIR}/ca.crt" "${args[@]}")
		fi
		if redis-cli "${args[@]}" 2>/dev/null | grep -q PONG; then
			log_ok "Dragonfly is ready on port $port"
			return 0
		fi
		retry=$((retry + 1))
		sleep 1
	done

	log_err "Dragonfly did not become ready in ${max_retries}s"
	return 1
}

# ---------------------------------------------------------------------------
# Benchmark runner
# ---------------------------------------------------------------------------
run_memtier_with_json() {
	local scenario="$1"
	local host="$2"
	local port="$3"
	shift 3

	local scenario_dir="${BENCH_OUT_DIR}/${scenario}"
	mkdir -p "$scenario_dir"

	local json_out="${scenario_dir}/results.json"
	local text_out="${scenario_dir}/results.txt"
	local raw_out="${scenario_dir}/raw.log"

	log_info "Running memtier-benchmark: ${BENCH_THREADS} threads, ${BENCH_CLIENTS} clients, ${BENCH_REQUESTS} requests"

	local tmpdir
	tmpdir="$(mktemp -d)"

	podman run --rm \
		--network host \
		--name "$MEMTIER_CONTAINER" \
		-v "${tmpdir}:/out:z" \
		"${MEMTIER_IMAGE}" \
		memtier_benchmark \
		--server="$host" \
		--port="$port" \
		--protocol=redis \
		--threads="$BENCH_THREADS" \
		--clients="$BENCH_CLIENTS" \
		--requests="$BENCH_REQUESTS" \
		--data-size="$BENCH_DATA_SIZE" \
		--ratio="$BENCH_RATIO" \
		--json-out-file=/out/results.json \
		"$@" \
		2>&1 | tee "$raw_out"

	if [[ -f "${tmpdir}/results.json" ]]; then
		cp "${tmpdir}/results.json" "$json_out"
		log_ok "JSON results saved to $json_out"
	fi

	tail -n 30 "$raw_out" >"$text_out"

	rm -rf "$tmpdir"
}

# ---------------------------------------------------------------------------
# Result summarisation
# ---------------------------------------------------------------------------
print_summary() {
	local scenario_dir="$1"
	local raw_out="${scenario_dir}/raw.log"

	if [[ ! -f "$raw_out" ]]; then
		log_err "No raw log found in $scenario_dir"
		return 1
	fi

	echo ""
	echo "============================================================"
	echo "  Results: $(basename "$scenario_dir")"
	echo "============================================================"

	local totals
	totals="$(grep -E '^Totals ' "$raw_out" | tail -1)" || true

	if [[ -n "$totals" ]]; then
		local rps avg_lat p50 p99 kb_sec
		rps="$(echo "$totals" | awk '{print $2}')"
		avg_lat="$(echo "$totals" | awk '{print $5}')"
		p50="$(echo "$totals" | awk '{print $6}')"
		p99="$(echo "$totals" | awk '{print $7}')"
		kb_sec="$(echo "$totals" | awk '{print $8}')"

		local total_reqs
		total_reqs="$((BENCH_THREADS * BENCH_CLIENTS * BENCH_REQUESTS))"

		printf "  Total Requests: %s\n" "$total_reqs"
		printf "  Throughput:     %s ops/sec\n" "$rps"
		printf "  Avg Latency:    %s ms\n" "$avg_lat"
		printf "  p50 Latency:    %s ms\n" "$p50"
		printf "  p99 Latency:    %s ms\n" "$p99"
		printf "  Bandwidth:      %s KB/sec\n" "$kb_sec"
	else
		log_err "Could not parse totals from raw log"
	fi

	echo "============================================================"
	echo ""
}

# ---------------------------------------------------------------------------
# Dragonfly start helpers
# ---------------------------------------------------------------------------
start_dragonfly_plain() {
	log_info "Starting Dragonfly (plain)..."
	podman run -d \
		--name "$DF_CONTAINER" \
		--network host \
		--rm \
		"${DRAGONFLY_IMAGE}" \
		--port="$DF_PORT" \
		--maxmemory="$DF_MAX_MEMORY" \
		--proactor_threads="$DF_PROACTOR_THREADS" \
		--logtostderr

	wait_for_dragonfly "$DF_PORT" "false"
}

start_dragonfly_mtls() {
	log_info "Starting Dragonfly (mTLS)..."

	podman run -d \
		--name "$DF_CONTAINER" \
		--network host \
		--rm \
		-v "${CERTS_DIR}:/certs:ro,z" \
		"${DRAGONFLY_IMAGE}" \
		--port="$DF_PORT" \
		--maxmemory="$DF_MAX_MEMORY" \
		--proactor_threads="$DF_PROACTOR_THREADS" \
		--tls \
		--tls_cert_file=/certs/dragonfly-server.crt \
		--tls_key_file=/certs/dragonfly-server.key \
		--tls_ca_cert_file=/certs/ca.crt \
		--tls_auth_clients \
		--logtostderr

	wait_for_dragonfly "$DF_PORT" "true"
}
