# Performance Campaign Plan

This document defines a repeatable profiling workflow for `dfguard`.

## Goals

- Improve p95 latency and/or CPU usage without changing correctness.
- Keep every optimization measurable and reversible.

## Rules

- Use the same host and load settings for before/after comparisons.
- Change one thing at a time.
- Collect two runs per scenario and compare medians.
- Keep an optimization only if it clears the acceptance threshold.

## Scenarios

1. Steady stateless traffic.
2. Connection churn traffic.
3. Mixed stateful/blocking traffic.

Current integration tests map to:

- `load_profile_ping_through_proxy` for steady/churn variants.
- `load_profile_mixed_command_classes_and_reset_reauth` for mixed routing behavior.

## Metrics to Capture

- Throughput (`req/s`)
- Latency (`p50`, `p95`, `p99`)
- CPU usage
- `dfguard_upstream_roundtrip_ms` p95
- `dfguard_pool_checkout_hit_total` and `dfguard_pool_checkout_miss_total`
- `dfguard_session_pinned_ms` p95
- `dfguard_errors_total` grouped by stage/direction

## Acceptance Thresholds

- Keep a change if one of the following is true without regressions:
  - p95 latency improves by at least 10%
  - CPU decreases by at least 10%
  - Throughput increases by at least 10%

## Round Order

1. TLS and connection setup overhead
2. Pool contention and checkout/release behavior
3. Stateful routing and pinned-session path

## Runbook

Use the helper script:

```bash
./scripts/perf_campaign.sh
```

Optional environment overrides:

- `DFGUARD_ITEST_LOAD_CLIENTS` (default `256`)
- `DFGUARD_ITEST_LOAD_REQUESTS` (default `5000`)
- `DFGUARD_ITEST_MIXED_CYCLES` (default `30000`)
- `PERF_FREQ` (default `199`)
- `PERF_OUT_DIR` (default `perf-results/<timestamp>`)

Allocator note:

- `dfguard` uses `mimalloc` as the global allocator.

The script writes:

- `flamegraph-load-ping-long.svg`
- `flamegraph-load-mixed-long.svg`
- command logs for each run

## Per-Round Report Template

- Change:
- Scenario:
- Before:
  - req/s:
  - p95:
  - CPU:
- After:
  - req/s:
  - p95:
  - CPU:
- Relevant metric deltas:
- Flamegraph delta summary:
- Decision: keep or revert
