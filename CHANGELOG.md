# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Changed `DFGUARD_IDLE_TIMEOUT_SECS` default to `0` (disabled) to align with Redis server idle-timeout behavior while keeping handshake/connect timeouts configurable and bounded.
- Switched runtime metrics to OTEL-only and removed the Prometheus `/metrics` endpoint while keeping `/healthz`, `/readyz`, and `/livez` on `DFGUARD_METRICS_LISTEN`.
- Expanded telemetry with pool/routing/state/size metrics and added additional spans around handshake, checkout/connect/auth stages, and reload flows.

## 0.2.6

- Avoid initializing OTEL exporters when no OTLP endpoint is configured.

## 0.2.5

- Added OpenTelemetry traces, logs, and metrics export support over OTLP gRPC.
- Added optional metrics and probe HTTP server (`DFGUARD_METRICS_LISTEN`) with `/metrics`, `/healthz`, `/readyz`, and `/livez`.
- Updated deployment example to use environment-based configuration and HTTP probe endpoints.
- Added Docker image defaults for ACL and TLS path environment variables.
- Defaulted `DFGUARD_LISTEN` to `[::]:6379` when unspecified.

## 0.2.4

- Added environment-variable based configuration for all runtime options (`DFGUARD_*`).

## 0.2.3

- Added RESP3 response frame support in upstream parsing to prevent false "unsupported RESP response type" errors.
- Refactored pinned session tracking into an explicit state-machine model for routing and unpin transitions.
- Added upstream re-authentication after successful `RESET` to keep pooled connections authenticated.
- Expanded tests for state transitions, RESET re-auth behavior, and RESP3 frame parsing.

## 0.2.2

- Added upstream TLS connection pooling keyed by authenticated user identity.
- Added command-aware pinning for stateful Redis flows, including transaction/blocking/tracking detection.
- Added automatic unpinning for temporary state after reset commands (for example, `EXEC`, `DISCARD`, `UNWATCH`, `CLIENT TRACKING OFF`).

## 0.2.0

- Breaking: ACL files must use USER list format; ACL SETUSER lines are rejected.
- Added nopass handling (omitting a password now means no AUTH is sent upstream).
- Demoted downstream TLS handshake EOFs to debug to reduce probe noise.
- Added reload logging for ACL/TLS watcher events.

## 0.2.1

- Always send AUTH, using `AUTH <user>` when nopass is set.

## 0.1.0

- Initial release of the mTLS-authenticating DragonflyDB/Redis proxy.
- Downstream mTLS with dNSName SAN identity mapping and ACL-based AUTH injection.
- RESP-aware AUTH blocking for downstream clients.
- Upstream mTLS with optional insecure mode and session-resumption fallback.
- Live reload of ACLs.
- Dockerfile and Helm/Flux deployment examples.

## 0.1.1

- Live reload of TLS materials.
