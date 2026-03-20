# dfguard

Minimal mTLS-authenticating proxy for DragonflyDB/Redis.

## What it does

- Accepts downstream mTLS connections and extracts the user from the client cert dNSName SAN.
- Connects upstream to DragonflyDB using its own mTLS client cert.
- Automatically sends `AUTH <user> <password>` based on `acl.conf`.
- Blocks `AUTH` commands from downstream clients.
- Uses upstream TLS connection pooling keyed by user.
- Pins connections for stateful commands and unpins when state is cleared (for example, `EXEC`/`DISCARD`/`UNWATCH` and `CLIENT TRACKING OFF`).

## Requirements

- Rust toolchain
- TLS material for downstream server and upstream client
- ACL file in Redis command format (see below)

## Build

```bash
cargo build --release
```

## Run

```bash
./target/release/dfguard \
  --listen 0.0.0.0:6380 \
  --upstream dragonfly.example:6379 \
  --acl /path/to/acl.conf \
  --server-cert /path/to/server.crt \
  --server-key /path/to/server.key \
  --server-ca /path/to/server-ca.crt \
  --upstream-cert /path/to/upstream.crt \
  --upstream-key /path/to/upstream.key \
  --upstream-ca /path/to/upstream-ca.crt

# Insecure upstream TLS (skips verification)

./target/release/dfguard \
  --insecure-upstream \
  --listen 0.0.0.0:6380 \
  --upstream dragonfly.example:6379 \
  --acl /path/to/acl.conf \
  --server-cert /path/to/server.crt \
  --server-key /path/to/server.key \
  --server-ca /path/to/server-ca.crt \
  --upstream-cert /path/to/upstream.crt \
  --upstream-key /path/to/upstream.key \
  --upstream-ca /path/to/upstream-ca.crt
```

You can also configure all options via environment variables:

```bash
DFGUARD_LISTEN=0.0.0.0:6380
DFGUARD_UPSTREAM=dragonfly.example:6379
DFGUARD_ACL=/path/to/acl.conf
DFGUARD_SERVER_CERT=/path/to/server.crt
DFGUARD_SERVER_KEY=/path/to/server.key
DFGUARD_SERVER_CA=/path/to/server-ca.crt
DFGUARD_UPSTREAM_CERT=/path/to/upstream.crt
DFGUARD_UPSTREAM_KEY=/path/to/upstream.key
DFGUARD_UPSTREAM_CA=/path/to/upstream-ca.crt
./target/release/dfguard
```

Optional env vars:

- `DFGUARD_LISTEN` (default `[::]:6379`)
- `DFGUARD_HANDSHAKE_TIMEOUT_SECS` (default `10`)
- `DFGUARD_IDLE_TIMEOUT_SECS` (default `300`)
- `DFGUARD_MAX_FRAME_SIZE` (default `16777216`)
- `DFGUARD_POOL_MAX_IDLE_PER_USER` (default `64`)
- `DFGUARD_INSECURE_UPSTREAM` (default `false`)
- `DFGUARD_METRICS_LISTEN` (disabled by default, for example `0.0.0.0:9464`)

CLI flags override environment variables.

## Observability

When OTEL is configured, `dfguard` exports traces, logs, and metrics via OTLP gRPC.

Common OTEL environment variables:

- `OTEL_EXPORTER_OTLP_ENDPOINT` (for example `http://otel-collector:4317`)
- `OTEL_SERVICE_NAME` (defaults to `dfguard`)
- `OTEL_SDK_DISABLED=true` to disable OTEL initialization

Metrics and probes are exposed only when `DFGUARD_METRICS_LISTEN` is set:

- `/metrics` (Prometheus format)
- `/healthz`
- `/readyz`
- `/livez`

## ACL format

Lines follow Redis ACL list format. The proxy extracts the user after `USER` and the last password token starting with `>`.

Example:

```text
USER service-a ON >service_a_secret +@all ~*
USER user1 NAMESPACE:namespace1 ON >user_pass +@all ~*
```

Duplicate users are rejected. Comments with `#` are ignored.

## TLS identity

The downstream client certificate must include exactly one `dNSName` SAN entry. That value is used as the Redis user.

## ACL reloads

The ACL file is watched with inotify (via `notify`) and reloaded on changes.

## Notes

- The proxy is minimally invasive: it only injects initial `AUTH` and blocks downstream `AUTH`.
- Stateful commands (for example, `SUBSCRIBE`, `MONITOR`, and `SELECT`) keep a connection pinned for the lifetime of that downstream session.
- Secrets are never logged.
