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
