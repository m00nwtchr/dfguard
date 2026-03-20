# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

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
