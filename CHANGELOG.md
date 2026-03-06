# Changelog

All notable changes to this project will be documented in this file.

## 0.1.0

- Initial release of the mTLS-authenticating DragonflyDB/Redis proxy.
- Downstream mTLS with dNSName SAN identity mapping and ACL-based AUTH injection.
- RESP-aware AUTH blocking for downstream clients.
- Upstream mTLS with optional insecure mode and session-resumption fallback.
- Live reload of ACLs.
- Dockerfile and Helm/Flux deployment examples.

## 0.1.1

- Live reload of TLS materials.
