FROM rust:1.92.0-bookworm AS builder

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends musl-tools pkg-config \
  && rm -rf /var/lib/apt/lists/*

RUN rustup target add x86_64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM scratch

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/dfguard /dfguard

ENV DFGUARD_ACL="/config/acl.conf" \
    DFGUARD_SERVER_CERT="/tls/server/tls.crt" \
    DFGUARD_SERVER_KEY="/tls/server/tls.key" \
    DFGUARD_SERVER_CA="/tls/server/ca.crt" \
    DFGUARD_UPSTREAM_CERT="/tls/upstream/tls.crt" \
    DFGUARD_UPSTREAM_KEY="/tls/upstream/tls.key" \
    DFGUARD_UPSTREAM_CA="/tls/upstream/ca.crt"
USER 65532:65532

ENTRYPOINT ["/dfguard"]
