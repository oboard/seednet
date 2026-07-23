# ── Build stage ──────────────────────────────────────────────────────────────
FROM rust:1.93.1-alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /build
COPY . .

RUN cargo build --release --bin seednet

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM alpine:3.21

COPY --from=builder /build/target/release/seednet /usr/local/bin/seednet

ENTRYPOINT ["seednet"]
