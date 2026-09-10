# =============================================================================
# nft-gate-gateway — bespoke, minimal container image
# =============================================================================
# Multi-stage build using cargo-chef for reliable dep-layer caching:
#   planner  — computes the dependency recipe from Cargo.toml/lock
#   builder  — compiles deps (cached layer), then compiles the binary
#   runtime  — distroless/cc: libc + CA certs; no shell or package manager
#
# rustls is used (no OpenSSL), so the runtime needs only libc + CA certs,
# which distroless/cc-debian13 provides.
#
# Operators should PIN both base images by digest before deploying to production.
# =============================================================================

FROM rust:1-slim AS chef
RUN cargo install cargo-chef --locked
WORKDIR /src

# ── Planner: derive the dependency recipe ────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Builder: compile deps (cached), then the binary ──────────────────────────
FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
# This layer is re-used on every build where only src/ changes (not Cargo.lock).
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release && strip target/release/nft-gate-gateway

# ── Runtime: minimal distroless image ────────────────────────────────────────
FROM gcr.io/distroless/cc-debian13:nonroot
WORKDIR /app
COPY --from=builder /src/target/release/nft-gate-gateway /app/nft-gate-gateway
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/nft-gate-gateway"]
