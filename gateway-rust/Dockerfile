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
# Both base images are pinned by digest (multi-arch index); bump tag and digest together.
# =============================================================================

FROM rust:1-slim@sha256:4cd829461bd5c4d511c32e269da9cb8929223b666519d8004e35fc8d1d771ab7 AS chef
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /src

# ── Planner: derive the dependency recipe ────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Builder: compile deps (cached), then the binary ──────────────────────────
FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
# This layer is re-used on every build where only src/ changes (not Cargo.lock).
RUN cargo chef cook --release --locked --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked && strip target/release/nft-gate-gateway

# ── Runtime: minimal distroless image ────────────────────────────────────────
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:54df941ed0d06a1bd95ef5e0ce391fd8d9f94b64782dc9a60062727849ee3f97
WORKDIR /app
COPY --from=builder /src/target/release/nft-gate-gateway /app/nft-gate-gateway
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/nft-gate-gateway"]
