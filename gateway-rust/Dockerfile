# =============================================================================
# access-gate-gateway — bespoke, minimal container image
# =============================================================================
# BUILD CONTEXT = THE REPOSITORY ROOT (the crate depends on ../core in the Cargo workspace):
#   docker build -f gateway-rust/Dockerfile .
# The root .dockerignore keeps the context to Cargo.toml, Cargo.lock, core/ and gateway-rust/.
#
# Multi-stage build using cargo-chef for reliable dep-layer caching:
#   planner  — computes the dependency recipe from Cargo.toml/lock
#   notices  — cargo-about licence notices of the linked crates (fails on an unaccepted licence)
#   builder  — compiles deps (cached layer), then compiles the binary
#   runtime  — distroless/cc: libc + CA certs; no shell or package manager
#
# rustls is used (no OpenSSL), so the runtime needs only libc + CA certs,
# which distroless/cc-debian13 provides.
#
# Both base images are pinned by digest (multi-arch index); bump tag and digest together.
# =============================================================================

FROM rust:1-slim@sha256:4df2ae8cfdfebdfc13a65da7f253b73d68983dc0339f2719bc17a279c913b13d AS chef
RUN cargo install cargo-chef --version 0.1.78 --locked
WORKDIR /src

# ── Planner: derive the dependency recipe ────────────────────────────────────
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ── Licence notices (Apache-2.0 §4(a) and the MIT/BSD notice clauses) ────────
# `--fail` stops the build when a linked crate's licence is not accepted by gateway-rust/about.toml. CI
# builds this target alone (`--target notices`) so a licence problem shows up without a full compile.
FROM chef AS notices
RUN cargo install --locked --version 0.9.2 --features cli cargo-about
COPY . .
RUN mkdir -p /out \
 && cargo about generate --locked --fail -c gateway-rust/about.toml --manifest-path gateway-rust/Cargo.toml gateway-rust/about.hbs \
      > /out/THIRD_PARTY_LICENSES.txt \
 && grep -q 'Apache License' /out/THIRD_PARTY_LICENSES.txt

# ── Builder: compile deps (cached), then the binary ──────────────────────────
FROM chef AS builder
COPY --from=planner /src/recipe.json recipe.json
# This layer is re-used on every build where only src/ changes (not Cargo.lock). Only the gateway and
# what it depends on are built: the workspace may hold crates (the Worker) that need another target.
RUN cargo chef cook --release --locked -p access-gate-gateway --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p access-gate-gateway && strip target/release/access-gate-gateway

# ── Runtime: minimal distroless image ────────────────────────────────────────
FROM gcr.io/distroless/cc-debian13:nonroot@sha256:3ee00291cf386ec52a552e6a858d555debd74776eb4bfa53fa3df2cd6677515e
WORKDIR /app
COPY --from=builder /src/target/release/access-gate-gateway /app/access-gate-gateway
# The lockfile makes the image's SBOM list the compiled crates (a stripped binary carries none);
# it is inert at runtime.
COPY --from=builder /src/Cargo.lock /app/Cargo.lock
# The licence texts the crates' licences require us to carry with a binary distribution.
COPY --from=notices /out/THIRD_PARTY_LICENSES.txt /app/THIRD_PARTY_LICENSES.txt
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/app/access-gate-gateway"]
