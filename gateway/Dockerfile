# syntax=docker/dockerfile:1

################################################################################

ARG RUST_VERSION=1.92
# Runtime base. The default needs a dhi.io (Docker Hardened Images) login; set
# RUNTIME_IMAGE=gcr.io/distroless/cc-debian13:nonroot to build without one.
ARG RUNTIME_IMAGE=dhi.io/static:20250419-glibc

FROM rust:${RUST_VERSION}-slim-trixie AS build

RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \ 
    protobuf-compiler

WORKDIR /app

# Leverage a cache mount to /usr/local/cargo/registry/
# for downloaded dependencies and a cache mount to /app/target/ for 
# compiled dependencies which will speed up subsequent builds.
# Leverage a bind mount to the src directory to avoid having to copy the
# source code into the container. Once built, copy the executable to an
# output directory before the cache mounted /app/target is unmounted.
RUN --mount=type=bind,source=Cargo.toml,target=Cargo.toml \
    --mount=type=bind,source=Cargo.lock,target=Cargo.lock \
    --mount=type=bind,source=gateway/src,target=gateway/src \
    --mount=type=bind,source=gateway/build.rs,target=gateway/build.rs \
    --mount=type=bind,source=gateway/Cargo.toml,target=gateway/Cargo.toml \
    --mount=type=bind,source=crates,target=crates \
    --mount=type=bind,source=mcp,target=mcp \
    --mount=type=bind,source=proto,target=proto \
    --mount=type=cache,target=/app/target/ \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    <<EOF
set -e
cargo build --locked --release -p gateway --bin gateway
cp ./target/release/gateway /bin/gateway
EOF

################################################################################

# distroless with glibc and libgcc for the gnu build, no shell or package manager
FROM ${RUNTIME_IMAGE} AS final

COPY --from=build /bin/gateway /bin/gateway

USER 65532:65532

ENTRYPOINT ["/bin/gateway"]
