ARG PROFILE=release

FROM rust:1.98.0-slim-trixie@sha256:17d1ba895198f9934c6314ec5346a0d5115372f3243390c3d731e242f35c2f27 AS netdev-builder

# caching dependency download
RUN mkdir /build/ && \
    cd /build && \
    cargo new --bin netdev
WORKDIR /build/netdev

COPY Cargo.toml Cargo.lock .

ARG PROFILE
ENV RUSTFLAGS="-C target-cpu=x86-64-v2 -C opt_level=3"
RUN cargo build --profile ${PROFILE} && \
    rm -rf src target/${PROFILE}/deps/netdev*

COPY src src
RUN cargo build --profile ${PROFILE} && \
    cp target/${PROFILE}/netdev /netdev
