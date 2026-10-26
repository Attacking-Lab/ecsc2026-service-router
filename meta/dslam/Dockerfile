ARG PROFILE=release

FROM rust:1.98.0-slim-trixie@sha256:17d1ba895198f9934c6314ec5346a0d5115372f3243390c3d731e242f35c2f27 AS dslam-builder

# caching dependency download
RUN cargo new --vcs none --bin /build/dslam && \
    cargo new --vcs none --lib /build/dslam/atm
WORKDIR /build/dslam

COPY Cargo.toml Cargo.lock .
COPY atm/Cargo.toml atm/Cargo.lock atm/

ARG PROFILE
ENV RUSTFLAGS="-C target-cpu=x86-64-v2 -C opt_level=3"
RUN cargo build --profile ${PROFILE} && \
    rm -rf src atm/src target/${PROFILE}/deps/dslam* target/${PROFILE}/deps/atm* target/${PROFILE}/deps/libatm*


COPY src src
COPY atm/src atm/src
RUN cargo build --profile ${PROFILE} && \
    cp target/${PROFILE}/dslam /dslam

FROM debian:trixie-20260824-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS runner

COPY --from=dslam-builder /dslam /bin/dslam

EXPOSE 9000
CMD ["dslam", "0.0.0.0:9000", "/dslam/numbering-plan.yaml"]
