#!/usr/bin/env bash

set -euo pipefail

mkdir -p "$1"
outdir=$(CDPATH= cd -- "$1" && pwd)
cd "$(dirname "$0")"

# The Zephyr build starts from the prebuilt toolchain image in the registry
# (pushed by the build-zephyr-toolchain CI step, or manually via `just -f
# meta/justfile toolchain-image`). Only local builds may fall back to building
# the `toolchain` stage from meta/zephyr/Dockerfile -- in CI an unreachable
# registry must fail the build, not silently rebuild the toolchain.
: "${TOOLCHAIN_IMAGE:=ecsc2026-service-router/zephyr-toolchain:latest}"
if [[ ! -v CI ]] &&
    ! docker image inspect "${TOOLCHAIN_IMAGE}" >/dev/null 2>&1 &&
    ! docker manifest inspect "${TOOLCHAIN_IMAGE}" >/dev/null 2>&1; then
    echo "==> ${TOOLCHAIN_IMAGE} is not available, building the toolchain stage locally"
    TOOLCHAIN_IMAGE=toolchain
fi
export TOOLCHAIN_IMAGE

# copies zephyr.elf + base-disk.img into $outdir
docker compose -f docker-compose.build.yml build zephyr-build
SERVICE_DIRECTORY="$outdir" docker compose -f docker-compose.build.yml run --rm zephyr-build
