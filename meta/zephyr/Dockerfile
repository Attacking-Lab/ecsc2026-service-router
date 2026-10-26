# syntax=docker/dockerfile:1
#
# Two-stage Zephyr build for the xtensa-dc233c target.
#
# Stage 1 (`toolchain`) is service-independent — Ubuntu + west + ONLY the
# xtensa-dc233c Zephyr SDK.
#
# Stage 2 (`zephyr-build`) is the per-build service compile.

ARG UBUNTU=ubuntu:26.04
ARG ZEPHYR_SDK_VERSION=0.17.4
ARG ZEPHYR_TOOLCHAIN=xtensa-dc233c_zephyr-elf
ARG SDK_BASE_URL=https://github.com/zephyrproject-rtos/sdk-ng/releases/download
# Base for stage 2. Default = the local `toolchain` stage; override in CI with
# the pushed registry image to skip rebuilding it.
ARG TOOLCHAIN_IMAGE=toolchain

FROM ${UBUNTU} AS toolchain
ARG ZEPHYR_SDK_VERSION
ARG ZEPHYR_TOOLCHAIN
ARG SDK_BASE_URL
ENV DEBIAN_FRONTEND=noninteractive

# Zephyr host build deps (getting-started set, trimmed to what an xtensa/QEMU
# target needs: no native_sim, so no libsdl2/multilib) + dosfstools/mtools for
# mkdisk.sh. Stage 2 fetches Zephyr over HTTPS from GitHub (no ssh needed).
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && apt-get install --no-install-recommends --yes \
        git cmake ninja-build gperf ccache dfu-util device-tree-compiler wget \
        python3-dev python3-venv python3-pip python3-setuptools python3-wheel \
        xz-utils file make gcc libmagic1 \
        dosfstools mtools ca-certificates

# west in a venv (Ubuntu is PEP 668 / externally-managed).
ENV VIRTUAL_ENV=/opt/venv PATH=/opt/venv/bin:$PATH
RUN python3 -m venv "${VIRTUAL_ENV}" && pip install --no-cache-dir west

# Zephyr SDK: minimal host bundle + only the xtensa toolchain, and register the
# SDK's CMake package (-c) so find_package(Zephyr) locates the toolchain.
ENV ZEPHYR_TOOLCHAIN_VARIANT=zephyr \
    ZEPHYR_SDK_INSTALL_DIR=/opt/toolchains/zephyr-sdk-${ZEPHYR_SDK_VERSION}
RUN mkdir -p /opt/toolchains && cd /opt/toolchains && \
    wget -q "${SDK_BASE_URL}/v${ZEPHYR_SDK_VERSION}/zephyr-sdk-${ZEPHYR_SDK_VERSION}_linux-x86_64_minimal.tar.xz" && \
    tar xf "zephyr-sdk-${ZEPHYR_SDK_VERSION}_linux-x86_64_minimal.tar.xz" && \
    rm "zephyr-sdk-${ZEPHYR_SDK_VERSION}_linux-x86_64_minimal.tar.xz" && \
    cd "zephyr-sdk-${ZEPHYR_SDK_VERSION}" && \
    ./setup.sh -t "${ZEPHYR_TOOLCHAIN}" -c

FROM ${TOOLCHAIN_IMAGE} AS zephyr-build
WORKDIR /build
COPY app app
COPY mkdisk.sh .

# `west packages pip --install` stays here (not in the toolchain) because it
# needs the west workspace that `west update` checks out. It fetches Zephyr's
# python requirements from PyPI on each build (the app copy above invalidates
# this layer every time, hence the pip cache); point pip at a mirror via
# PIP_INDEX_URL if CI egress to pypi.org is restricted.
RUN \
    --mount=type=cache,target=/build/zephyr \
    --mount=type=cache,target=/build/modules \
    --mount=type=cache,target=/build/build,sharing=locked \
    --mount=type=cache,target=/root/.cache/pip \
    west init --local app && \
    west update --narrow --fetch-opt=--depth=1 && \
    west packages pip --install && \
    west build -b qemu_xtensa/dc233c/mmu app && \
    west build -t base-disk && \
    cp build/zephyr/zephyr.elf build/base-disk.img /
