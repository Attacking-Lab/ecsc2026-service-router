#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."

# artifacts already present are not rebuilt, so build.sh and checker_build.sh
# can run back to back without redoing shared work
# always rebuild locally
if [[ ! -f service/zephyr.elf || ! -f service/base-disk.img || ! -v CI ]]; then
    meta/build_zephyr.sh service
fi

if [[ ! -f service/netdev || ! -v CI ]]; then
    docker compose -f meta/docker-compose.build.yml build netdev-build
    docker compose -f meta/docker-compose.build.yml run --rm netdev-build
fi

rm -rf service/patmy
cp -arv checker/patmy service/patmy

if [[ ! -v CI ]]; then
    # Build the dslam container locally
    # It's pushed by CI, but you can't pull it by default
    : "${DSLAM_IMAGE:=ecsc2026-service-router/dslam:latest}"
    docker build -t "${DSLAM_IMAGE}" meta/dslam
fi
