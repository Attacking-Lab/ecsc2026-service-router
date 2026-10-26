#!/usr/bin/env bash

set -euo pipefail
cd "$(dirname "$0")/.."

# The checker wants the zephyr.elf around. Prefer the one the service build
# already produced; with only checker/ and meta/ checked out (the staging
# checker VM), build it from scratch into a scratch dir instead.
# always copy a the binary locally
if [[ ! -f checker/zephyr.elf || ! -v CI ]]; then
    if [[ -f service/zephyr.elf ]]; then
        cp -av service/zephyr.elf checker/zephyr.elf
    else
        tmpdir=$(mktemp -d)
        meta/build_zephyr.sh "$tmpdir"
        cp -av "$tmpdir/zephyr.elf" checker/zephyr.elf
        rm -rf "$tmpdir"
    fi
fi
