#!/bin/bash
set -euo pipefail

BASE_DISK="${BASE_DISK:-$(dirname "${BASH_SOURCE[0]}")/base-disk.img}"
DISK_SIZE="${DISK_SIZE:-512}"

# Create the empty disk image
#  -S 512 must match CONFIG_FS_FATFS_{MIN,MAX}_SS
rm -f -- "${BASE_DISK}"
truncate -s "${DISK_SIZE}M" "${BASE_DISK}"
mkfs.fat -F 16 -S 512 -s 16 -n ATMLAB "${BASE_DISK}"

# Create a template file for the OAM storage
template="$(mktemp)"
trap 'rm -f "${template}"' EXIT
truncate -s "$((SLOTS_PER_GENERATION * RECORD_SIZE))" "${template}"

# Copy the files in
mmd -i "${BASE_DISK}" ::/oam
mmd -i "${BASE_DISK}" ::/user
for ((i = 0; i < LIVE_GENERATIONS; i++)); do
    mcopy -i "${BASE_DISK}" "${template}" "::/oam/$(printf '%04X' "${i}")"
done
