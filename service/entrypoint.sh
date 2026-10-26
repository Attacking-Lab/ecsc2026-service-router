#!/bin/sh
set -euxo pipefail

export DISK="${DISK:-/tmp/atmlab-disk.img}"
export VFIO_SOCKET="${VFIO_SOCKET:-/tmp/atmlab-netdev.sock}"
export KERNEL="${KERNEL:-$(dirname "$(readlink -f "$0")")/zephyr.elf}"

if [ ! -e "${DISK}" ]; then
    echo "Creating ${DISK}"
    cp "/router/base-disk.img" "${DISK}"
fi

rm -f -- "${VFIO_SOCKET}"
/bin/netdev --force "${DSLAM_ADDRESS}" "${VFIO_SOCKET}" &

set +x
while [ ! -e "${VFIO_SOCKET}" ]; do sleep 0.1; done
set -x

exec "${QEMU_OVERRIDE:-qemu-system-xtensa}" \
  -machine virt,aux-ram-share=on \
  -nographic \
  -cpu dc233c \
  -net none \
  -semihosting \
  -device '{"driver":"vfio-user-pci","socket":{"path":"'"${VFIO_SOCKET}"'","type":"unix"},"x-no-posted-writes":true}' \
  -drive if=none,id=nvram,file="${DISK}",format=raw,cache=writethrough \
  -device virtio-blk-pci,drive=nvram,addr=0x2,disable-legacy=on \
  -icount shift=6,align=off,sleep=on \
  -rtc clock=vm \
  -kernel "${KERNEL}"
