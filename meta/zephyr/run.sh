#!/bin/bash
set -euxo pipefail

export DISK="${DISK:-/tmp/atmlab-disk.img}"
if [ ! -e "${DISK}" ]; then
    echo "Creating ${DISK}"
    cp "${BASE_DISK}" "${DISK}"
fi


export VFIO_SOCKET="${VFIO_SOCKET:-/run/user/${UID}/atmlab-netdev.sock}"
if [ -f "${VFIO_SOCKET}" ]; then
    echo "Refusing to delete ${VFIO_SOCKET}"
    exit 1
fi

rm -f -- "${VFIO_SOCKET}"
{
    # NB: do `cargo run -- 127.0.0.1:9000` in meta/dslam first
    cd "$(dirname "${BASH_SOURCE[0]}")"/../netdev
    cargo +nightly run -- --force 127.0.0.1:9000 "${VFIO_SOCKET}"
} &

set +x
while [ ! -e "${VFIO_SOCKET}" ]; do sleep 0.1; done
set -x

# Rust vfio_user workarounds:
#  - aux-ram-share=on is required to send file descriptors with the DMA mappings
#  - x-no-posted-writes disables use of the (unsupported) VFIO_USER_NO_REPLY flag
#    which otherwise causes desync on the VFIO channel.
exec "${QEMU_OVERRIDE:-qemu-system-xtensa}" \
  -machine virt,aux-ram-share=on \
  -nographic \
  -cpu dc233c \
  -net none \
  -semihosting \
  -device '{"driver":"vfio-user-pci","socket":{"path":"'"${VFIO_SOCKET:-/run/user/${UID}/atmlab-netdev.sock}"'","type":"unix"},"x-no-posted-writes":true}' \
  -drive if=none,id=nvram,file="${DISK:-/tmp/atmlab-disk.img}",format=raw,cache=writethrough \
  -device virtio-blk-pci,drive=nvram,addr=0x2,disable-legacy=on \
  -icount shift=6,align=off,sleep=on \
  -rtc clock=vm \
  -kernel "${KERNEL}"
