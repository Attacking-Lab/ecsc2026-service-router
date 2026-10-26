#!/usr/bin/env python3
"""Clear SHF_WRITE on a section, in place.

Zephyr links baremetal targets with `-Wl,-N` (ld `--omagic`), which drops
SEC_READONLY from .text, so the section ends up marked writable. objcopy
--set-section-flags would fix that, but it rewrites the whole file: it drops
the zero-FileSiz .bss PT_LOAD and shuffles section offsets. This only pokes the
sh_flags word in the section header table, so everything else is byte-identical.
"""

import argparse
import struct
import sys

SHF_WRITE = 0x1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("elf")
    parser.add_argument("section")
    args = parser.parse_args()

    with open(args.elf, "r+b") as f:
        data = bytearray(f.read())

        if data[:4] != b"\x7fELF":
            sys.exit(f"{args.elf}: not an ELF file")
        is64 = data[4] == 2
        endian = ">" if data[5] == 2 else "<"

        # e_shoff, e_shentsize, e_shnum, e_shstrndx
        if is64:
            shoff, = struct.unpack_from(endian + "Q", data, 0x28)
            shentsize, shnum, shstrndx = struct.unpack_from(endian + "3H", data, 0x3A)
            flags_off, offset_off, word = 8, 24, endian + "Q"
        else:
            shoff, = struct.unpack_from(endian + "I", data, 0x20)
            shentsize, shnum, shstrndx = struct.unpack_from(endian + "3H", data, 0x2E)
            flags_off, offset_off, word = 8, 16, endian + "I"

        def shdr(i):
            return shoff + i * shentsize

        # Section names live in the section at e_shstrndx.
        strtab, = struct.unpack_from(word, data, shdr(shstrndx) + offset_off)

        want = args.section.encode()
        for i in range(shnum):
            name_off, = struct.unpack_from(endian + "I", data, shdr(i))
            name_at = strtab + name_off
            if data[name_at:data.index(b"\0", name_at)] != want:
                continue

            at = shdr(i) + flags_off
            flags, = struct.unpack_from(word, data, at)
            if not flags & SHF_WRITE:
                print(f"{args.elf}: {args.section} is already read-only")
                return
            struct.pack_into(word, data, at, flags & ~SHF_WRITE)
            f.seek(0)
            f.write(data)
            print(f"{args.elf}: cleared SHF_WRITE on {args.section}")
            return

    sys.exit(f"{args.elf}: no section named {args.section}")


if __name__ == "__main__":
    main()
