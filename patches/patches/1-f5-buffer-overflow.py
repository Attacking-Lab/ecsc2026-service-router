#!/usr/bin/env python3

# Fixes the length check in f5_get

import argparse
import pathlib

from elftools.elf.elffile import ELFFile

from xtensa import Image


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=pathlib.Path)
    args = parser.parse_args()

    with args.elf.open("r+b") as handle:
        image = Image(ELFFile(handle))
        f5_get = image.symbol("f5_get")

        # Replace the `+ 0x3a` with the correct length limit (`+ 0x38`)
        OLD_LENGTH = 0x3a
        NEW_LENGTH = 0x38
        for insn in image.disassemble(*f5_get):
            if insn.mnemonic == "addi" and int(insn.operands.split(", ")[-1], 0) == OLD_LENGTH:
                assert insn.raw[-1] == OLD_LENGTH
                offset = image.offset(insn.address, len(insn.raw))
                handle.seek(offset + len(insn.raw) - 1)
                handle.write(bytes([NEW_LENGTH]))
                break
        else:
            raise LookupError("Failed to find patch target")
