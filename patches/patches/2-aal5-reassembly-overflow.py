#!/usr/bin/env python3

# Fixes the upper bound on the last cell's payload in aal5_rx

import argparse
import pathlib

from elftools.elf.elffile import ELFFile

from xtensa import Image


ATM_SDU_SIZE = 48
TRAILER_SIZE = 8

BIAS = TRAILER_SIZE - 1
OLD_LIMIT = ATM_SDU_SIZE
NEW_LIMIT = ATM_SDU_SIZE - TRAILER_SIZE


def immediate(insn) -> int:
    return int(insn.operands.split(", ")[-1], 0)


def encode_movi(insn, value: int) -> bytes:
    """Re-encodes a `movi`/`movi.n` with a new, small immediate"""
    raw = bytearray(insn.raw)
    if insn.mnemonic == "movi":
        # RRI8: imm12 is s:imm8, and the limit fits in imm8 either way
        assert raw[1] & 0xf == 0 and 0 <= value < 0x100, "movi immediate is not 8-bit"
        raw[2] = value
    else:
        # RI7: imm7 is split across the high nibbles of both bytes
        assert 0 <= value < 0x60, "movi.n immediate is out of range"
        raw[0] = (raw[0] & 0xf) | (value & 0xf0)
        raw[1] = (raw[1] & 0xf) | ((value & 0xf) << 4)
    return bytes(raw)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=pathlib.Path)
    args = parser.parse_args()

    with args.elf.open("r+b") as handle:
        image = Image(ELFFile(handle))
        aal5_rx = image.symbol("aal5_rx")

        # Find the comparison
        insns = list(image.disassemble(*aal5_rx))
        targets = []
        for index, insn in enumerate(insns[2:], start=2):
            if insn.mnemonic != "bltu":
                continue
            limit_register, value_register, _ = insn.operands.split(", ")
            operands = {prev.operands.split(", ")[0]: prev for prev in insns[index - 2:index]}
            movi, addi = operands.get(limit_register), operands.get(value_register)
            if movi is None or addi is None:
                continue
            if not movi.mnemonic.startswith("movi") or immediate(movi) != OLD_LIMIT + BIAS:
                continue
            if not addi.mnemonic.startswith("addi") or immediate(addi) != BIAS:
                continue
            targets.append(movi)

        if len(targets) != 1:
            raise LookupError(f"Found {len(targets)} candidates for the length check in aal5_rx")

        movi = targets[0]
        raw = encode_movi(movi, NEW_LIMIT + BIAS)
        handle.seek(image.offset(movi.address, len(raw)))
        handle.write(raw)
