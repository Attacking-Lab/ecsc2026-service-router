#!/usr/bin/env python3

# Replaces the xorshift in f5cs_generate_key with something with slightly different constants.
# Doing this programmatically is more work than doing it once by hand, but this way it should
# survive rebuilds.

from __future__ import annotations

import argparse
import dataclasses
import pathlib
import typing

from elftools.elf.elffile import ELFFile

from xtensa import Image


@dataclasses.dataclass
class TargetInsn:
    op: typing.Literal["slli", "srli", "extui"]
    dst: int
    src: int
    shift: int
    mask: int | None = None


    @classmethod
    def parse(cls, insn: bytes) -> TargetInsn | None:
        if len(insn) != 3:
            return None
        value = int.from_bytes(insn, "little")
        op2 = (value >> 20) & 0xf
        op1 = (value >> 16) & 0xf
        r = (value >> 12) & 0xf
        s = (value >> 8) & 0xf
        t = (value >> 4) & 0xf
        op0 = value & 0xf
        if op0 == 0 and op1 == 1 and (op2 & 0b1110) == 0:
            # SLLI
            imm = t + ((op2 & 1) << 4)
            return cls("slli", r, s, 32 - imm)
        elif op0 == 0 and op1 == 1 and op2 == 4:
            # SRLI
            return cls("srli", r, t, s)
        elif op0 == 0 and (op1 & 0b1110) == 4:
            # EXTUI
            mask = op2 + 1
            imm = s + ((op1 & 1) << 4)
            return cls("extui", r, t, imm, mask)
        return None

        
    def encode(self) -> bytes:
        op0 = 0
        match self.op:
            case "slli":
                op1 = 1
                op2 = (32 - self.shift) >> 4
                r = self.dst
                s = self.src
                t = (32 - self.shift) & 0xf
            case "srli":
                op1 = 1
                op2 = 4
                r = self.dst
                s = self.shift
                t = self.src
            case "extui":
                assert self.mask is not None, "extui without mask"
                op1 = 4 + (self.shift >> 4)
                op2 = self.mask - 1
                r = self.dst
                s = self.shift & 0xf
                t = self.src
        insn = sum((op2 << 20, op1 << 16, r << 12, s << 8, t << 4, op0))
        return insn.to_bytes(3, "little")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=pathlib.Path)
    args = parser.parse_args()

    with args.elf.open("r+b") as handle:
        image = Image(ELFFile(handle))
        f5cs_generate_key = image.symbol("f5cs_generate_key")

        # Now, replace the xorshift constants (13, 17, 5) with (6, 21, 7)
        replacements = []
        for insn in image.disassemble(*f5cs_generate_key):
            ti = TargetInsn.parse(insn.raw)
            if ti is None:
                continue

            if ti.op == "slli" and ti.shift == 13:
                ti.shift = 6
            elif ti.op == "extui" and ti.shift == 17 and ti.mask == 32 - ti.shift:
                ti.shift = 21
                ti.mask = 32 - ti.shift
            elif ti.op == "slli" and ti.shift == 5:
                ti.shift = 7
            else:
                raise LookupError("Unexpected target instruction in f5cs_generate_key")

            replacements.append((
                insn.address,
                ti.encode()
            ))

        if len(replacements) != 3:
            raise LookupError("Failed to identify all three targets in f5cs_generate_key")

        for address, raw in replacements:
            offset = image.offset(address, len(raw))
            handle.seek(offset)
            handle.write(raw)

