#!/usr/bin/env python3

import argparse
import pathlib

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

from xtensa import Image


# Current rejected bytes from key_char_ok
NEEDLE = b'*+,:;<=>[]|"?\x00'

# Refuse more things that will trigger the bug
REJECT = (
    bytes(range(0x01, 0x21))               # These end the name early
    + b"./\\\x7f"                          # Dot and separators
    + bytes(range(ord("A"), ord("Z") + 1)) # Folded names
    + NEEDLE                               # The original reject list
)

# Reduce the length of the key too to match the error behavior from before
OLD_KEY_MAX = 12
NEW_KEY_MAX = 8


def symbol_value(elf: ELFFile, name: str) -> int:
    """Resolves a symbol Image does not index, which only keeps functions"""
    for section in elf.iter_sections():
        if not isinstance(section, SymbolTableSection):
            continue
        for symbol in section.iter_symbols():
            if symbol.name == name:
                return symbol["st_value"]
    raise LookupError(f"No symbol named {name!r}")


def rodata_cave(image: Image, size: int) -> int:
    """Finds free space in the padding that pads the read-only region to a page"""
    end = symbol_value(image.elf, "__rodata_region_end")
    for section in image.elf.iter_sections():
        if section["sh_type"] != "SHT_PROGBITS" or not section["sh_addr"]:
            continue
        base, data = section["sh_addr"], section.data()
        if base + len(data) != end:
            continue
        padding = len(data) - len(data.rstrip(b"\0"))
        start = -(-(base + len(data) - padding) // 4) * 4
        if end - start >= size:
            return start
    raise LookupError(f"No room for {size} bytes at the end of the read-only region")


def immediate(insn) -> int:
    return int(insn.operands.split(", ")[-1], 0)


def encode_movi(insn, value: int) -> bytes:
    """Re-encodes a `movi`/`movi.n` with a new, small immediate"""
    raw = bytearray(insn.raw)
    if insn.mnemonic == "movi":
        # RRI8: imm12 is s:imm8 (but the value here fits anyways)
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
        user_data_path = image.symbol("user_data_path")

        # Handle non-inlined key_char_ok() also
        filters = [user_data_path]
        try:
            filters.insert(0, image.symbol("key_char_ok"))
        except LookupError:
            pass

        # Simply redirect the pointer to the list of banned bytes
        references = [
            insn
            for start, end in filters
            for insn in image.scan(start, end)
            if insn.mnemonic == "l32r" and insn.target is not None
            and image.read(insn.target, len(NEEDLE)) == NEEDLE
        ]
        if len(references) != 1:
            raise LookupError(f"Found {len(references)} rejection sets in the key filter")
        slot = int(references[0].operands.rpartition(". ")[2], 16)

        limits = [
            insn for insn in image.disassemble(*user_data_path)
            if insn.mnemonic.startswith("movi") and immediate(insn) == OLD_KEY_MAX - 1
        ]
        if len(limits) != 1:
            raise LookupError(f"Found {len(limits)} key length limits in user_data_path")

        cave = rodata_cave(image, len(REJECT))

        handle.seek(image.offset(cave, len(REJECT)))
        handle.write(REJECT)

        handle.seek(image.offset(slot, 4))
        handle.write(cave.to_bytes(4, "little"))

        raw = encode_movi(limits[0], NEW_KEY_MAX - 1)
        handle.seek(image.offset(limits[0].address, len(raw)))
        handle.write(raw)
