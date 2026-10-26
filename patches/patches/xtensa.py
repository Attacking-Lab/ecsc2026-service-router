"""Xtensa firmware utilities."""

import bisect
from collections.abc import Iterator
from typing import NamedTuple

import capstone
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

MD = capstone.Cs(capstone.CS_ARCH_XTENSA, capstone.CS_MODE_LITTLE_ENDIAN)


class Insn(NamedTuple):
    address: int
    mnemonic: str
    operands: str
    raw: bytes
    target: int | None = None  # l32r/callx8 targets


def branch(insn: Insn) -> int:
    """Computes the target of a branch"""
    # Branch targets are relative (`. +0x1c`) in capstone,
    # l32r pool slots are absolute (`. 0x100618`).
    return insn.address + int(insn.operands.rpartition(". ")[2], 16)


class Image:
    """.text plus the function boundaries recovered from it."""

    def __init__(self, elf: ELFFile) -> None:
        self.elf = elf
        self.sections: list[tuple[int, bytes]] = [
            (section["sh_addr"], section.data())
            for section in elf.iter_sections()
            if section["sh_type"] == "SHT_PROGBITS" and section["sh_addr"]
        ]

        self.base, self.text = self.section(".text")
        self.limit = self.base + len(self.text)
        # Every windowed-ABI function opens with `entry a1, N`
        self.starts: list[int] = [
            self.base + offset
            for offset in range(len(self.text) - 1)
            if self.text[offset] == 0x36 and self.text[offset + 1] & 0xF == 1
        ]

        # Static functions of the same name in different translation units collide
        self.symbols: dict[str, set[tuple[int, int]]] = {}
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if symbol["st_info"]["type"] == "STT_FUNC" and symbol["st_value"]:
                    entry = (symbol["st_value"], symbol["st_size"])
                    self.symbols.setdefault(symbol.name, set()).add(entry)

    def section(self, name: str) -> tuple[int, bytes]:
        """Resolves a section's address and data by name"""
        section = self.elf.get_section_by_name(name)
        if section is None:
            raise LookupError(name)
        return section["sh_addr"], section.data()

    def read(self, address: int, length: int) -> bytes | None:
        """Reads bytes from the image"""
        for start, data in self.sections:
            if start <= address and address + length <= start + len(data):
                return data[address - start:address - start + length]
        return None

    def word(self, address: int) -> int | None:
        data = self.read(address, 4)
        return int.from_bytes(data, "little") if data else None

    def offset(self, address: int, length: int = 1) -> int:
        """File offset of `address`, for patching the ELF in place"""
        offsets = list(self.elf.address_offsets(address, length))
        if len(offsets) != 1:
            raise LookupError(f"{address:#x} maps to {len(offsets)} file offsets")
        return offsets[0]

    def string(self, prefix: bytes, name: str = ".rodata") -> int:
        base, data = self.section(name)
        return base + data.index(prefix)

    def symbol(self, name: str) -> tuple[int, int]:
        """Start and end of the function called `name`, or of the only one whose name contains it"""
        matches = {name: self.symbols[name]} if name in self.symbols else {
            symbol: entries for symbol, entries in self.symbols.items() if name in symbol
        }
        entries = {entry for entries in matches.values() for entry in entries}
        if not entries:
            raise LookupError(f"No function symbol matching {name!r}")
        if len(entries) != 1:
            raise LookupError(f"{name!r} is ambiguous: {', '.join(sorted(matches))}")

        start, size = entries.pop()
        return start, start + size if size else self.function(start)[1]

    def function(self, address: int) -> tuple[int, int]:
        """Start and end (including literal pool and padding) of the function around `address`."""
        index = bisect.bisect_right(self.starts, address) - 1
        following = self.starts[index + 1:index + 2]
        return self.starts[index], following[0] if following else self.limit

    def functions(self) -> Iterator[tuple[int, int]]:
        return zip(self.starts, self.starts[1:] + [self.limit])

    def disassemble(self, start: int | None = None, end: int | None = None) -> Iterator[Insn]:
        """Disassembles code from `start` (default .text) to `end` (default: end of the function containing `start`)"""
        if start is None:
            start, end = self.base, self.limit
        elif end is None:
            _, end = self.function(start)

        # capstone 6.0.0a10 does not know beqz.n/bnez.n, and decodes the
        # ESP32-S3 `ee.*` opcodes that a dc233c does not have.
        pc = start
        while pc < end - 1:
            window = self.text[pc - self.base:pc - self.base + 8]
            insn = next(MD.disasm(window, pc, count=1), None)
            if insn is not None and not insn.mnemonic.startswith("ee."):
                yield Insn(pc, insn.mnemonic, insn.op_str, bytes(insn.bytes))
                pc += insn.size
            elif window[0] & 0xF == 0xC and window[0] >> 4 >= 8:
                r, s = window[0] >> 4, window[1] & 0xF
                offset = 4 + (((r & 3) << 4) | window[1] >> 4)
                mnemonic = "beqz.n" if r & 0xC == 8 else "bnez.n"
                yield Insn(pc, mnemonic, f"a{s}, . +{offset:#x}", window[:2])
                pc += 2
            else:
                pc += 1

    def scan(self, start: int | None = None, end: int | None = None) -> Iterator[Insn]:
        """`disassemble()`, but resolving l32r and callx8 targets."""
        pool: dict[str, int | None] = {}
        for insn in self.disassemble(start, end):
            if insn.mnemonic == "l32r":
                register, slot = insn.operands.split(", ")
                pool[register] = self.word(int(slot.removeprefix(". "), 16))
                yield insn._replace(target=pool[register])
            elif insn.mnemonic.startswith("callx") and insn.operands in pool:
                yield insn._replace(target=pool[insn.operands])
            else:
                yield insn

    def calls(self, start: int | None = None, end: int | None = None) -> Iterator[int]:
        for insn in self.scan(start, end):
            if insn.mnemonic.startswith("callx") and insn.target is not None:
                yield insn.target
