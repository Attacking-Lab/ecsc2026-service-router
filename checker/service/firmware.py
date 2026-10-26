"""Tooling for the exploit path to parse `zephyr.elf`."""

from __future__ import annotations

import functools
import pathlib

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

DEFAULT_PATH = pathlib.Path(__file__).resolve().parent.parent / "zephyr.elf"


class FirmwareError(LookupError):
    """Failed to load the firmware image, or to find what we were looking for."""


class Image:
    """The firmware's symbols, and the bytes behind an address."""

    def __init__(self, elf: ELFFile):
        self.elf = elf
        self.mapped: list[tuple[int, bytes]] = [
            (section["sh_addr"], section.data())
            for section in elf.iter_sections()
            if section["sh_type"] == "SHT_PROGBITS" and section["sh_addr"]
        ]

        # Statics of the same name in different translation units collide, hence the set
        self.functions: dict[str, set[int]] = {}
        self.objects: dict[str, tuple[int, int]] = {}
        for section in elf.iter_sections():
            if not isinstance(section, SymbolTableSection):
                continue
            for symbol in section.iter_symbols():
                if not symbol["st_value"]:
                    continue
                if symbol["st_info"]["type"] == "STT_FUNC":
                    self.functions.setdefault(symbol.name, set()).add(symbol["st_value"])
                elif symbol["st_info"]["type"] == "STT_OBJECT":
                    self.objects.setdefault(symbol.name, (symbol["st_value"], symbol["st_size"]))

        if not self.functions:
            raise FirmwareError("No function symbols in the firmware image")

    @classmethod
    def load(cls, path: pathlib.Path | str = DEFAULT_PATH) -> Image:
        """Loads a firmware image."""
        try:
            return cls(ELFFile(pathlib.Path(path).open("rb")))
        except OSError as error:
            raise FirmwareError(f"Cannot read the firmware image at {path}") from error

    def function(self, name: str, within: str | None = ".text") -> int:
        """Finds the (lowest) address of `name` in `within`, or in the whole image."""
        addresses = self.functions.get(name)
        if not addresses:
            raise FirmwareError(f"No such function: {name!r}")
        if within is None:
            return min(addresses)
        base, data = self.section(within)
        inside = [address for address in addresses if base <= address < base + len(data)]
        if not inside:
            raise FirmwareError(f"No function {name!r} in {within} (found {len(addresses)} elsewhere)")
        return min(inside)

    def symbol(self, name: str) -> tuple[int, int]:
        """Looks up the address and size of the `name` object symbol."""
        if name not in self.objects:
            raise FirmwareError(f"Failed to find object: {name!r}")
        return self.objects[name]

    def section(self, name: str) -> tuple[int, bytes]:
        section = self.elf.get_section_by_name(name)
        if section is None:
            raise FirmwareError(f"No {name} section in the firmware")
        return section["sh_addr"], section.data()

    def read(self, address: int, length: int) -> bytes:
        for start, data in self.mapped:
            if start <= address and address + length <= start + len(data):
                return data[address - start : address - start + length]
        raise FirmwareError(f"Nothing mapped at {address:#010x}+{length}")


@functools.cache
def image(path: pathlib.Path | str = DEFAULT_PATH) -> Image:
    return Image.load(path)
