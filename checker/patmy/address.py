"""E.164 ATM end system addresses (AESA), per ITU-T E.191."""

from __future__ import annotations

import dataclasses

ATM_ADDRESS_SIZE = 20  # Full AESA length
E164_ADDRESS_SIZE = 8  # BCD IDI length
E164_MAX_LENGTH = 15  # Digit length
E164_AFI = 45


class AddressError(ValueError):
    pass


@dataclasses.dataclass(frozen=True)
class AtmAddress:
    """An E.191 AESA holding an E.164 IDI and a zeroed-out HO-DSP/ESI/..."""

    idi: bytes
    afi: int = E164_AFI
    dsp: bytes = bytes(11)

    @classmethod
    def from_number(cls, number: str) -> AtmAddress:
        # `+49 123 456 7890` encodes as `00 04 91 23 45 67 89 0F` in the IDI part.
        # For consistency, we enforce international numbers without trunk prefixes.
        number = number.strip()
        if not number.startswith("+"):
            raise AddressError("Number must be an international number")

        digits = []
        for character in number[1:]:
            if character.isdigit():
                digits.append(int(character))
            elif character not in " \t()/-":
                raise AddressError(f"Invalid character {character!r} in {number!r}")
        if len(digits) > E164_MAX_LENGTH:
            raise AddressError(f"Number is longer than {E164_MAX_LENGTH} digits")

        nibbles = [0] * (E164_MAX_LENGTH - len(digits)) + digits + [0xF]
        idi = bytes(high << 4 | low for high, low in zip(nibbles[::2], nibbles[1::2], strict=True))
        return cls(idi=idi)

    @classmethod
    def from_bytes(cls, data: bytes) -> AtmAddress:
        if len(data) != ATM_ADDRESS_SIZE:
            raise AddressError(f"Invalid AESA length ({len(data)}), expected {ATM_ADDRESS_SIZE} bytes.")
        return cls(idi=data[1:9], afi=data[0], dsp=data[9:])

    def to_bytes(self) -> bytes:
        if len(self.idi) != E164_ADDRESS_SIZE or len(self.dsp) != 11:
            raise AddressError("Malformed AESA")
        return bytes([self.afi]) + self.idi + self.dsp

    @property
    def number(self) -> str:
        if self.afi != E164_AFI:
            raise AddressError("Cannot fetch phone number from a non-E.164 AESA")

        digits = ""
        for nibble in (half for byte in self.idi for half in (byte >> 4, byte & 0xF)):
            if nibble == 0xF:
                return "+" + digits
            if nibble > 9:
                raise AddressError(f"Invalid digit {nibble:#x} in IDI {self.idi.hex()}")
            if nibble or digits:
                digits += str(nibble)
        raise AddressError(f"Unterminated IDI: {self.idi.hex()}")

    def is_nonstandard(self) -> bool:
        # The network only ever uses raw E.164 AESAs without DSPs
        return self.afi != E164_AFI or any(self.dsp)

    def __str__(self) -> str:
        try:
            rendered = self.number
        except AddressError:
            rendered = f"<{self.idi.hex()}>"
        if self.is_nonstandard():
            return f"{rendered} (AFI {self.afi}, DSP {self.dsp.hex()})"
        return rendered
