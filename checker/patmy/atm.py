"""UNI ATM cells and virtual circuits."""

from __future__ import annotations

import dataclasses
import enum
import typing

from .crc import atm_hec

ATM_CELL_SIZE = 53
ATM_HEADER_SIZE = 5
ATM_PAYLOAD_SIZE = 48
assert ATM_CELL_SIZE == ATM_HEADER_SIZE + ATM_PAYLOAD_SIZE

# Smaller VCIs are reserved
MIN_ALLOCATED_VCI = 32


class CellError(ValueError):
    pass


class Pti(enum.IntEnum):
    """ATM payload type identifier, per ITU-T I.361 (§ 2.2.4)"""

    USER_DATA_0 = 0b000
    USER_DATA_1 = 0b001
    USER_DATA_CONGESTED_0 = 0b010
    USER_DATA_CONGESTED_1 = 0b011
    SEGMENT_OAM_F5 = 0b100
    END_TO_END_OAM_F5 = 0b101
    RESOURCE_MANAGEMENT = 0b110
    RESERVED = 0b111

    @property
    def is_user_data(self) -> bool:
        return self <= Pti.USER_DATA_CONGESTED_1

    @property
    def is_oam(self) -> bool:
        return self in (Pti.SEGMENT_OAM_F5, Pti.END_TO_END_OAM_F5)

    @property
    def auu(self) -> int:
        if not self.is_user_data:
            raise CellError("Requested AUU bit on non-user-data cell")
        return self & 1

    @staticmethod
    def user_data(auu: bool, congestion: bool = False) -> Pti:
        return Pti((0b010 if congestion else 0) | (1 if auu else 0))


@dataclasses.dataclass(frozen=True, order=True)
class VirtualCircuit:
    """ATM virtual circuit (on UNI)"""

    vpi: int
    vci: int

    SIGNALLING: typing.ClassVar[VirtualCircuit]
    ILMI: typing.ClassVar[VirtualCircuit]

    def __post_init__(self) -> None:
        if not 0 <= self.vpi <= 0xFF or not 0 <= self.vci <= 0xFFFF:
            raise CellError(f"Circuit {self.vpi}.{self.vci} is out of range")

    @classmethod
    def parse(cls, text: str) -> VirtualCircuit:
        for separator in ".:/":
            if separator in text:
                vpi, _, vci = text.partition(separator)
                return cls(vpi=int(vpi), vci=int(vci))
        raise CellError(f"No separator found in {text!r}")

    @property
    def is_reserved(self) -> bool:
        return self.vci < MIN_ALLOCATED_VCI or self in (VirtualCircuit.SIGNALLING, VirtualCircuit.ILMI)

    def __str__(self) -> str:
        return f"{self.vpi}.{self.vci}"


VirtualCircuit.SIGNALLING = VirtualCircuit(0, 5)
VirtualCircuit.ILMI = VirtualCircuit(0, 18)


@dataclasses.dataclass
class Cell:
    """An ATM cell, per ITU-T I.361"""

    payload: bytes
    circuit: VirtualCircuit
    pti: Pti = Pti.USER_DATA_0
    gfc: int = 0
    clp: int = 0
    hec: int | None = None

    @classmethod
    def from_bytes(cls, data: bytes) -> Cell:
        if len(data) != ATM_CELL_SIZE:
            raise CellError(f"Invalid cell length ({len(data)}), expected {ATM_CELL_SIZE} bytes")
        return cls(
            payload=data[ATM_HEADER_SIZE:],
            circuit=VirtualCircuit(
                ((data[0] & 0x0F) << 4) | (data[1] >> 4),
                ((data[1] & 0x0F) << 12) | (data[2] << 4) | (data[3] >> 4),
            ),
            pti=Pti((data[3] >> 1) & 0b111),
            gfc=data[0] >> 4,
            clp=data[3] & 1,
            hec=data[4],
        )

    def to_bytes(self) -> bytes:
        if len(self.payload) != ATM_PAYLOAD_SIZE:
            raise CellError(f"Invalid payload length ({len(self.payload)}), expected {ATM_PAYLOAD_SIZE} bytes")
        vpi, vci = self.circuit.vpi, self.circuit.vci
        header = bytearray(ATM_HEADER_SIZE)
        header[0] = (self.gfc << 4) | (vpi >> 4)
        header[1] = ((vpi & 0x0F) << 4) | (vci >> 12)
        header[2] = (vci >> 4) & 0xFF
        header[3] = ((vci & 0x0F) << 4) | (self.pti << 1) | self.clp
        header[4] = atm_hec(bytes(header[:4])) if self.hec is None else self.hec
        return bytes(header) + self.payload

    @property
    def hec_valid(self) -> bool:
        return self.hec is None or self.hec == atm_hec(self.to_bytes()[:4])
