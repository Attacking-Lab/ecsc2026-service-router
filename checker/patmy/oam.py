"""OAM cells (ITU-T I.610)"""

from __future__ import annotations

import dataclasses
import enum

from .atm import ATM_PAYLOAD_SIZE
from .crc import oam_edc

OAM_PAYLOAD_SIZE = ATM_PAYLOAD_SIZE - 1 - 2


class OamError(ValueError):
    pass


class OamType(enum.IntEnum):
    """OAM type codes (ITU-T I.610, table 1)"""

    FAULT_MANAGEMENT = 0x1
    PERFORMANCE_MANAGEMENT = 0x2
    APS_COORDINATION = 0x5
    ACTIVATION_DEACTIVATION = 0x8
    SYSTEM_MANAGEMENT = 0xF


@dataclasses.dataclass
class OamCell:
    """OAM cell"""

    oam_type: int  # An OamType, or whatever the peer sent
    function: int  # Meaning depends on the type
    body: bytes
    reserved: int = 0
    edc: int | None = None

    @staticmethod
    def cell_edc(payload: bytes) -> int:
        """The EDC of a whole cell payload"""
        # We have to add in the reserved bits directly in front of the EDC also
        reserved = ((payload[46] >> bit) & 1 for bit in range(7, 1, -1))
        return oam_edc(payload[:46], additional_bits=reserved)

    @classmethod
    def from_bytes(cls, payload: bytes) -> OamCell:
        if len(payload) != ATM_PAYLOAD_SIZE:
            raise OamError(f"Invalid OAM cell length ({len(payload)}), expected {ATM_PAYLOAD_SIZE} bytes")
        return cls(
            oam_type=payload[0] >> 4,
            function=payload[0] & 0xF,
            body=payload[1 : OAM_PAYLOAD_SIZE + 1],
            reserved=payload[46] >> 2,
            edc=((payload[46] & 0x3) << 8) | payload[47],
        )

    def to_bytes(self) -> bytes:
        if len(self.body) > OAM_PAYLOAD_SIZE:
            raise OamError(f"Invalid OAM body length ({len(self.body)}), expected {OAM_PAYLOAD_SIZE} bytes")
        payload = bytearray(ATM_PAYLOAD_SIZE)
        payload[0] = ((self.oam_type & 0xF) << 4) | (self.function & 0xF)
        payload[1 : 1 + OAM_PAYLOAD_SIZE] = self.body.ljust(OAM_PAYLOAD_SIZE, b"\x6a")
        payload[46] = (self.reserved & 0x3F) << 2
        edc = OamCell.cell_edc(bytes(payload)) if self.edc is None else self.edc
        payload[46] |= (edc >> 8) & 0x3
        payload[47] = edc & 0xFF
        return bytes(payload)

    @property
    def edc_valid(self) -> bool:
        return self.edc is None or self.edc == OamCell.cell_edc(self.to_bytes())
