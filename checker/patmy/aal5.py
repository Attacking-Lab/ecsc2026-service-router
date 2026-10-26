"""ATM Adaption Layer Type 5 (AAL5, ITU-T I.363.5)."""

from __future__ import annotations

import dataclasses
import enum
import itertools
import struct
import typing

from .atm import ATM_PAYLOAD_SIZE, Cell, Pti, VirtualCircuit
from .crc import aal5_crc

AAL5_MAX_SDU_SIZE = 0xFFFF


class Aal5Error(ValueError):
    pass


@dataclasses.dataclass
class Trailer:
    """CPCS-PDU trailer, per ITU-T I.363.5 (§ 9.2.1.2)"""

    uu: int = 0
    cpi: int = 0
    length: int = 0
    crc: int = 0

    FORMAT: typing.ClassVar[str] = "!BBHI"
    SIZE: typing.ClassVar[int] = 8

    @classmethod
    def from_bytes(cls, data: bytes) -> Trailer:
        if len(data) != cls.SIZE:
            raise Aal5Error(f"Invalid trailer length ({len(data)}), expected {cls.SIZE} bytes")
        return cls(*struct.unpack(cls.FORMAT, data))

    def to_bytes(self) -> bytes:
        return struct.pack(self.FORMAT, self.uu, self.cpi, self.length, self.crc)

    @property
    def is_abort(self) -> bool:
        """A zero length field aborts the PDU (§ 9.2.1.2 (d))"""
        return self.length == 0


def padded_length(sdu_length: int) -> int:
    """Padded length of a given payload"""
    cells = (sdu_length + Trailer.SIZE + ATM_PAYLOAD_SIZE - 1) // ATM_PAYLOAD_SIZE
    return cells * ATM_PAYLOAD_SIZE - Trailer.SIZE


AAL5_MAX_PDU_SIZE = padded_length(AAL5_MAX_SDU_SIZE) + Trailer.SIZE


class PduError(enum.Enum):
    """Possible errors in a CPCS-PDU"""

    TRUNCATED = "the PDU was truncated"
    TOO_MUCH_PADDING = "too much padding"
    BAD_CHECKSUM = "trailer checksum mismatch"
    OVERSIZED = "the PDU exceeds the maximum size"

    def __str__(self) -> str:
        return self.value


@dataclasses.dataclass
class Pdu:
    """An AAL5 CPCS-PDU"""

    body: bytes  # Payload and padding
    trailer: Trailer
    error: PduError | None = None

    @classmethod
    def from_sdu(
        cls,
        data: bytes,
        *,
        padding: bytes | None = None,
        uu: int = 0,
        cpi: int = 0,
        length: int | None = None,
        crc: int | None = None,
    ) -> Pdu:
        """Pack an SDU into an AAL5 CPCS-PDU"""
        if len(data) > AAL5_MAX_SDU_SIZE:
            raise Aal5Error(f"Invalid SDU length ({len(data)}), at most {AAL5_MAX_SDU_SIZE} bytes")

        pad_length = padded_length(len(data)) - len(data)
        if padding is None:
            padding = bytes(pad_length)
        elif len(padding) != pad_length:
            raise Aal5Error(f"Invalid padding length ({len(padding)}), expected {pad_length} bytes")

        # CRC covers payload, padding, and trailer except for the CRC field (§ 9.2.1.2 (f)).
        body = data + padding
        trailer = Trailer(uu=uu, cpi=cpi, length=len(data) if length is None else length)
        trailer.crc = aal5_crc(body + trailer.to_bytes()[:-4]) if crc is None else crc
        return cls(body, trailer)

    @classmethod
    def from_bytes(cls, raw: bytes) -> Pdu:
        if len(raw) < Trailer.SIZE:
            raise Aal5Error(f"Invalid PDU length ({len(raw)}), no room for a trailer")
        body, trailer = raw[: -Trailer.SIZE], Trailer.from_bytes(raw[-Trailer.SIZE :])
        if len(raw) > AAL5_MAX_PDU_SIZE:
            error = PduError.OVERSIZED
        elif trailer.length > len(body):
            error = PduError.TRUNCATED
        elif padded_length(trailer.length) != len(body):
            error = PduError.TOO_MUCH_PADDING  # Basically, we can't have padding-only cells
        elif aal5_crc(raw[:-4]) != trailer.crc:
            error = PduError.BAD_CHECKSUM
        else:
            error = None
        return cls(body, trailer, error)

    def to_bytes(self) -> bytes:
        return self.body + self.trailer.to_bytes()

    def segments(self, circuit: VirtualCircuit, *, clp: int = 0, congestion: bool = False) -> list[Cell]:
        """Segment the PDU into cells and mark the last one with the AUU bit"""
        raw = self.to_bytes()
        if not raw or len(raw) % ATM_PAYLOAD_SIZE:
            raise Aal5Error(f"Invalid PDU length ({len(raw)}), expected a multiple of {ATM_PAYLOAD_SIZE} bytes")
        payloads = [bytes(batch) for batch in itertools.batched(raw, ATM_PAYLOAD_SIZE, strict=True)]
        return [
            Cell(payload, circuit, pti=Pti.user_data(index >= len(payloads) - 1, congestion), clp=clp)
            for index, payload in enumerate(payloads)
        ]

    @property
    def ok(self) -> bool:
        return self.error is None

    @property
    def data(self) -> bytes:
        if self.error is not None:
            raise Aal5Error(f"Invalid PDU: {self.error}")
        return self.body[: self.trailer.length]


@dataclasses.dataclass
class Reassembler:
    """Reassembles the cells of one circuit into CPCS-PDUs"""

    buffer: bytearray = dataclasses.field(default_factory=bytearray)

    def _take(self) -> bytes:
        raw, self.buffer = bytes(self.buffer), bytearray()
        return raw

    def push(self, cell: Cell) -> Pdu | None:
        """Adds a cell to the reassembler and if it is the last cell return the reassembled PDU"""
        self.buffer += cell.payload
        if len(self.buffer) > AAL5_MAX_PDU_SIZE:
            return Pdu(self._take(), Trailer(), PduError.OVERSIZED)
        return Pdu.from_bytes(self._take()) if cell.pti.auu else None
