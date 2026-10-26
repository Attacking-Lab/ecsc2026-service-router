"""
This is a heavily simplified custom signalling protocol.

The nominally "correct" ITU-T Q.2931 over SSCF/SSCOP (Q.2130 and Q.2110)
would be thousands of lines of additional code for no gain, and quite
frankly way too much effort, since we're not running this on actual wires.

Like the standard signalling, this is carried over AAL5 on VPI 0, VCI 5.

Every message carries a (big-endian) u32 message type and transaction ID.
ESTABLISH messages follow that up with the peer's AESA, and a proposed VPI/VCI (u32).
RELEASE messages follow that with the VPI and VCI (both u32) to release.
No other message has an additional payload.
"""

from __future__ import annotations

import dataclasses
import enum
import struct

from .address import ATM_ADDRESS_SIZE, AtmAddress
from .atm import VirtualCircuit

HEADER_FORMAT = "!II"  # Message type and transaction ID
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
CIRCUIT_FORMAT = "!II"  # VPI and VCI
CIRCUIT_SIZE = struct.calcsize(CIRCUIT_FORMAT)


class SignallingError(ValueError):
    pass


class MessageType(enum.IntEnum):
    """Message types."""

    ESTABLISH = 0
    ESTABLISHED = 1
    RELEASE = 2
    RELEASED = 3
    GENERIC_ERROR = 10
    INVALID_ADDRESS = 11
    UNREACHABLE = 12
    REJECTED_CIRCUIT = 13
    NOT_PERMITTED = 14
    QUOTA_EXCEEDED = 15
    CONGESTED = 16

    @property
    def is_error(self) -> bool:
        return self >= MessageType.GENERIC_ERROR

    @property
    def payload_size(self) -> int:
        """Encoded size of the body that follows the header"""
        if self is MessageType.ESTABLISH:
            return ATM_ADDRESS_SIZE + CIRCUIT_SIZE
        if self is MessageType.RELEASE:
            return CIRCUIT_SIZE
        return 0


@dataclasses.dataclass
class Message:
    """A signalling message."""

    type: MessageType
    id: int
    address: AtmAddress | None = None  # ESTABLISH only
    circuit: VirtualCircuit | None = None  # ESTABLISH and RELEASE

    @staticmethod
    def _pack_circuit(circuit: VirtualCircuit) -> bytes:
        return struct.pack(CIRCUIT_FORMAT, circuit.vpi, circuit.vci)

    @staticmethod
    def _parse_circuit(data: bytes) -> VirtualCircuit:
        vpi, vci = struct.unpack(CIRCUIT_FORMAT, data)
        if vpi > 0xFF or vci > 0xFFFF:
            raise SignallingError(f"Invalid circuit {vpi}.{vci}")
        return VirtualCircuit(vpi, vci)

    @classmethod
    def from_bytes(cls, data: bytes) -> Message:
        if len(data) < HEADER_SIZE:
            raise SignallingError(f"Invalid message length ({len(data)}), expected at least {HEADER_SIZE} bytes")
        raw_type, message_id = struct.unpack_from(HEADER_FORMAT, data)
        try:
            message_type = MessageType(raw_type)
        except ValueError:
            raise SignallingError(f"Invalid message type {raw_type}") from None

        payload = data[HEADER_SIZE:]
        if len(payload) != message_type.payload_size:
            raise SignallingError(
                f"Invalid payload length ({len(payload)}) for {message_type.name}, "
                f"expected {message_type.payload_size} bytes"
            )

        address, circuit = None, None
        if message_type is MessageType.ESTABLISH:
            address = AtmAddress.from_bytes(payload[:ATM_ADDRESS_SIZE])
            circuit = cls._parse_circuit(payload[ATM_ADDRESS_SIZE:])
        elif message_type is MessageType.RELEASE:
            circuit = cls._parse_circuit(payload)
        return cls(message_type, message_id, address, circuit)

    def to_bytes(self) -> bytes:
        header = struct.pack(HEADER_FORMAT, self.type, self.id)
        if self.type is MessageType.ESTABLISH:
            if self.address is None or self.circuit is None:
                raise SignallingError("ESTABLISH needs an address and a circuit")
            return header + self.address.to_bytes() + self._pack_circuit(self.circuit)
        if self.type is MessageType.RELEASE:
            if self.circuit is None:
                raise SignallingError("RELEASE needs a circuit")
            return header + self._pack_circuit(self.circuit)
        return header
