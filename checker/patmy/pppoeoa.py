"""PPPoE (RFC 2516) over bridged Ethernet (RFC 2684)"""

from __future__ import annotations

import dataclasses
import struct
import typing

ETH_ALEN = 6
ETHERNET_HEADER_SIZE = 14
ETHERTYPE_PPPOE_DISCOVERY = 0x8863
ETHERTYPE_PPPOE_SESSION = 0x8864

# RFC 2684 bridged encapsulation with LLC/SNAP
LLC_DSAP_SNAP = 0xAA
LLC_SSAP_SNAP = 0xAA
LLC_CTRL_UI = 0x03  # Unnumbered information
SNAP_OUI_8021 = bytes((0x00, 0x80, 0xC2))  # IEEE 802.1 bridging
BRIDGED_PID_ETHERNET_FCS = 0x0001  # Ethernet/802.3, LAN FCS preserved
BRIDGED_PID_ETHERNET = 0x0007  # Ethernet/802.3, FCS stripped

LLC_SNAP_HEADER = (
    bytes((LLC_DSAP_SNAP, LLC_SSAP_SNAP, LLC_CTRL_UI))
    + SNAP_OUI_8021
    + struct.pack("!H", BRIDGED_PID_ETHERNET)
    + bytes(2)
)
LLC_SNAP_HEADER_SIZE = len(LLC_SNAP_HEADER)

PPPOE_VERSION = 1
PPPOE_TYPE = 1
PPPOE_VERSION_TYPE = (PPPOE_VERSION << 4) | PPPOE_TYPE
PPPOE_CODE_SESSION = 0x00
PPPOE_HEADER_SIZE = 6

PPP_PROTO_IPV4 = 0x0021
PPP_PROTO_IPV6 = 0x0057
PPP_HEADER_SIZE = 2

HEADER_SIZE = LLC_SNAP_HEADER_SIZE + ETHERNET_HEADER_SIZE + PPPOE_HEADER_SIZE + PPP_HEADER_SIZE


class PppoeoaError(ValueError):
    pass


def parse_mac(address: str | bytes) -> bytes:
    if isinstance(address, str):
        address = bytes.fromhex(address.replace(":", "").replace("-", "").replace(".", ""))
    if len(address) != ETH_ALEN:
        raise PppoeoaError(f"Invalid MAC length ({len(address)}), expected {ETH_ALEN} bytes")
    return bytes(address)


def format_mac(address: bytes) -> str:
    return ":".join(f"{byte:02x}" for byte in address)


@dataclasses.dataclass
class Frame:
    """A PPP payload under PPPoE, Ethernet and RFC 2684 headers"""

    payload: bytes
    source: bytes
    destination: bytes
    session_id: int
    encapsulation: bytes = LLC_SNAP_HEADER
    ethertype: int = ETHERTYPE_PPPOE_SESSION
    version_type: int = PPPOE_VERSION_TYPE
    code: int = PPPOE_CODE_SESSION
    protocol: int = PPP_PROTO_IPV4
    length: int | None = None

    ETHERNET_FORMAT: typing.ClassVar[str] = "!6s6sH"
    PPPOE_FORMAT: typing.ClassVar[str] = "!BBHH"
    PPP_FORMAT: typing.ClassVar[str] = "!H"

    def __post_init__(self) -> None:
        self.source = parse_mac(self.source)
        self.destination = parse_mac(self.destination)

    @classmethod
    def from_bytes(cls, data: bytes) -> Frame:
        if len(data) < HEADER_SIZE:
            raise PppoeoaError(f"Invalid frame length ({len(data)}), expected at least {HEADER_SIZE} bytes")

        encapsulation = data[:LLC_SNAP_HEADER_SIZE]
        if encapsulation != LLC_SNAP_HEADER:
            raise PppoeoaError(f"Unsupported encapsulation ({encapsulation.hex()}), expected {LLC_SNAP_HEADER.hex()}")

        destination, source, ethertype = struct.unpack_from(cls.ETHERNET_FORMAT, data, LLC_SNAP_HEADER_SIZE)
        if ethertype != ETHERTYPE_PPPOE_SESSION:
            raise PppoeoaError(f"Unsupported ethertype ({ethertype:#06x}), expected {ETHERTYPE_PPPOE_SESSION:#06x}")

        version_type, code, session_id, length = struct.unpack_from(
            cls.PPPOE_FORMAT, data, LLC_SNAP_HEADER_SIZE + ETHERNET_HEADER_SIZE
        )
        if version_type != PPPOE_VERSION_TYPE:
            raise PppoeoaError(
                f"Unsupported PPPoE version/type ({version_type:#04x}), expected {PPPOE_VERSION_TYPE:#04x}"
            )
        if code != PPPOE_CODE_SESSION:
            raise PppoeoaError(f"Unsupported PPPoE code ({code:#04x}), expected a session frame")

        body = data[LLC_SNAP_HEADER_SIZE + ETHERNET_HEADER_SIZE + PPPOE_HEADER_SIZE :]
        if not PPP_HEADER_SIZE <= length <= len(body):
            raise PppoeoaError(f"Invalid PPPoE length ({length}), with {len(body)} bytes behind the header")
        (protocol,) = struct.unpack_from(cls.PPP_FORMAT, body)

        return cls(
            payload=body[PPP_HEADER_SIZE:length],  # strip padding
            source=source,
            destination=destination,
            session_id=session_id,
            encapsulation=encapsulation,
            ethertype=ethertype,
            version_type=version_type,
            code=code,
            protocol=protocol,
            length=length,
        )

    def to_bytes(self) -> bytes:
        return b"".join(
            (
                self.encapsulation,
                struct.pack(self.ETHERNET_FORMAT, self.destination, self.source, self.ethertype),
                struct.pack(
                    self.PPPOE_FORMAT,
                    self.version_type,
                    self.code,
                    self.session_id,
                    PPP_HEADER_SIZE + len(self.payload) if self.length is None else self.length,
                ),
                struct.pack(self.PPP_FORMAT, self.protocol),
                self.payload,
            )
        )

    def __str__(self) -> str:
        return f"{format_mac(self.source)} > {format_mac(self.destination)} (session {self.session_id:#06x})"
