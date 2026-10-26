"""IPv4 (RFC 791) carrying UDP (RFC 768)"""

from __future__ import annotations

import dataclasses
import ipaddress
import struct
import typing

IPV4_VERSION = 4
IPV4_IHL_NO_OPTIONS = 5  # header length in 32-bit words
IPV4_HEADER_SIZE = IPV4_IHL_NO_OPTIONS * 4
IPV4_VERSION_IHL = (IPV4_VERSION << 4) | IPV4_IHL_NO_OPTIONS
IPV4_PROTO_UDP = 17

# flags and fragment offset share one 16-bit field
IPV4_FLAG_RESERVED = 0x8000  # must be zero
IPV4_FLAG_DF = 0x4000  # don't fragment
IPV4_FLAG_MF = 0x2000  # more fragments
IPV4_FRAGMENT_OFFSET_MASK = 0x1FFF

UDP_HEADER_SIZE = 8

HEADER_SIZE = IPV4_HEADER_SIZE + UDP_HEADER_SIZE
DEFAULT_TTL = 64


class InetError(ValueError):
    pass


def inet_checksum(data: bytes) -> int:
    """16-bit ones' complement checksum from RFC 1071"""
    if len(data) % 2:
        data += b"\x00"  # padding
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return total ^ 0xFFFF


@dataclasses.dataclass
class Datagram:
    """A UDP datagram in an IPv4 packet"""

    payload: bytes
    source: ipaddress.IPv4Address
    destination: ipaddress.IPv4Address
    source_port: int
    destination_port: int
    version_ihl: int = IPV4_VERSION_IHL
    dscp_ecn: int = 0
    identification: int = 0
    flags_fragment: int = IPV4_FLAG_DF
    ttl: int = DEFAULT_TTL
    protocol: int = IPV4_PROTO_UDP
    total_length: int | None = None
    checksum: int | None = None
    udp_length: int | None = None
    udp_checksum: int | None = 0

    IPV4_FORMAT: typing.ClassVar[str] = "!BBHHHBBH4s4s"
    UDP_FORMAT: typing.ClassVar[str] = "!HHHH"

    def __post_init__(self) -> None:
        self.source = ipaddress.IPv4Address(self.source)
        self.destination = ipaddress.IPv4Address(self.destination)

    @classmethod
    def from_bytes(cls, data: bytes) -> Datagram:
        if len(data) < HEADER_SIZE:
            raise InetError(f"Invalid datagram length ({len(data)}), expected at least {HEADER_SIZE} bytes")

        (
            version_ihl,
            dscp_ecn,
            total_length,
            identification,
            flags_fragment,
            ttl,
            protocol,
            checksum,
            source,
            destination,
        ) = struct.unpack_from(cls.IPV4_FORMAT, data)
        if version_ihl != IPV4_VERSION_IHL:
            raise InetError(f"Unsupported version/IHL ({version_ihl:#04x}), expected {IPV4_VERSION_IHL:#04x}")
        if protocol != IPV4_PROTO_UDP:
            raise InetError(f"Unsupported protocol ({protocol}), expected UDP ({IPV4_PROTO_UDP})")
        if flags_fragment & (IPV4_FLAG_RESERVED | IPV4_FLAG_MF | IPV4_FRAGMENT_OFFSET_MASK):
            raise InetError(f"Refusing a fragmented datagram (flags {flags_fragment:#06x})")
        if inet_checksum(data[:IPV4_HEADER_SIZE]) != 0:
            raise InetError("Header checksum mismatch")
        if total_length != len(data):
            raise InetError(f"Total length ({total_length}) disagrees with the {len(data)} bytes received")

        source_port, destination_port, udp_length, udp_checksum = struct.unpack_from(
            cls.UDP_FORMAT, data, IPV4_HEADER_SIZE
        )
        if udp_length != total_length - IPV4_HEADER_SIZE:
            raise InetError(f"UDP length ({udp_length}) disagrees with the IPv4 total length ({total_length})")

        return cls(
            payload=data[HEADER_SIZE:],
            source=ipaddress.IPv4Address(source),
            destination=ipaddress.IPv4Address(destination),
            source_port=source_port,
            destination_port=destination_port,
            version_ihl=version_ihl,
            dscp_ecn=dscp_ecn,
            identification=identification,
            flags_fragment=flags_fragment,
            ttl=ttl,
            protocol=protocol,
            total_length=total_length,
            checksum=checksum,
            udp_length=udp_length,
            udp_checksum=udp_checksum,
        )

    def to_bytes(self) -> bytes:
        body_length = UDP_HEADER_SIZE + len(self.payload)

        udp = self._udp_header(0)
        if self.udp_checksum is None:
            checksum = inet_checksum(self._pseudo_header(body_length) + udp + self.payload)
            udp = self._udp_header(checksum or 0xFFFF)

        header = self._header(0, body_length)
        if self.checksum is None:
            header = self._header(inet_checksum(header), body_length)
        return header + udp + self.payload

    def _header(self, computed: int, body_length: int) -> bytes:
        return struct.pack(
            self.IPV4_FORMAT,
            self.version_ihl,
            self.dscp_ecn,
            IPV4_HEADER_SIZE + body_length if self.total_length is None else self.total_length,
            self.identification,
            self.flags_fragment,
            self.ttl,
            self.protocol,
            computed if self.checksum is None else self.checksum,
            self.source.packed,
            self.destination.packed,
        )

    def _udp_header(self, computed: int) -> bytes:
        return struct.pack(
            self.UDP_FORMAT,
            self.source_port,
            self.destination_port,
            UDP_HEADER_SIZE + len(self.payload) if self.udp_length is None else self.udp_length,
            computed if self.udp_checksum is None else self.udp_checksum,
        )

    def _pseudo_header(self, body_length: int) -> bytes:
        return self.source.packed + self.destination.packed + struct.pack("!BBH", 0, self.protocol, body_length)
