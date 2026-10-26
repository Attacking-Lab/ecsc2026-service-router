"""A UDP flow to the peer, over PPPoEoA, over one ATM circuit."""

from __future__ import annotations

import ipaddress
import logging
import random

from . import inet, pppoeoa
from .client import Circuit

# Use some default values, we're not going to do DHCP in here...
DEFAULT_SESSION_ID = 1
DEFAULT_LOCAL_MAC = "02:00:00:00:00:01"
DEFAULT_PEER_MAC = "02:00:00:00:00:02"
DEFAULT_LOCAL_IP = "10.0.0.2"
DEFAULT_PEER_IP = "10.0.0.1"
DEFAULT_PEER_PORT = 5000
EPHEMERAL_PORTS = (0xC000, 0x10000)


class UdpSession:
    """One UDP flow between us and the peer on an already established circuit"""

    def __init__(
        self,
        circuit: Circuit,
        *,
        session_id: int = DEFAULT_SESSION_ID,
        local_mac: str | bytes = DEFAULT_LOCAL_MAC,
        peer_mac: str | bytes = DEFAULT_PEER_MAC,
        local_ip: str | ipaddress.IPv4Address = DEFAULT_LOCAL_IP,
        peer_ip: str | ipaddress.IPv4Address = DEFAULT_PEER_IP,
        local_port: int | None = None,  # None picks an ephemeral one
        peer_port: int = DEFAULT_PEER_PORT,
        rng: random.Random | None = None,
        logger: logging.LoggerAdapter | None = None,
    ):
        self.circuit = circuit
        self.logger = logger if logger is not None else circuit.logger
        self.session_id = session_id
        self.local_mac = pppoeoa.parse_mac(local_mac)
        self.peer_mac = pppoeoa.parse_mac(peer_mac)
        self.local_ip = ipaddress.IPv4Address(local_ip)
        self.peer_ip = ipaddress.IPv4Address(peer_ip)
        self.peer_port = peer_port
        self.local_port = (
            (rng if rng is not None else random).randrange(*EPHEMERAL_PORTS) if local_port is None else local_port
        )

    async def send(self, payload: bytes, **overrides) -> None:
        """Sends a UDP payload"""
        await self.send_datagram(
            inet.Datagram(payload, self.local_ip, self.peer_ip, self.local_port, self.peer_port, **overrides)
        )

    async def send_datagram(self, datagram: inet.Datagram, **overrides) -> None:
        """Sends a built datagram"""
        await self.send_frame(
            pppoeoa.Frame(datagram.to_bytes(), self.local_mac, self.peer_mac, self.session_id, **overrides)
        )

    async def send_frame(self, frame: pppoeoa.Frame, **overrides) -> None:
        """Sends a built frame as one SDU"""
        await self.circuit.send(frame.to_bytes(), **overrides)

    async def recv(self, timeout: float | None = None) -> bytes:
        """Waits for the next UDP payload"""
        return (await self.recv_datagram(timeout)).payload

    async def recv_datagram(self, timeout: float | None = None) -> inet.Datagram:
        """Waits for the next datagram"""
        while True:
            sdu = await self.circuit.recv(timeout)
            try:
                frame = pppoeoa.Frame.from_bytes(sdu)
                if frame.protocol != pppoeoa.PPP_PROTO_IPV4:
                    raise pppoeoa.PppoeoaError(f"Unsupported PPP protocol ({frame.protocol:#06x})")
                datagram = inet.Datagram.from_bytes(frame.payload)
            except ValueError as error:
                self.logger.warning("Discarding a frame on %s: %s", self.circuit, error)
                continue
            if not self.addressed_to_us(frame, datagram):
                self.logger.debug("Discarding %s on %s: not for this session", frame, self.circuit)
                continue
            return datagram

    def addressed_to_us(self, frame: pppoeoa.Frame, datagram: inet.Datagram) -> bool:
        return (
            frame.session_id == self.session_id
            and frame.destination == self.local_mac
            and datagram.destination == self.local_ip
            and datagram.destination_port == self.local_port
        )

    def __str__(self) -> str:
        return f"{self.local_ip}:{self.local_port} <-> {self.peer_ip}:{self.peer_port} on {self.circuit}"
