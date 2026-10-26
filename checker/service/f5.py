"""OAM F5 system management cells can carry custom commands per ITU-T I.610.

We implement a simple encrypted key-value store with two custom commands:

    PUT(data)      -> (id, key)   stores id -> (key, enc(data, key))
    GET(id, nonce) -> (ct, mac)   computes mac <- CMAC(ct || nonce, key)

The MAC computation proves that the service actually held on to the key.

Make sure to keep this in sync with `meta/zephyr/app/src/f5.{c,h}`.
"""

from __future__ import annotations

import asyncio
import dataclasses
import enum
import logging

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from patmy import Circuit
from patmy.oam import OamCell, OamType

DEFAULT_LOGGER = logging.LoggerAdapter(logging.getLogger(__name__), {})

ID_SIZE = 4  # f5_id_t: Storage generation and slot
DATA_SIZE = 38  # f5_data_t: Data payload (one flag)
MAC_SIZE = 7  # f5_mac_t: Truncated CMAC tag
KEY_SIZE = 16  # f5_key_t: AES-128 key

OAM_TIMEOUT = 10.0


class F5Error(ValueError):
    """Something is wrong with an F5 exchange."""


class F5ProtocolError(F5Error):
    """The service answered with something the protocol does not allow."""


class F5UsageError(F5Error):
    """We asked for something the protocol cannot express."""


class Function(enum.IntEnum):
    """System management function codes (`enum f5_function`)."""

    PUT = 0
    GET = 1

    @property
    def as_response(self) -> int:
        return self | 8


@dataclasses.dataclass(frozen=True)
class Record:
    id: bytes
    key: bytes

    def __post_init__(self) -> None:
        if len(self.id) != ID_SIZE:
            raise F5UsageError(f"Invalid record ID length ({len(self.id)}), expected {ID_SIZE} bytes")
        if len(self.key) != KEY_SIZE:
            raise F5UsageError(f"Invalid key length ({len(self.key)}), expected {KEY_SIZE} bytes")

    @classmethod
    def from_hex(cls, identifier: str, key: str) -> Record:
        return cls(bytes.fromhex(identifier), bytes.fromhex(key))

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypts the ciphertext with the key."""
        counter = self.id.ljust(16, b"\0")
        decryptor = Cipher(algorithms.AES(self.key), modes.CTR(counter)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

    def mac(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """Computes the MAC of the ciphertext under the given nonce."""
        tag = cmac.CMAC(algorithms.AES(self.key))
        tag.update(ciphertext + nonce)
        return tag.finalize()[:MAC_SIZE]

    def __str__(self) -> str:
        return self.id.hex()


@dataclasses.dataclass(frozen=True)
class Retrieval:
    ciphertext: bytes
    mac: bytes
    nonce: bytes

    def authenticate(self, record: Record) -> bool:
        return self.mac == record.mac(self.ciphertext, self.nonce)

    def plaintext(self, record: Record) -> bytes:
        return record.decrypt(self.ciphertext)


class Client:
    """A client for the F5-backed flag store."""

    def __init__(self, circuit: Circuit, *, timeout: float = OAM_TIMEOUT, logger: logging.LoggerAdapter | None = None):
        self.circuit = circuit
        self.timeout = timeout
        self.logger = logger if logger is not None else DEFAULT_LOGGER

    async def put(self, data: bytes, *, injected_padding: bytes = b"") -> Record:
        """Stores a record, returning its ID and key."""
        if len(data) != DATA_SIZE:
            raise F5UsageError(f"A record holds {DATA_SIZE} bytes, got {len(data)}")
        body = await self._transact(Function.PUT, data.ljust(DATA_SIZE, b"\0") + injected_padding)
        return Record(body[:ID_SIZE], body[ID_SIZE : ID_SIZE + KEY_SIZE])

    async def get(self, record: Record | bytes, *, nonce: bytes, injected_padding: bytes = b"") -> Retrieval:
        """Reads a record back based on its ID."""
        identifier = record.id if isinstance(record, Record) else record
        if len(identifier) != ID_SIZE:
            raise F5UsageError(f"Invalid record ID length ({len(identifier)}), expected {ID_SIZE} bytes")
        body = await self._transact(Function.GET, identifier + bytes([len(nonce)]) + nonce + injected_padding)
        return Retrieval(body[:DATA_SIZE], body[DATA_SIZE : DATA_SIZE + MAC_SIZE], nonce)

    async def _transact(self, function: Function, body: bytes) -> bytes:
        """Sends one request and waits for the response that answers it."""
        # Drain existing responses first
        self.circuit.drain_oam()
        cell = OamCell(OamType.SYSTEM_MANAGEMENT, function, body)
        await self.circuit.send_oam(cell)

        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError(f"No {function.name} response within {self.timeout} seconds")
            answer = await self.circuit.recv_oam(remaining)
            if answer.oam_type != OamType.SYSTEM_MANAGEMENT or answer.function != function.as_response:
                self.logger.debug(
                    "Ignoring OAM type %#x function %#x while waiting for %s on %s",
                    answer.oam_type,
                    answer.function,
                    function.name,
                    self.circuit,
                )
                continue
            if not answer.edc_valid:
                raise F5ProtocolError(f"Invalid EDC in {function.name} response")
            return answer.body
