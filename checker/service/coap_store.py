"""A key/value store reachable over CoAP.

    POST /store/<key>   claims <key> with a given handle  -> 2.01, 4.03 if taken
    PUT  /store/<key>   stores the payload                -> 2.04
    GET  /store/<key>   reads it back                     -> 2.05 with the value

PUT and GET pass the handle in If-Match. See `meta/zephyr/app/src/coap_service.c`
and `meta/zephyr/app/src/user_data.h`.
"""

from __future__ import annotations

import collections.abc
import logging
import random
import string

from patmy import Circuit, CoapClient, CoapCode, ContentFormat, Option, OptionNumber, Response

RESOURCE = "store"
OCTETS = ContentFormat.OCTET_STREAM

KEY_LENGTH = 8  # With space for the 8.3 folding
KEY_MAX = 12  # USER_DATA_KEY_MAX, the 8.3 short name a key folds into
VALUE_MAX = 64  # USER_DATA_VALUE_MAX
HANDLE_SIZE = 8  # USER_DATA_HANDLE_SIZE


class StoreProtocolError(ValueError):
    """The service answered with something the protocol does not allow."""


class KeyMissing(StoreProtocolError):
    """The store has no value under that key (4.04)."""


class KeyTaken(StoreProtocolError):
    """Somebody else claimed that key first (4.03)."""


def if_match(handle: bytes) -> list[Option]:
    return [Option(OptionNumber.IF_MATCH, handle)]


def unexpected(
    operation: str, key: str, response: Response, expected: collections.abc.Iterable[int]
) -> StoreProtocolError:
    """Turns an unexpected response code into a readable error message."""
    wanted = " or ".join(str(CoapCode(code)) for code in expected)
    return StoreProtocolError(f"{operation} {key!r} answered {response.code_name}, expected {wanted}")


# `create_name()` (ff.c) folds a key into an 8.3 short name before it looks it up, so
# several spellings name one file: any byte <= 0x20 ends the name, a trailing dot opens
# an empty extension, and ASCII is upper-cased.
FOLD_PAD = string.ascii_letters + string.digits


def folded_spellings(key: str, rng: random.Random) -> collections.abc.Iterator[bytes]:
    """Yields alias spellings that fold into the same short name as `key`."""
    room = KEY_MAX - len(key) - 1
    raw = key.encode()
    while True:
        pad = "".join(rng.choices(FOLD_PAD, k=rng.randint(0, room))).encode()
        yield raw + b" " + pad
        yield raw + bytes([rng.randrange(1, 0x20)]) + pad
        yield raw + b"."
        if any(c.isalpha() for c in key):  # the plain case fold needs letters to flip
            yield "".join(c.upper() if rng.random() < 0.5 else c for c in key).encode()


class Client:
    """A client for the CoAP-backed flag store."""

    def __init__(
        self,
        target: Circuit | CoapClient,
        *,
        rng: random.Random | None = None,
        logger: logging.LoggerAdapter | None = None,
        **kwargs,
    ):
        self.coap = (
            target if isinstance(target, CoapClient) else CoapClient.over(target, rng=rng, logger=logger, **kwargs)
        )
        self.logger = logger if logger is not None else self.coap.logger

    async def claim(self, key: str, handle: bytes, **kwargs) -> None:
        """Registers `key` with `handle`, raising `KeyTaken` if it is already taken."""
        response = await self.coap.post([RESOURCE, key], handle, content_format=OCTETS, **kwargs)
        if response.code == CoapCode.FORBIDDEN:
            raise KeyTaken(f"Key {key!r} is already claimed")
        if response.code != CoapCode.CREATED:
            raise unexpected("POST", key, response, (CoapCode.CREATED,))

    async def put(self, key: str, value: bytes, handle: bytes, **kwargs) -> None:
        """Stores the value for the key."""
        options = if_match(handle)
        response = await self.coap.put([RESOURCE, key], value, content_format=OCTETS, options=options, **kwargs)
        if response.code != CoapCode.CHANGED:
            raise unexpected("PUT", key, response, (CoapCode.CHANGED,))

    async def get(self, key: str, handle: bytes, **kwargs) -> bytes:
        """Reads a value back, raising `KeyMissing` if the key is gone."""
        response = await self.coap.get([RESOURCE, key], options=if_match(handle), **kwargs)
        if response.code == CoapCode.NOT_FOUND:
            raise KeyMissing(f"Key {key!r}")
        if response.code != CoapCode.CONTENT:
            raise unexpected("GET", key, response, (CoapCode.CONTENT,))
        # The store advertises ct=42, so it must be that (or empty, RFC 7252 § 5.5.1).
        if response.content_format not in (None, OCTETS):
            raise StoreProtocolError(f"GET {key!r} answered in content format {response.content_format}, expected 42")
        return response.payload

    async def claim_raw(self, key: bytes, handle: bytes, **kwargs) -> Response:
        """Registers a key without checking the result."""
        return await self.coap.post([RESOURCE, key], handle, content_format=OCTETS, **kwargs)

    async def get_raw(self, key: bytes | str, handle: bytes, **kwargs) -> Response:
        """Reads a value back without checking the result."""
        key = key.encode() if isinstance(key, str) else key
        return await self.coap.get([RESOURCE, key], options=if_match(handle), **kwargs)

    async def store(self, key: str, value: bytes, handle: bytes, **kwargs) -> None:
        """Claims a key and writes its value."""
        await self.claim(key, handle, **kwargs)
        await self.put(key, value, handle, **kwargs)

    def __str__(self) -> str:
        return f"Flag store on {self.coap}"
