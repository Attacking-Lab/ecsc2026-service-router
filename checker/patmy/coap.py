"""The Constrained Application Protocol (CoAP, RFC 7252) over UDP."""

from __future__ import annotations

import asyncio
import collections.abc
import dataclasses
import enum
import logging
import random
import struct
import typing

from .client import Circuit
from .udp_session import UdpSession

COAP_PORT = 5683  # The port CoAP is registered on (§ 12.8)
WELL_KNOWN_CORE = "/.well-known/core"  # The discovery resource (RFC 6690 § 4)

VERSION = 1
HEADER_FORMAT = "!BBH"  # Version/type/token length, code, message ID
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
MAX_TOKEN_SIZE = 8
MAX_MESSAGE_ID = 0xFFFF
PAYLOAD_MARKER = 0xFF

# Option deltas and lengths above 12 continue in extension bytes (§ 3.1)
NIBBLE_EXTEND_8 = 13
NIBBLE_EXTEND_16 = 14
NIBBLE_RESERVED = 15  # Reserved, and a message that uses it is malformed
EXTEND_8_BASE = 13
EXTEND_16_BASE = 269
MAX_OPTION_NUMBER = 0xFFFF  # The IANA registry is 16 bits wide (§ 12.2)

# Retransmission parameters (§ 4.8). The defaults here are the RFC's, except
# that we give up after fewer attempts than MAX_RETRANSMIT (4) would.
ACK_TIMEOUT = 2.0
ACK_RANDOM_FACTOR = 1.5
DEFAULT_RETRANSMISSIONS = 2
SEPARATE_TIMEOUT = 10.0  # How long a separate response may take after its empty ACK

DEFAULT_TOKEN_SIZE = 4

# A path is "/a/b", b"/a/b", or the segments themselves; a query is "a=1&b=2" or its arguments
type UriPath = str | bytes | collections.abc.Iterable[str | bytes]
type UriQuery = str | bytes | collections.abc.Iterable[str | bytes]


class CoapError(ValueError):
    pass


class CoapReset(CoapError):
    """The peer rejected a message of ours with a RST (§ 4.2)."""

    def __init__(self, message_id: int, message: str | None = None):
        self.message_id = message_id
        super().__init__(message or f"The peer reset message {message_id:#06x}")


class CoapType(enum.IntEnum):
    """Message types (§ 3)"""

    CON = 0  # Confirmable, so it is retransmitted until it is acknowledged
    NON = 1  # Non-confirmable, fire and forget
    ACK = 2
    RST = 3


def code(response_class: int, detail: int) -> int:
    """Packs a `class.detail` code into the byte that carries it (§ 3)."""
    if not 0 <= response_class <= 7 or not 0 <= detail <= 31:
        raise CoapError(f"Invalid code {response_class}.{detail:02d}")
    return (response_class << 5) | detail


def format_code(value: int) -> str:
    """Spells a code byte as `class.detail`."""
    return f"{value >> 5}.{value & 0x1F:02d}"


CLASS_REQUEST = 0
CLASS_SUCCESS = 2
CLASS_CLIENT_ERROR = 4
CLASS_SERVER_ERROR = 5


class CoapCode(enum.IntEnum):
    """The request methods and the response codes of § 12.1."""

    EMPTY = code(0, 0)
    # Methods (§ 5.8)
    GET = code(0, 1)
    POST = code(0, 2)
    PUT = code(0, 3)
    DELETE = code(0, 4)
    # Success
    CREATED = code(2, 1)
    DELETED = code(2, 2)
    VALID = code(2, 3)
    CHANGED = code(2, 4)
    CONTENT = code(2, 5)
    # Client error
    BAD_REQUEST = code(4, 0)
    UNAUTHORIZED = code(4, 1)
    BAD_OPTION = code(4, 2)
    FORBIDDEN = code(4, 3)
    NOT_FOUND = code(4, 4)
    METHOD_NOT_ALLOWED = code(4, 5)
    NOT_ACCEPTABLE = code(4, 6)
    PRECONDITION_FAILED = code(4, 12)
    REQUEST_ENTITY_TOO_LARGE = code(4, 13)
    UNSUPPORTED_CONTENT_FORMAT = code(4, 15)
    # Server error
    INTERNAL_SERVER_ERROR = code(5, 0)
    NOT_IMPLEMENTED = code(5, 1)
    BAD_GATEWAY = code(5, 2)
    SERVICE_UNAVAILABLE = code(5, 3)
    GATEWAY_TIMEOUT = code(5, 4)
    PROXYING_NOT_SUPPORTED = code(5, 5)

    def __str__(self) -> str:
        return format_code(self)


class OptionNumber(enum.IntEnum):
    """Option numbers (§ 12.2), plus the block-wise transfer ones of RFC 7959."""

    IF_MATCH = 1
    URI_HOST = 3
    ETAG = 4
    IF_NONE_MATCH = 5
    OBSERVE = 6  # RFC 7641
    URI_PORT = 7
    LOCATION_PATH = 8
    URI_PATH = 11
    CONTENT_FORMAT = 12
    MAX_AGE = 14
    URI_QUERY = 15
    ACCEPT = 17
    LOCATION_QUERY = 20
    BLOCK2 = 23  # RFC 7959
    BLOCK1 = 27  # RFC 7959
    SIZE2 = 28  # RFC 7959
    PROXY_URI = 35
    PROXY_SCHEME = 39
    SIZE1 = 60

    @property
    def is_critical(self) -> bool:
        """Critical options may not be ignored by whoever receives them (§ 5.4.1)."""
        return bool(self & 0x01)

    @property
    def is_unsafe(self) -> bool:
        """Unsafe options may not be forwarded by a proxy that does not know them (§ 5.4.2)."""
        return bool(self & 0x02)

    @property
    def is_repeatable(self) -> bool:
        """Whether more than one instance of the option is allowed (§ 5.4.5)."""
        return self in REPEATABLE_OPTIONS


REPEATABLE_OPTIONS = frozenset(
    {
        OptionNumber.IF_MATCH,
        OptionNumber.ETAG,
        OptionNumber.LOCATION_PATH,
        OptionNumber.URI_PATH,
        OptionNumber.URI_QUERY,
        OptionNumber.LOCATION_QUERY,
    }
)


class ContentFormat(enum.IntEnum):
    """Content formats (§ 12.3)"""

    TEXT_PLAIN = 0
    LINK_FORMAT = 40
    XML = 41
    OCTET_STREAM = 42
    EXI = 47
    JSON = 50


def encode_uint(value: int, *, size: int | None = None) -> bytes:
    """Encodes an option value in the shortest unsigned integer form (§ 3.2)."""
    if value < 0:
        raise CoapError(f"Invalid option value ({value}), expected an unsigned integer")
    length = (value.bit_length() + 7) // 8 if size is None else size
    try:
        return value.to_bytes(length, "big")
    except OverflowError:
        raise CoapError(f"Option value {value} does not fit {length} bytes") from None


def decode_uint(value: bytes) -> int:
    """Decodes the unsigned integer an option value carries; an empty one is zero (§ 3.2)."""
    return int.from_bytes(value, "big")


def split_path(path: UriPath) -> list[bytes]:
    """Splits a path into Uri-Path segments, given as a string, as bytes, or as the segments."""
    if isinstance(path, (str, bytes)):
        raw = path.encode() if isinstance(path, str) else path
        return [segment for segment in raw.split(b"/") if segment]
    segments = [segment.encode() if isinstance(segment, str) else bytes(segment) for segment in path]
    for segment in segments:
        if b"/" in segment:
            raise CoapError(f"Invalid path segment ({segment!r}), a segment cannot contain a slash")
    return segments


def split_query(query: UriQuery) -> list[bytes]:
    """Splits a query into Uri-Query arguments, given as one string or as the arguments (§ 6.4)."""
    if isinstance(query, (str, bytes)):
        raw = query.encode() if isinstance(query, str) else query
        return [argument for argument in raw.removeprefix(b"?").split(b"&") if argument]
    arguments = [argument.encode() if isinstance(argument, str) else bytes(argument) for argument in query]
    for argument in arguments:
        if b"&" in argument:
            raise CoapError(f"Invalid query argument ({argument!r}), an argument cannot contain an ampersand")
    return arguments


def join_path(segments: collections.abc.Iterable[bytes]) -> str:
    """Joins the segments back into one path for displaying."""
    return "/" + "/".join(segment.decode(errors="backslashreplace") for segment in segments)


@dataclasses.dataclass
class Option:
    """One option instance. The number is an `OptionNumber` or whatever the peer sent."""

    number: int
    value: bytes = b""

    def __post_init__(self) -> None:
        if not 0 <= self.number <= MAX_OPTION_NUMBER:
            raise CoapError(f"Invalid option number ({self.number}), expected 0 to {MAX_OPTION_NUMBER}")
        self.value = self.value.encode() if isinstance(self.value, str) else bytes(self.value)

    @classmethod
    def from_int(cls, number: int, value: int, **kwargs) -> Option:
        """Builds an option carrying an unsigned integer."""
        return cls(number, encode_uint(value, **kwargs))

    @classmethod
    def from_text(cls, number: int, value: str) -> Option:
        return cls(number, value.encode())

    @property
    def name(self) -> str:
        try:
            return OptionNumber(self.number).name
        except ValueError:
            return f"Option {self.number}"

    @property
    def is_critical(self) -> bool:
        return bool(self.number & 0x01)

    @property
    def is_unsafe(self) -> bool:
        return bool(self.number & 0x02)

    @property
    def as_int(self) -> int:
        return decode_uint(self.value)

    @property
    def as_text(self) -> str:
        try:
            return self.value.decode()
        except UnicodeDecodeError as error:
            raise CoapError(f"{self.name} is not valid UTF-8: {error}") from None

    def __str__(self) -> str:
        return f"{self.name}={self.value!r}"


def _decode_nibble(nibble: int, data: bytes, at: int, what: str) -> tuple[int, int]:
    """Reads one delta or length nibble and its extension bytes, if it has any (§ 3.1)."""
    if nibble == NIBBLE_RESERVED:
        raise CoapError(f"Reserved option {what} encoding ({NIBBLE_RESERVED})")
    if nibble == NIBBLE_EXTEND_8:
        if at + 1 > len(data):
            raise CoapError(f"Truncated option {what} extension")
        return data[at] + EXTEND_8_BASE, at + 1
    if nibble == NIBBLE_EXTEND_16:
        if at + 2 > len(data):
            raise CoapError(f"Truncated option {what} extension")
        return struct.unpack_from("!H", data, at)[0] + EXTEND_16_BASE, at + 2
    return nibble, at


def _encode_nibble(value: int, what: str) -> tuple[int, bytes]:
    """Encodes a delta or a length as a nibble and its extension bytes (§ 3.1)."""
    if value < NIBBLE_EXTEND_8:
        return value, b""
    if value < EXTEND_16_BASE:
        return NIBBLE_EXTEND_8, bytes((value - EXTEND_8_BASE,))
    if value <= 0xFFFF + EXTEND_16_BASE:
        return NIBBLE_EXTEND_16, struct.pack("!H", value - EXTEND_16_BASE)
    raise CoapError(f"Option {what} ({value}) is too large to encode")


def decode_options(data: bytes, offset: int) -> tuple[list[Option], bytes]:
    """Parses the option block at `offset` and whatever payload follows it."""
    options: list[Option] = []
    number, at = 0, offset
    while at < len(data):
        if data[at] == PAYLOAD_MARKER:
            payload = data[at + 1 :]
            if not payload:
                raise CoapError("The payload marker is not followed by a payload")
            return options, payload

        head, at = data[at], at + 1
        delta, at = _decode_nibble(head >> 4, data, at, "delta")
        length, at = _decode_nibble(head & 0x0F, data, at, "length")
        number += delta
        if number > MAX_OPTION_NUMBER:
            raise CoapError(f"Option number ({number}) is out of range")
        if at + length > len(data):
            raise CoapError(f"Truncated value of option {number} ({length} bytes, {len(data) - at} left)")
        options.append(Option(number, data[at : at + length]))
        at += length
    return options, b""


def encode_options(options: collections.abc.Iterable[Option]) -> bytes:
    """Serialises options in ascending order as deltas against the previous one (§ 3.1)."""
    encoded, previous = bytearray(), 0
    for option in sorted(options, key=lambda option: option.number):  # A stable sort keeps repeats in order
        delta_nibble, delta_extension = _encode_nibble(option.number - previous, "delta")
        length_nibble, length_extension = _encode_nibble(len(option.value), "length")
        encoded.append((delta_nibble << 4) | length_nibble)
        encoded += delta_extension + length_extension + option.value
        previous = option.number
    return bytes(encoded)


@dataclasses.dataclass
class Message:
    """A CoAP message (§ 3)."""

    code: int  # A `CoapCode` or whatever the peer sent
    type: CoapType = CoapType.CON
    message_id: int = 0
    token: bytes = b""
    options: list[Option] = dataclasses.field(default_factory=list)
    payload: bytes = b""

    @classmethod
    def from_bytes(cls, data: bytes) -> typing.Self:
        if len(data) < HEADER_SIZE:
            raise CoapError(f"Invalid message length ({len(data)}), expected at least {HEADER_SIZE} bytes")

        first, raw_code, message_id = struct.unpack_from(HEADER_FORMAT, data)
        version = first >> 6
        if version != VERSION:
            raise CoapError(f"Unsupported version ({version}), expected {VERSION}")
        token_length = first & 0x0F
        if token_length > MAX_TOKEN_SIZE:
            raise CoapError(f"Invalid token length ({token_length}), at most {MAX_TOKEN_SIZE} bytes")
        if len(data) < HEADER_SIZE + token_length:
            raise CoapError(f"Truncated token ({len(data) - HEADER_SIZE} bytes, expected {token_length})")

        options, payload = decode_options(data, HEADER_SIZE + token_length)
        message = cls(
            code=raw_code,
            type=CoapType((first >> 4) & 0x03),
            message_id=message_id,
            token=data[HEADER_SIZE : HEADER_SIZE + token_length],
            options=options,
            payload=payload,
        )
        if message.is_empty and (message.token or message.options or message.payload):
            raise CoapError("An empty message carries no token, options or payload")
        return message

    def to_bytes(self) -> bytes:
        if not 0 <= self.code <= 0xFF:
            raise CoapError(f"Invalid code ({self.code})")
        if len(self.token) > MAX_TOKEN_SIZE:
            raise CoapError(f"Invalid token length ({len(self.token)}), at most {MAX_TOKEN_SIZE} bytes")
        if not 0 <= self.message_id <= MAX_MESSAGE_ID:
            raise CoapError(f"Invalid message ID ({self.message_id})")
        if self.is_empty and (self.token or self.options or self.payload):
            raise CoapError("An empty message carries no token, options or payload (§ 4.1)")

        header = struct.pack(
            HEADER_FORMAT,
            (VERSION << 6) | ((int(self.type) & 0x03) << 4) | len(self.token),
            int(self.code),
            self.message_id,
        )
        marked = bytes((PAYLOAD_MARKER,)) + self.payload if self.payload else b""
        return header + self.token + encode_options(self.options) + marked

    @property
    def is_empty(self) -> bool:
        """An empty message is the 0.00 code, which is a ping, an ACK, or a RST (§ 4.1)."""
        return self.code == CoapCode.EMPTY

    @property
    def code_class(self) -> int:
        return self.code >> 5

    @property
    def code_detail(self) -> int:
        return self.code & 0x1F

    @property
    def code_name(self) -> str:
        """The code as `class.detail` with its RFC 7252 name where there is one."""
        try:
            return f"{format_code(self.code)} ({CoapCode(self.code).name})"
        except ValueError:
            return format_code(self.code)

    def all_options(self, number: int) -> list[Option]:
        """Every instance of a repeatable option in message order (§ 5.4.5)."""
        return [option for option in self.options if option.number == number]

    def option(self, number: int) -> Option | None:
        """The first instance of an option, or None."""
        return next((option for option in self.options if option.number == number), None)

    def option_value(self, number: int) -> bytes | None:
        option = self.option(number)
        return None if option is None else option.value

    def option_int(self, number: int) -> int | None:
        option = self.option(number)
        return None if option is None else option.as_int

    @property
    def segments(self) -> list[bytes]:
        """The Uri-Path segments (§ 5.10.1)."""
        return [option.value for option in self.all_options(OptionNumber.URI_PATH)]

    @property
    def path(self) -> str:
        return join_path(self.segments)

    @property
    def query(self) -> list[str]:
        """The Uri-Query arguments (§ 5.10.1)."""
        return [option.as_text for option in self.all_options(OptionNumber.URI_QUERY)]

    @property
    def content_format(self) -> int | None:
        return self.option_int(OptionNumber.CONTENT_FORMAT)

    def __str__(self) -> str:
        parts = [f"{self.type.name} {self.code_name}", f"id={self.message_id:#06x}"]
        if self.token:
            parts.append(f"token={self.token.hex()}")
        if self.options:
            parts.append(f"options=[{', '.join(str(option) for option in self.options)}]")
        if self.payload:
            parts.append(f"{len(self.payload)} bytes")
        return " ".join(parts)


class Response(Message):
    """A message received as the answer to a request."""

    @property
    def ok(self) -> bool:
        """Whether the request succeeded (is a 2.xx)."""
        return self.code_class == CLASS_SUCCESS

    def raise_for_code(self) -> Response:
        """Raises if the request failed, or returns the response."""
        if not self.ok:
            raise CoapError(f"The peer answered {self.code_name}")
        return self

    @property
    def text(self) -> str:
        try:
            return self.payload.decode()
        except UnicodeDecodeError as error:
            raise CoapError(f"The payload is not valid UTF-8: {error}") from None

    @property
    def location(self) -> str:
        """Where a created resource ended up, from the Location-Path options (§ 5.10.7)."""
        return join_path(option.value for option in self.all_options(OptionNumber.LOCATION_PATH))


@dataclasses.dataclass
class Link:
    """One link of an RFC 6690 link format document."""

    path: str
    attributes: dict[str, str] = dataclasses.field(default_factory=dict)

    @property
    def content_format(self) -> int | None:
        """The `ct` attribute if the peer gave a single numeric one (RFC 6690 § 3.1)."""
        value = self.attributes.get("ct", "")
        return int(value) if value.isdigit() else None

    def __iter__(self) -> collections.abc.Iterator:
        # So a link unpacks as `path, attributes`
        return iter((self.path, self.attributes))

    def __str__(self) -> str:
        return "".join([f"<{self.path}>", *(f";{name}={value}" for name, value in self.attributes.items())])


def _split_outside_quotes(text: str, separator: str) -> list[str]:
    """Splits on a separator, ignoring the ones inside a quoted string (RFC 6690 § 2)."""
    parts: list[str] = []
    current: list[str] = []
    quoted = escaped = False
    for character in text:
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == separator and not quoted:
            parts.append("".join(current))
            current = []
            continue
        current.append(character)
    if quoted or escaped:
        raise CoapError("Unterminated quoted string in the link format document")
    parts.append("".join(current))
    return parts


def _unquote(value: str) -> str:
    if len(value) < 2 or not value.startswith('"') or not value.endswith('"'):
        return value
    unquoted, escaped = [], False
    for character in value[1:-1]:
        if not escaped and character == "\\":
            escaped = True
            continue
        escaped = False
        unquoted.append(character)
    return "".join(unquoted)


def parse_link_format(document: bytes | str) -> list[Link]:
    """Parses an RFC 6690 link format document, as `/.well-known/core` returns it."""
    if isinstance(document, bytes):
        try:
            document = document.decode()
        except UnicodeDecodeError as error:
            raise CoapError(f"The link format document is not valid UTF-8: {error}") from None

    links = []
    for entry in _split_outside_quotes(document, ","):
        fields = _split_outside_quotes(entry.strip(), ";")
        target = fields[0].strip()
        if not target:
            continue  # A trailing comma, or an empty document
        if not target.startswith("<") or not target.endswith(">"):
            raise CoapError(f"Invalid link target ({target!r}), expected <uri-reference>")
        attributes = {}
        for attribute in fields[1:]:
            name, _, value = attribute.strip().partition("=")
            if not name:
                raise CoapError(f"Invalid link attribute in {entry!r}")
            attributes[name] = _unquote(value)
        links.append(Link(target[1:-1], attributes))
    return links


class CoapClient:
    """A CoAP client, on an established UDP session to one peer.

    async with client.calling(number) as circuit:
        service = CoapClient.over(circuit)
        print((await service.get("/hello")).payload)
    """

    def __init__(
        self,
        session: UdpSession,
        *,
        timeout: float = ACK_TIMEOUT,
        retransmissions: int = DEFAULT_RETRANSMISSIONS,
        separate_timeout: float = SEPARATE_TIMEOUT,
        token_size: int = DEFAULT_TOKEN_SIZE,
        rng: random.Random | None = None,
        logger: logging.LoggerAdapter | None = None,
    ):
        if not 0 <= token_size <= MAX_TOKEN_SIZE:
            raise CoapError(f"Invalid token size ({token_size}), at most {MAX_TOKEN_SIZE} bytes")
        self.session = session
        self.logger = logger if logger is not None else session.logger
        self.timeout = timeout
        self.retransmissions = retransmissions
        self.separate_timeout = separate_timeout
        self.token_size = token_size
        self.rng = rng
        self._message_id = (rng if rng is not None else random).randrange(MAX_MESSAGE_ID + 1)

    @classmethod
    def over(
        cls,
        circuit: Circuit,
        *,
        peer_port: int = COAP_PORT,
        rng: random.Random | None = None,
        logger: logging.LoggerAdapter | None = None,
        **kwargs,
    ) -> CoapClient:
        """Opens a client on a UDP session of its own. Overrides are passed to `UdpSession`."""
        session = UdpSession(circuit, peer_port=peer_port, rng=rng, logger=logger, **kwargs)
        return cls(session, rng=rng, logger=logger)

    def next_message_id(self) -> int:
        """Takes the ID for the next message we start an exchange with (§ 4.4)."""
        self._message_id = (self._message_id + 1) % (MAX_MESSAGE_ID + 1)
        return self._message_id

    def new_token(self) -> bytes:
        """Draws a token that tells one of our exchanges from another (§ 5.3.1)."""
        return (self.rng if self.rng is not None else random).randbytes(self.token_size)

    async def send(self, message: Message) -> None:
        """Sends one message, without waiting for anything to come back."""
        self.logger.debug("Sending %s", message)
        await self.session.send(message.to_bytes())

    async def acknowledge(self, message: Message) -> None:
        """Acknowledges a confirmable message with an empty ACK (§ 5.2.2)."""
        await self.send(Message(code=CoapCode.EMPTY, type=CoapType.ACK, message_id=message.message_id))

    async def reset(self, message: Message) -> None:
        """Rejects a message we cannot place with a RST (§ 4.2)."""
        await self.send(Message(code=CoapCode.EMPTY, type=CoapType.RST, message_id=message.message_id))

    def build(
        self,
        method: CoapCode | int,
        path: UriPath = "",
        payload: bytes | None = None,
        *,
        confirmable: bool = True,
        content_format: int | None = None,
        accept: int | None = None,
        query: UriQuery | None = None,
        options: collections.abc.Iterable[Option] = (),
        token: bytes | None = None,
        message_id: int | None = None,
    ) -> Message:
        """Assembles one request message, without sending it."""
        request_options = [Option(OptionNumber.URI_PATH, segment) for segment in split_path(path)]
        if query is not None:
            request_options += [Option(OptionNumber.URI_QUERY, argument) for argument in split_query(query)]
        if content_format is not None:
            request_options.append(Option.from_int(OptionNumber.CONTENT_FORMAT, content_format))
        if accept is not None:
            request_options.append(Option.from_int(OptionNumber.ACCEPT, accept))
        request_options += options

        return Message(
            code=int(method),
            type=CoapType.CON if confirmable else CoapType.NON,
            message_id=self.next_message_id() if message_id is None else message_id,
            token=self.new_token() if token is None else token,
            options=request_options,
            payload=payload if payload is not None else b"",
        )

    async def request(
        self,
        method: CoapCode | int,
        path: UriPath = "",
        payload: bytes | None = None,
        *,
        timeout: float | None = None,
        retransmissions: int | None = None,
        **kwargs,
    ) -> Response:
        """Sends one request and waits for its response. Overrides are passed to `build`."""
        request = self.build(method, path, payload, **kwargs)
        return await self.exchange(request, timeout=timeout, retransmissions=retransmissions)

    async def exchange(
        self,
        request: Message,
        *,
        timeout: float | None = None,
        retransmissions: int | None = None,
    ) -> Response:
        """Sends a message and waits for the response to it, retransmitting a CON (§ 4.2)."""
        rng = self.rng if self.rng is not None else random
        timeout = self.timeout if timeout is None else timeout
        attempts = self.retransmissions if retransmissions is None else retransmissions
        if request.type is not CoapType.CON:
            attempts = 0  # Only a confirmable message is retransmitted (§ 4.3)
        # The first timeout is spread over [ACK_TIMEOUT, ACK_TIMEOUT * ACK_RANDOM_FACTOR), and doubles from there
        wait = timeout * (1.0 + (ACK_RANDOM_FACTOR - 1.0) * rng.random())
        loop = asyncio.get_running_loop()

        await self.send(request)
        deadline, separate = loop.time() + wait, False
        while True:
            remaining = deadline - loop.time()
            if remaining <= 0:
                if separate or not attempts:
                    raise TimeoutError(f"No response to {request.code_name} {request.path}")
                attempts, wait = attempts - 1, wait * 2
                self.logger.debug("Retransmitting %s", request)
                await self.send(request)  # The same message ID: this is a retransmission, not a new request
                deadline = loop.time() + wait
                continue

            try:
                datagram = await self.session.recv_datagram(remaining)
            except TimeoutError:
                continue  # The deadline decides whether that was the last attempt
            try:
                message = Response.from_bytes(datagram.payload)
            except CoapError as error:
                self.logger.warning("Discarding a CoAP message from %s: %s", self.session.peer_ip, error)
                continue
            self.logger.debug("Received %s", message)

            if message.message_id == request.message_id and message.type is CoapType.RST:
                raise CoapReset(message.message_id)
            if message.message_id == request.message_id and message.type is CoapType.ACK:
                if not message.is_empty:
                    if message.token != request.token:
                        raise CoapError(
                            f"The piggybacked response carries token {message.token.hex()}, "
                            f"expected {request.token.hex()}"
                        )
                    return message
                # An empty ACK means the response follows in a message of its own (§ 5.2.2)
                self.logger.debug("Message %#06x was acknowledged, awaiting a separate response", request.message_id)
                separate, deadline = True, loop.time() + self.separate_timeout
                continue
            if not request.is_empty and message.token == request.token and message.type in (CoapType.CON, CoapType.NON):
                if message.type is CoapType.CON:
                    await self.acknowledge(message)
                return message

            self.logger.debug("Ignoring %s: it does not answer %s", message, request)
            if message.type is CoapType.CON:
                await self.reset(message)

    async def get(self, path: UriPath = "", **kwargs) -> Response:
        return await self.request(CoapCode.GET, path, **kwargs)

    async def post(self, path: UriPath, payload: bytes = b"", **kwargs) -> Response:
        return await self.request(CoapCode.POST, path, payload, **kwargs)

    async def put(self, path: UriPath, payload: bytes = b"", **kwargs) -> Response:
        return await self.request(CoapCode.PUT, path, payload, **kwargs)

    async def delete(self, path: UriPath, **kwargs) -> Response:
        return await self.request(CoapCode.DELETE, path, **kwargs)

    async def ping(self, **kwargs) -> bool:
        """Pings the peer with an empty CON, which it answers with a RST (§ 4.2)."""
        request = Message(code=CoapCode.EMPTY, type=CoapType.CON, message_id=self.next_message_id())
        try:
            response = await self.exchange(request, **kwargs)
        except CoapReset:
            return True
        except TimeoutError:
            return False
        raise CoapError(f"The peer answered a ping with {response.code_name}")

    async def discover(self, path: UriPath = WELL_KNOWN_CORE, **kwargs) -> list[Link]:
        """Reads the peer's resource listing from `/.well-known/core` (RFC 6690 § 4)."""
        response = (await self.get(path, **kwargs)).raise_for_code()
        return parse_link_format(response.payload)

    def __str__(self) -> str:
        return f"CoAP on {self.session}"
