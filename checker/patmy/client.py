"""An asynchronous ADSL line and ATM client."""

from __future__ import annotations

import asyncio
import collections.abc
import contextlib
import logging
import random
import typing

from .aal5 import Pdu, Reassembler
from .address import ATM_ADDRESS_SIZE, AtmAddress
from .atm import ATM_CELL_SIZE, MIN_ALLOCATED_VCI, Cell, Pti, VirtualCircuit
from .oam import OamCell
from .signalling import Message, MessageType

DEFAULT_LOGGER = logging.LoggerAdapter(logging.getLogger(__name__), {})

# Default timeouts and queue sizes
CONNECT_TIMEOUT = 10.0
SIGNALLING_TIMEOUT = 5.0
SIGNALLING_RETRIES = 2
QUEUE_SIZE = 256


class ConnectionLost(Exception):
    pass


class CallFailed(Exception):
    def __init__(self, error: MessageType, message: str | None = None):
        self.error = error
        super().__init__(message or f"Signalling failed: {error.name}")


class Circuit:
    """A virtual circuit to a peer"""

    def __init__(self, connection: AtmConnection, circuit: VirtualCircuit):
        self.connection = connection
        self.circuit = circuit
        self.logger = connection.logger
        self.reassembler = Reassembler()
        self.pdus: asyncio.Queue[Pdu] = asyncio.Queue(QUEUE_SIZE)
        self.oam: asyncio.Queue[OamCell] = asyncio.Queue(QUEUE_SIZE)
        self.dropped = 0

    def feed(self, cell: Cell) -> None:
        """Adds a received cell into the circuit's receive path"""
        if cell.pti.is_oam:
            self._offer(self.oam, OamCell.from_bytes(cell.payload))
        elif not cell.pti.is_user_data:
            self.logger.debug("Dropping %s on %s", cell.pti.name, self.circuit)
        elif (pdu := self.reassembler.push(cell)) is not None:
            self._offer(self.pdus, pdu)

    def _offer(self, queue: asyncio.Queue, item: object) -> None:
        try:
            queue.put_nowait(item)
        except asyncio.QueueFull:
            self.dropped += 1
            self.logger.warning("Queue for %s is full, dropping a %s", self.circuit, type(item).__name__)

    async def send(self, data: bytes, **overrides) -> None:
        """Send an SDU."""
        await self.send_pdu(Pdu.from_sdu(data, **overrides))

    async def send_pdu(self, pdu: Pdu, **overrides) -> None:
        """Sends a CPCS-PDU."""
        await self.connection.send(pdu.segments(self.circuit, **overrides))

    async def recv_pdu(self, timeout: float | None = None) -> Pdu:
        """Waits for the next PDU."""
        return await self.connection.wait_for(self.pdus, timeout)

    async def recv(self, timeout: float | None = None) -> bytes:
        """Waits for the next valid SDU."""
        while True:
            pdu = await self.recv_pdu(timeout)
            if pdu.ok:
                return pdu.data
            self.logger.warning("Discarding PDU on %s: %s", self.circuit, pdu.error)

    async def send_oam(self, cell: OamCell, *, pti: Pti = Pti.END_TO_END_OAM_F5) -> None:
        await self.connection.send([Cell(cell.to_bytes(), self.circuit, pti)])

    async def recv_oam(self, timeout: float | None = None) -> OamCell:
        return await self.connection.wait_for(self.oam, timeout)

    def drain_oam(self) -> None:
        """Drains all received OAM cells"""
        while not self.oam.empty():
            self.oam.get_nowait()

    def __str__(self) -> str:
        return str(self.circuit)


class AtmConnection:
    """Link to the DSLAM"""

    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        address: AtmAddress,
        *,
        logger: logging.LoggerAdapter | None = None,
    ):
        self.reader, self.writer, self.address = reader, writer, address
        self.logger = logger if logger is not None else DEFAULT_LOGGER
        self.circuits: dict[VirtualCircuit, Circuit] = {}
        self.dropped = 0
        self.closed = asyncio.Event()
        self._failure: BaseException | None = None
        self._lock = asyncio.Lock()
        self._pump = asyncio.create_task(self._receive(), name="patmy-receive")

    @classmethod
    async def connect(
        cls,
        host: str | None = None,
        port: int | None = None,
        *,
        socket: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None,
        timeout: float = CONNECT_TIMEOUT,
        logger: logging.LoggerAdapter | None = None,
    ) -> AtmConnection:
        if host is not None and port is not None and socket is None:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
        elif host is None and port is None and socket is not None:
            reader, writer = socket
        else:
            raise Exception("connect needs either host and port or socket")

        try:
            raw = await asyncio.wait_for(reader.readexactly(ATM_ADDRESS_SIZE), timeout)
        except BaseException:
            writer.close()
            raise
        address = AtmAddress.from_bytes(raw)
        connection = cls(reader, writer, address, logger=logger)
        connection.logger.info("Connected and assigned %s", address)
        return connection

    async def _receive(self) -> None:
        try:
            while True:
                cell = Cell.from_bytes(await self.reader.readexactly(ATM_CELL_SIZE))
                target = self.circuits.get(cell.circuit)
                if not cell.hec_valid or target is None:
                    self.dropped += 1
                    reason = "bad HEC" if not cell.hec_valid else "circuit not open"
                    self.logger.debug("Dropping cell on %s (%s)", cell.circuit, reason)
                    continue
                target.feed(cell)
        except asyncio.IncompleteReadError:
            self._fail(ConnectionLost("The DSLAM closed the connection"))
        except asyncio.CancelledError:
            self._fail(ConnectionLost("The connection was closed locally"))
            raise
        except Exception as error:
            self.logger.exception("Receive task failed")
            self._fail(error)

    def _fail(self, error: BaseException) -> None:
        self._failure = self._failure or error
        self.closed.set()

    def _check_alive(self) -> None:
        if self.closed.is_set():
            raise self._failure or ConnectionLost("The connection is closed")

    async def wait_for(self, queue: asyncio.Queue, timeout: float | None = None) -> typing.Any:
        """Waits for a queue item or the link dropping"""
        self._check_alive()
        item = asyncio.ensure_future(queue.get())
        shutdown = asyncio.ensure_future(self.closed.wait())
        try:
            done, _ = await asyncio.wait((item, shutdown), timeout=timeout, return_when=asyncio.FIRST_COMPLETED)
            if item in done:
                return item.result()
            self._check_alive()
            raise TimeoutError(f"Nothing received within {timeout} seconds")
        finally:
            item.cancel()
            shutdown.cancel()

    def open(self, circuit: VirtualCircuit) -> Circuit:
        if circuit in self.circuits:
            raise ValueError(f"Circuit {circuit} is already open")
        self.circuits[circuit] = Circuit(self, circuit)
        return self.circuits[circuit]

    def close(self, circuit: VirtualCircuit) -> None:
        self.circuits.pop(circuit, None)

    async def send(self, cells: collections.abc.Iterable[Cell]) -> None:
        """Writes multiple cells at once"""
        payload = b"".join(cell.to_bytes() for cell in cells)
        async with self._lock:
            self._check_alive()
            self.writer.write(payload)
            await self.writer.drain()

    async def aclose(self) -> None:
        self._fail(ConnectionLost("The connection was closed locally"))
        self._pump.cancel()
        try:
            await self._pump
        except asyncio.CancelledError:
            # If this was targeted _at us_, we have to reraise
            if (task := asyncio.current_task()) is not None and task.cancelling():
                raise
        finally:
            self.writer.close()
        with contextlib.suppress(Exception):
            await self.writer.wait_closed()


class Signalling:
    """The call-setup state machine"""

    # This is already bad enough. Now you see why we did not want to implement SSCOP.

    def __init__(self, connection: AtmConnection, *, rng: random.Random | None = None, auto_accept: bool = True):
        self.connection = connection
        self.logger = connection.logger
        self.auto_accept = auto_accept
        self.circuit = connection.open(VirtualCircuit.SIGNALLING)
        self.incoming: asyncio.Queue[tuple[AtmAddress, Circuit]] = asyncio.Queue(QUEUE_SIZE)
        self._waiters: dict[int, asyncio.Future[Message]] = {}
        self._last_id = (rng if rng is not None else random).randrange(2**32)
        self._task = asyncio.create_task(self._run(), name="patmy-signalling")

    def _next_id(self) -> int:
        self._last_id = (self._last_id + 1) % 2**32
        return self._last_id

    async def _run(self) -> None:
        try:
            while True:
                try:
                    message = Message.from_bytes(await self.circuit.recv())
                except ValueError as error:
                    self.logger.warning("Discarding malformed signalling message: %s", error)
                    continue
                self.logger.debug("Received %s", message)
                await self._dispatch(message)
        except (ConnectionLost, asyncio.CancelledError):
            for waiter in self._waiters.values():
                if not waiter.done():
                    waiter.set_exception(ConnectionLost("The connection closed"))
            self._waiters.clear()
            raise

    async def _dispatch(self, message: Message) -> None:
        if message.type is MessageType.ESTABLISH:
            assert message.circuit is not None
            if not self.auto_accept:
                await self.send(Message(MessageType.NOT_PERMITTED, message.id))
                return
            # ESTABLISH for a open circuit is a retransmission, just confirm again
            if message.circuit not in self.connection.circuits:
                opened = self.connection.open(message.circuit)
                caller = message.address or AtmAddress(bytes(8))
                with contextlib.suppress(asyncio.QueueFull):
                    self.incoming.put_nowait((caller, opened))
            await self.send(Message(MessageType.ESTABLISHED, message.id))
        elif message.type is MessageType.RELEASE:
            assert message.circuit is not None
            self.connection.close(message.circuit)
            await self.send(Message(MessageType.RELEASED, message.id))
        elif (waiter := self._waiters.pop(message.id, None)) and not waiter.done():
            waiter.set_result(message)
        else:
            self.logger.debug("Ignoring unexpected signalling message: %s", message)

    async def send(self, message: Message) -> None:
        self.logger.debug("Sending %s", message)
        await self.circuit.send(message.to_bytes())

    async def transact(
        self,
        message: Message,
        expect: MessageType,
        *,
        timeout: float = SIGNALLING_TIMEOUT,
        retries: int = SIGNALLING_RETRIES,
    ) -> Message:
        """Sends a signalling message and waits for a reply"""
        waiter: asyncio.Future[Message] = asyncio.get_running_loop().create_future()
        self._waiters[message.id] = waiter
        try:
            for attempt in range(retries + 1):
                await self.send(message)
                try:
                    reply = await asyncio.wait_for(asyncio.shield(waiter), timeout)
                except TimeoutError:
                    self.logger.debug("No reply to %s (attempt %d/%d)", message.type.name, attempt + 1, retries + 1)
                    continue
                if reply.type is expect:
                    return reply
                if reply.type.is_error:
                    raise CallFailed(reply.type)
                raise CallFailed(MessageType.GENERIC_ERROR, f"Expected {expect.name} but got {reply.type.name}")
            raise TimeoutError(f"No reply to {message.type.name}")
        finally:
            self._waiters.pop(message.id, None)

    async def establish(self, address: AtmAddress, circuit: VirtualCircuit, **kwargs) -> None:
        message = Message(MessageType.ESTABLISH, self._next_id(), address, circuit)
        await self.transact(message, MessageType.ESTABLISHED, **kwargs)

    async def release(self, circuit: VirtualCircuit, **kwargs) -> None:
        message = Message(MessageType.RELEASE, self._next_id(), circuit=circuit)
        await self.transact(message, MessageType.RELEASED, **kwargs)

    async def aclose(self) -> None:
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            # If this was targeted _at us_, we have to reraise
            if (task := asyncio.current_task()) is not None and task.cancelling():
                raise
        except ConnectionLost:
            # We just disconnected, so this is fine
            pass
        except Exception:
            # The signalling task died on its own
            self.logger.warning("Signalling task failed unexpectedly", exc_info=True)


class AtmClient:
    """The ATM client that reads/writes cells in an ADSL setup"""

    def __init__(self, connection: AtmConnection, *, rng: random.Random | None = None, **kwargs):
        self.connection = connection
        self.logger = connection.logger
        self.rng = rng
        self.signalling = Signalling(connection, rng=rng, **kwargs)

    @classmethod
    async def connect(
        cls,
        host: str | None = None,
        port: int | None = None,
        *,
        socket: tuple[asyncio.StreamReader, asyncio.StreamWriter] | None = None,
        timeout: float = CONNECT_TIMEOUT,
        logger: logging.LoggerAdapter | None = None,
        **kwargs,
    ) -> AtmClient:
        return cls(await AtmConnection.connect(host, port, socket=socket, timeout=timeout, logger=logger), **kwargs)

    @property
    def address(self) -> AtmAddress:
        """This is the AESA that the DSLAM assigned to this connection"""
        return self.connection.address

    def free_circuit(self, attempts: int = 96) -> VirtualCircuit:
        """Picks a circuit that is neither reserved nor already in use"""
        rng = self.rng if self.rng is not None else random
        for _ in range(attempts):
            candidate = VirtualCircuit(rng.randrange(0x100), rng.randrange(MIN_ALLOCATED_VCI, 0x10000))
            if candidate not in self.connection.circuits:
                return candidate
        raise RuntimeError(f"No free circuit found in {attempts} attempts")

    async def call(self, number: str | AtmAddress, *, circuit: VirtualCircuit | None = None, **kwargs) -> Circuit:
        """Places a call and returns its circuit"""
        address = AtmAddress.from_number(number) if isinstance(number, str) else number
        vc = circuit if circuit is not None else self.free_circuit()
        if vc.is_reserved:
            raise ValueError(f"Circuit {vc} is reserved")

        opened = self.connection.open(vc)
        try:
            await self.signalling.establish(address, vc, **kwargs)
        except BaseException:
            self.connection.close(vc)
            raise
        self.logger.info("Call to %s is on %s", address, vc)
        return opened

    @contextlib.asynccontextmanager
    async def calling(self, number: str | AtmAddress, **kwargs) -> collections.abc.AsyncGenerator[Circuit]:
        """Context manager that places a call on enter and hangs up on exit"""
        circuit = await self.call(number, **kwargs)
        try:
            yield circuit
        finally:
            # Suppress teardown errors. We want to keep the original error here.
            with contextlib.suppress(ConnectionLost, TimeoutError, CallFailed):
                await self.hangup(circuit)

    async def accept(self, timeout: float | None = None) -> tuple[AtmAddress, Circuit]:
        """Waits for an inbound call, then returns the caller and its circuit"""
        return await self.connection.wait_for(self.signalling.incoming, timeout)

    async def hangup(self, circuit: Circuit | VirtualCircuit, **kwargs) -> None:
        vc = circuit.circuit if isinstance(circuit, Circuit) else circuit
        try:
            await self.signalling.release(vc, **kwargs)
        finally:
            self.connection.close(vc)

    async def aclose(self) -> None:
        try:
            await self.signalling.aclose()
        finally:
            await self.connection.aclose()

    async def __aenter__(self) -> typing.Self:
        return self

    async def __aexit__(self, *_) -> None:
        await self.aclose()
