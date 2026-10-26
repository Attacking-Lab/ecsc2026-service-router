"""A (much!) simplified DSLAM for local testing."""

# Run this with `python -m mindslam`.
# Use DSLAM_ADDRESS to send a router instance to this DSLAM.
# For the patmy client, you can use `--dslam-host`.
#
# It behaves much like the real DSLAM, but does not have timeouts, retransmissions,
# rate limits, call permissions, or numbering plan support.
# The first connection gets the fixed number configured on the command line,
# the rest just gets +49 14 6464 000000 and upwards.

from __future__ import annotations

import argparse
import asyncio
import dataclasses
import itertools
import logging
import random

from patmy.aal5 import Pdu, Reassembler
from patmy.address import AtmAddress
from patmy.atm import ATM_CELL_SIZE, Cell, Pti, VirtualCircuit
from patmy.signalling import Message, MessageType

logger = logging.getLogger("mindslam")


@dataclasses.dataclass
class Call:
    peer: Connection
    peer_circuit: VirtualCircuit  # The circuit on the peer's connection
    id: int  # The ESTABLISH transaction ID on this connection
    incoming: bool
    connected: bool = False


@dataclasses.dataclass(eq=False)
class Connection:
    """A subscriber's line/connection"""

    writer: asyncio.StreamWriter  # TCP writer
    address: AtmAddress  # Subscriber address
    calls: dict[VirtualCircuit, Call] = dataclasses.field(default_factory=dict)
    ids: itertools.count = dataclasses.field(default_factory=itertools.count)

    def write(self, data: bytes) -> None:
        if not self.writer.is_closing():
            self.writer.write(data)

    def signal(self, type: MessageType, id: int, **fields) -> None:
        message = Message(type, id, **fields)
        logger.debug(f"-> {self}: {message}")
        for cell in Pdu.from_sdu(message.to_bytes()).segments(VirtualCircuit.SIGNALLING):
            self.write(cell.to_bytes())

    def __str__(self) -> str:
        return str(self.address)


class Dslam:
    def __init__(self, fixed: AtmAddress) -> None:
        self.fixed = fixed
        self.numbers = itertools.count(1)
        self.connections: dict[AtmAddress, Connection] = {}

    def assign_address(self) -> AtmAddress:
        if self.fixed not in self.connections:
            return self.fixed
        return AtmAddress.from_number(f"+49 14 6464 {next(self.numbers):06}")

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connection = Connection(writer, self.assign_address())
        self.connections[connection.address] = connection
        logger.info(f"{connection} connected from {writer.get_extra_info('peername')}")
        connection.write(connection.address.to_bytes())
        reassembler = Reassembler()
        try:
            while True:
                # Grab a cell
                cell = Cell.from_bytes(await reader.readexactly(ATM_CELL_SIZE))
                if not cell.hec_valid or cell.pti in (
                    Pti.SEGMENT_OAM_F5,
                    Pti.RESOURCE_MANAGEMENT,
                    Pti.RESERVED,
                ):
                    continue
                if cell.circuit == VirtualCircuit.SIGNALLING:
                    # Signaling cells are AAL5
                    if (pdu := reassembler.push(cell)) is None or not pdu.ok:
                        continue
                    try:
                        message = Message.from_bytes(pdu.data)
                    except ValueError as error:
                        logger.debug(f"<- {connection}: invalid signalling ({error})")
                        continue
                    logger.debug(f"<- {connection}: {message}")
                    self.dispatch(connection, message)
                elif (call := connection.calls.get(cell.circuit)) is not None and call.connected:
                    # Data cell for a connected call
                    call.peer.write(dataclasses.replace(cell, circuit=call.peer_circuit, hec=None).to_bytes())
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            logger.info(f"{connection} disconnected")
            del self.connections[connection.address]
            for circuit in list(connection.calls):
                self.hang_up(connection, circuit)
            writer.close()

    def dispatch(self, connection: Connection, message: Message) -> None:
        match message.type:
            case MessageType.ESTABLISH:
                self.establish(connection, message)
            case MessageType.ESTABLISHED:
                self.answer(connection, message.id, None)
            case MessageType.RELEASE:
                assert message.circuit is not None
                self.hang_up(connection, message.circuit)
                connection.signal(MessageType.RELEASED, message.id)
            case MessageType.RELEASED:
                pass  # We never wait for these
            case error:
                self.answer(connection, message.id, error)

    def establish(self, caller: Connection, message: Message) -> None:
        """The caller wants to establish a call"""
        assert message.address is not None and message.circuit is not None
        circuit = message.circuit
        if (existing := caller.calls.get(circuit)) is not None and not existing.connected:
            return  # A retransmission (the callee has not answered yet)
        if existing is not None or circuit.is_reserved:
            # The real DSLAM will replace circuits if the caller reuses the circuit ID.
            # We don't do that here, that would be too much code.
            return caller.signal(MessageType.REJECTED_CIRCUIT, message.id)
        if (callee := self.connections.get(message.address)) is None:
            return caller.signal(MessageType.UNREACHABLE, message.id)

        # Make sure to not reuse the caller's circuit if someone is calling themselves (why would you do that though?)
        callee_circuit = circuit
        while callee_circuit == circuit or callee_circuit.is_reserved or callee_circuit in callee.calls:
            callee_circuit = VirtualCircuit(random.randrange(0x100), random.randrange(0x10000))

        id = next(callee.ids)
        caller.calls[circuit] = Call(callee, callee_circuit, message.id, incoming=False)
        callee.calls[callee_circuit] = Call(caller, circuit, id, incoming=True)
        callee.signal(MessageType.ESTABLISH, id, address=caller.address, circuit=callee_circuit)
        logger.info(f"{caller} ({circuit}) is calling {callee} ({callee_circuit})")

    def answer(self, callee: Connection, id: int, error: MessageType | None) -> None:
        """The callee accepted an incoming call or rejected it with an error"""
        waiting = (c for c, call in callee.calls.items() if call.incoming and not call.connected and call.id == id)
        if (circuit := next(waiting, None)) is None:
            return
        call = callee.calls[circuit]
        caller, caller_call = call.peer, call.peer.calls[call.peer_circuit]
        if error is None:
            call.connected = caller_call.connected = True
            caller.signal(MessageType.ESTABLISHED, caller_call.id)
            logger.info(f"{caller} ({call.peer_circuit}) and {callee} ({circuit}) are connected")
        else:
            del callee.calls[circuit], caller.calls[call.peer_circuit]
            caller.signal(error, caller_call.id)
            logger.info(f"{callee} rejected the call from {caller}: {error.name}")

    def hang_up(self, connection: Connection, circuit: VirtualCircuit) -> None:
        """Ends the call on this circuit and tells the other end"""
        if (call := connection.calls.pop(circuit, None)) is None:
            return
        peer_call = call.peer.calls.pop(call.peer_circuit)
        if peer_call.connected or peer_call.incoming:
            call.peer.signal(MessageType.RELEASE, next(call.peer.ids), circuit=call.peer_circuit)
        else:
            # The caller is still waiting for an answer
            call.peer.signal(MessageType.UNREACHABLE, peer_call.id)
        logger.info(f"Call between {connection} ({circuit}) and {call.peer} ({call.peer_circuit}) is gone")


async def main() -> None:
    parser = argparse.ArgumentParser(description="A (much!) simplified DSLAM for local testing")
    parser.add_argument("--host", default="0.0.0.0", help="Listening address")
    parser.add_argument("--port", type=int, default=9000, help="Listening port")
    parser.add_argument(
        "--number",
        default="+49 12 667",
        help="Number for the first subscriber (the router)",
    )
    parser.add_argument("--verbose", "-v", action="store_true", help="Log every signalling message")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="[%(name)s] %(message)s",
    )
    dslam = Dslam(AtmAddress.from_number(args.number))
    server = await asyncio.start_server(dslam.handle, args.host, args.port)
    logger.info(f"Listening on {args.host}:{args.port}")
    async with server:
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
