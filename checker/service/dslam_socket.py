import asyncio
import contextlib
import logging
import time
import traceback
import typing

from enochecker3 import (
    Enochecker,
    OfflineException,
    TaskMetadata,
    flows,
    enochecker,
)

from patmy import AtmClient

def register_dslam_socket(checker: Enochecker, dslam_host: str, dslam_port: int):

    # copied from enochecker3, modified to use DSLAM address and return AtmClient
    @checker.register_dependency
    @contextlib.asynccontextmanager
    async def get_dslam_socket(
        logger: logging.LoggerAdapter,  # type: ignore[type-arg]
        metadata: TaskMetadata,
    ) -> AtmClient:
        """
        Provide a raw TCP socket connection to the service.

        Injectable as: socket: AsyncSocket (note: this is an async context manager)

        Returns a tuple of (StreamReader, StreamWriter) for low-level protocol interaction.
        The connection is automatically closed when the checker method completes.

        The connection is recorded in metadata["flows"] (5-tuple plus open/close
        timestamps).

        In HAProxy mode (see ENOCHECKER_HAPROXY_MODE), an EOFError raised while
        the checker was reading from a connection that never received any bytes
        from the other side is reported as OfflineException instead of the usual
        MumbleException: behind an HAProxy-style router the TCP connection to the
        router itself always succeeds, so a down backend that the router drops
        without forwarding anything would otherwise look like a checker-side
        protocol error rather than the OfflineException it actually is.

        Example:
            async def my_checker(socket: AsyncSocket):
                reader, writer = socket
                writer.write(b"HELLO\\n")
                response = await reader.readline()
        """
        start = time.time()
        try:
            conn = await asyncio.streams.open_connection(
                dslam_host, int(dslam_port)
            )
        except:
            trace = traceback.format_exc()
            logger.info(f"Failed to connect to service\n{trace}")
            raise OfflineException("Could not establish socket connection to service")
        flow = flows.record_flow(
            metadata,
            "tcp",
            conn[1].get_extra_info("sockname"),
            conn[1].get_extra_info("peername"),
            start,
        )

        reader = conn[0]
        received_data = False
        orig_feed_data = reader.feed_data

        def _feed_data(data: typing.Iterable[typing.SupportsIndex]) -> None:
            nonlocal received_data
            if data:
                received_data = True
                metadata.received_upstream_data = True
            orig_feed_data(data)

        reader.feed_data = _feed_data  # type: ignore[method-assign]  # ty: ignore[invalid-assignment]

        try:
            yield await AtmClient.connect(socket=conn, logger=logger)
        except EOFError as e:
            if enochecker._haproxy_mode_enabled() and not received_data:
                raise OfflineException(
                    "Connection to service closed before sending any data"
                ) from e
            raise
        finally:
            # Ensure the socket is properly closed even if the checker crashes
            conn[1].close()
            await conn[1].wait_closed()
            flows.close_flow(flow)
