from __future__ import annotations

import argparse
import asyncio
import secrets
import sys
import typing

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .client import AtmClient, Circuit
from .coap import CoapClient, CoapCode, ContentFormat, Option, OptionNumber
from .oam import OamCell, OamType


async def settings_put_action(args: argparse.Namespace, circuit: Circuit):
    handle = secrets.token_bytes(8)
    value = args.value.encode()
    coap = CoapClient.over(circuit)

    claim = await coap.post(
        ["store", args.key],
        handle,
        content_format=ContentFormat.OCTET_STREAM,
    )
    if claim.code == CoapCode.FORBIDDEN:
        raise KeyError(f"{args.key} is already configured")
    if claim.code != CoapCode.CREATED:
        raise RuntimeError(f"Unexpected {claim.code_name} when storing {args.key}")

    store = await coap.put(
        ["store", args.key],
        value,
        content_format=ContentFormat.OCTET_STREAM,
        options=[Option(OptionNumber.IF_MATCH, handle)],
    )
    if store.code != CoapCode.CHANGED:
        raise RuntimeError(f"Unexpected {store.code_name} when storing {args.key}")

    print(f"Successfully stored {args.key}")
    print(f"Handle for retrieval is {handle.hex()}")


async def settings_get_action(args: argparse.Namespace, circuit: Circuit):
    if len(args.handle) != 8:
        raise ValueError(f"Invalid handle (must be 8 bytes): {args.handle!r}")

    coap = CoapClient.over(circuit)
    response = await coap.post(
        ["store", args.key],
        args.handle,
        options=[Option(OptionNumber.IF_MATCH, args.handle)],
    )
    if response.code == CoapCode.NOT_FOUND:
        raise KeyError(f"{args.key!r} is not configured")
    if response.code != CoapCode.CONTENT:
        raise RuntimeError(f"Unexpected {response.code_name} when retrieving {args.key!r}")
    if response.content_format not in (None, ContentFormat.OCTET_STREAM):
        raise RuntimeError(f"Unexpected content format {response.content_format} when retrieving {args.key!r}")

    print(f"{args.key} is {response.payload!r}")


SECRET_DATA_LENGTH = 38
SECRET_ID_LENGTH = 4
SECRET_KEY_LENGTH = 16
SECRET_MAC_LENGTH = 7
SECRET_OP_PUT = 0
SECRET_OP_GET = 1
SECRET_RESPONSE = 8


async def secrets_oam_wait(circuit: Circuit, function: int, timeout: float | None = None):
    loop = asyncio.get_running_loop()
    deadline = (loop.time() + timeout) if timeout is not None else None
    while True:
        if deadline is not None:
            remaining = deadline - loop.time()
            if remaining <= 0:
                raise TimeoutError("Timed out waiting for a response")
        else:
            remaining = None

        response = await circuit.recv_oam(remaining)
        if response.oam_type != OamType.SYSTEM_MANAGEMENT:
            continue
        if response.function != function | SECRET_RESPONSE:
            continue
        return response


async def secrets_put_action(args: argparse.Namespace, circuit: Circuit):
    body = args.value.encode().ljust(SECRET_DATA_LENGTH, b"\x00")
    if len(body) > SECRET_DATA_LENGTH:
        raise ValueError("Secret is too long to store here")
    cell = OamCell(OamType.SYSTEM_MANAGEMENT, SECRET_OP_PUT, body)

    circuit.drain_oam()
    await circuit.send_oam(cell)

    response = await secrets_oam_wait(circuit, cell.function, args.timeout)
    if not response.edc_valid:
        raise ValueError("Corrupted response")

    secret_id = response.body[:SECRET_ID_LENGTH]
    secret_key = response.body[SECRET_ID_LENGTH:][:SECRET_KEY_LENGTH]
    print(f"ID for stored secret:  {secret_id.hex()}")
    print(f"Key for stored secret: {secret_key.hex()}")


async def secrets_get_action(args: argparse.Namespace, circuit: Circuit):
    nonce = args.nonce if args.nonce is not None else secrets.token_bytes(SECRET_DATA_LENGTH)
    if len(args.id) != SECRET_ID_LENGTH:
        raise ValueError("Invalid secret ID (must be 4 bytes)")
    if len(args.key) != SECRET_KEY_LENGTH:
        raise ValueError("Invalid secret key (must be 16 bytes)")
    if len(nonce) > SECRET_DATA_LENGTH:
        raise ValueError("Nonce is too long")
    cell = OamCell(OamType.SYSTEM_MANAGEMENT, SECRET_OP_GET, args.id + bytes([len(nonce)]) + nonce)

    circuit.drain_oam()
    await circuit.send_oam(cell)

    response = await secrets_oam_wait(circuit, cell.function, args.timeout)
    if not response.edc_valid:
        raise ValueError("Corrupted response")

    secret_ct = response.body[:SECRET_DATA_LENGTH]
    secret_mac = response.body[SECRET_DATA_LENGTH:][:SECRET_MAC_LENGTH]

    aes = algorithms.AES(args.key)
    mac = cmac.CMAC(aes)
    mac.update(secret_ct + nonce)
    if mac.finalize()[:SECRET_MAC_LENGTH] != secret_mac:
        raise ValueError("Invalid MAC")

    dec = Cipher(aes, modes.CTR(args.id.ljust(16, b"\0"))).decryptor()
    secret_plain = dec.update(secret_ct) + dec.finalize()

    print(f"Stored secret: {secret_plain.decode()}")


async def main(args: argparse.Namespace):
    client = await AtmClient.connect(args.dslam_host, args.dslam_port)
    async with client.calling(args.number) as circuit:
        await args.action(args, circuit)


def parse_arguments():
    # Try to be helpful if Python is new enough
    kwargs: dict[typing.Any, typing.Any] = {"suggest_on_error": True} if sys.version_info >= (3, 14) else {}

    # Argument parser
    parser = argparse.ArgumentParser(description="Router client", **kwargs)

    # Connection information. Try "+49 12 667" or check the numbering plan.
    parser.add_argument("number", type=str, help="Phone number to dial (see numbering plan, or try +49 12 667)")

    # Game network settings
    parser.add_argument("--dslam-host", type=str, default="10.60.249.53", help="DSLAM TCP address")
    parser.add_argument("--dslam-port", type=int, default=9000, help="DSLAM TCP port")

    # Subcommands
    subparsers = parser.add_subparsers(required=True)
    settings = subparsers.add_parser("settings", help="Configure router settings").add_subparsers(required=True)
    settings_put = settings.add_parser("put", help="Set a router setting")
    settings_get = settings.add_parser("get", help="Retrieve a router setting")

    settings_put.add_argument("key", help="The settings key")
    settings_put.add_argument("value", help="The value to set")
    settings_put.set_defaults(action=settings_put_action)

    settings_get.add_argument("key", help="The settings key")
    settings_get.add_argument("handle", help="Handle for that key", type=bytes.fromhex)
    settings_get.set_defaults(action=settings_get_action)

    secrets_args = subparsers.add_parser("secrets", help="Store router secrets")
    secrets_args.add_argument("--timeout", help="Response timeout in seconds", type=float)

    secrets = secrets_args.add_subparsers(required=True)
    secrets_put = secrets.add_parser("put", help="Store a router secret")
    secrets_get = secrets.add_parser("get", help="Retrieve a router secret")

    secrets_put.add_argument("value", help="The secret to store")
    secrets_put.set_defaults(action=secrets_put_action)

    secrets_get.add_argument("id", help="Secret ID to retrieve", type=bytes.fromhex)
    secrets_get.add_argument("key", help="Secret key for that secret", type=bytes.fromhex)
    secrets_get.add_argument("--nonce", help="Nonce for integrity check", type=bytes.fromhex)
    secrets_get.set_defaults(action=secrets_get_action)

    return parser.parse_args()


if __name__ == "__main__":
    asyncio.run(main(parse_arguments()))
