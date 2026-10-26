#!/usr/bin/env python3

# Stops a zero-length If-Match from bypassing authentication

import argparse
import pathlib

from elftools.elf.elffile import ELFFile

from xtensa import Image


# struct coap_option is { uint16_t delta; uint8_t len; uint8_t value[]; }
# (CONFIG_COAP_EXTENDED_OPTIONS_LEN is off)
OPTION_LEN_OFFSET = 2
HANDLE_SIZE = 8

# How large of an area to scan in the binary
WINDOW = 6


def encode_nop(register: int) -> bytes:
    """Encodes `mov.n aN, aN`"""
    return bytes([(register << 4) | 0x0d, register])


def loads_option_len(insn, register: str) -> bool:
    """Finds `l8ui aN, _, 2` (match->len)"""
    return (
        insn.mnemonic == "l8ui"
        and insn.operands.split(", ")[0] == register
        and int(insn.operands.split(", ")[-1], 0) == OPTION_LEN_OFFSET
    )


def tests_handle_size(insn, register: str) -> bool:
    """Finds `bnei aN, 8, deny` (the correct length check)"""
    return (
        insn.mnemonic == "bnei"
        and insn.operands.split(", ")[0] == register
        and int(insn.operands.split(", ")[1], 0) == HANDLE_SIZE
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("elf", type=pathlib.Path)
    args = parser.parse_args()

    with args.elf.open("r+b") as handle:
        image = Image(ELFFile(handle))
        coap_service_handle = image.symbol("coap_service_handle")

        # Handle non-inlined handle_matches() also
        matchers = [coap_service_handle]
        try:
            matchers.insert(0, image.symbol("handle_matches"))
        except LookupError:
            pass

        # Drop the beqz.n that does the authentication bypass
        targets = []
        for start, end in matchers:
            insns = list(image.disassemble(start, end))
            for index, insn in enumerate(insns):
                if insn.mnemonic != "beqz.n":
                    continue
                register = insn.operands.split(", ")[0]
                before = insns[max(index - WINDOW, 0):index]
                after = insns[index + 1:index + 1 + WINDOW]
                if not any(loads_option_len(other, register) for other in before):
                    continue
                if not any(tests_handle_size(other, register) for other in after):
                    continue
                targets.append(insn)

        if len(targets) != 1:
            raise LookupError(f"Found {len(targets)} If-Match length checks in the handle comparison")

        insn = targets[0]
        raw = encode_nop(int(insn.operands.split(", ")[0].removeprefix("a")))
        assert len(raw) == len(insn.raw), "the replacement has to be the same size"
        handle.seek(image.offset(insn.address, len(raw)))
        handle.write(raw)
