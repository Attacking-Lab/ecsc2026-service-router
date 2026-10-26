#!/usr/bin/env python3
"""Strip the app symbols out of a Zephyr binary."""

import argparse
import pathlib
import shutil
import subprocess
import tempfile


def run(*command):
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


def defined_symbols(nm, *objects):
    return set(run(nm, "--defined-only", "--format=just-symbols", *objects).split())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nm", required=True)
    parser.add_argument("--ar", required=True)
    parser.add_argument("--objcopy", required=True)
    parser.add_argument("--build-dir", required=True, type=pathlib.Path)
    parser.add_argument("--app-lib", required=True, type=pathlib.Path)
    parser.add_argument("--debug-copy", required=True, type=pathlib.Path)
    parser.add_argument("elf", type=pathlib.Path)
    args = parser.parse_args()

    ours = args.app_lib.name, f"{args.app_lib.stem}-nodwarf{args.app_lib.suffix}"
    zephyr_libs = [str(lib) for lib in args.build_dir.rglob("*.a") if lib.name not in ours]

    symbols = defined_symbols(args.nm, str(args.app_lib)) - defined_symbols(args.nm, *zephyr_libs)
    # Our objects lost their STT_FILE symbol to --strip-debug, so ld synthesized
    # a replacement from the archive member name (aal5.c.obj). Zephyr's own file
    # symbols keep their unsuffixed names (mutex.c) and are not affected.
    symbols |= set(run(args.ar, "t", str(args.app_lib)).split())

    if not symbols & defined_symbols(args.nm, str(args.elf)):
        return  # Already stripped

    shutil.copy(args.elf, args.debug_copy)
    with tempfile.NamedTemporaryFile("w", suffix=".txt") as symbol_list:
        symbol_list.write("".join(f"{symbol}\n" for symbol in sorted(symbols)))
        symbol_list.flush()
        run(args.objcopy, f"--strip-symbols={symbol_list.name}", str(args.elf))
    args.debug_copy.touch()  # Make this is newer than the ELF from which is "generated"
    print(f"Stripped {len(symbols)} application symbols from {args.elf}")


if __name__ == "__main__":
    main()
