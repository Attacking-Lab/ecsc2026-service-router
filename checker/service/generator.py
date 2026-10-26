import random
import secrets
from string import ascii_letters, ascii_lowercase, digits, hexdigits

from . import coap_store, f5, suspicious


def random_bytes(min_length: int, max_length: int, rng: random.Random) -> bytes:
    return rng.randbytes(rng.randint(min_length, max_length))


def hex_bytes(min_length: int, max_length: int, rng: random.Random) -> bytes:
    return bytes(rng.choices(hexdigits.encode(), k=rng.randint(min_length, max_length)))


def alphanumeric_bytes(min_length: int, max_length: int, rng: random.Random) -> bytes:
    return bytes(rng.choices((ascii_letters + digits).encode(), k=rng.randint(min_length, max_length)))


def suspicious_bytes(min_length: int, max_length: int, rng: random.Random) -> bytes:
    # `suspicious.get` filters on the encoded length, but still falls back to an
    # oversized string (with a warning) when nothing is in range, so cap it here.
    return suspicious.get(min_length, max_length, rng).encode()[:max_length]


def any_bytes(min_length: int, max_length: int, rng: random.Random) -> bytes:
    return rng.choices(
        [random_bytes, hex_bytes, alphanumeric_bytes, suspicious_bytes],
        [0.3, 0.3, 0.3, 0.1],
    )[0](min_length, max_length, rng)


def any_f5_data(rng: random.Random, pad_to: int = f5.DATA_SIZE, pad_with: bytes = b"\0") -> bytes:
    return any_bytes(min(pad_to // 2, 8), pad_to, rng).ljust(pad_to, pad_with)


def any_coap_data(rng: random.Random) -> bytes:
    return any_bytes(1, coap_store.VALUE_MAX, rng)


def coap_key(rng: random.Random, length: int = coap_store.KEY_LENGTH) -> str:
    return "".join(rng.choices(ascii_lowercase + digits + "!#$%&'()-@^_`{}~", k=length))


def coap_handle() -> bytes:
    return secrets.token_bytes(coap_store.HANDLE_SIZE)  # No task RNG because this does not need reproducing


def any_nonce(rng: random.Random) -> bytes:
    return rng.randbytes(rng.randint(4, f5.DATA_SIZE))
