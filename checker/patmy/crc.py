import typing


class CRC:
    def __init__(self, polynomial: int, width: int, initial: int, coset: int):
        assert width >= 8, "Small-width CRCs not supported"
        self.polynomial = polynomial
        self.width = width
        self.initial = initial
        self.coset = coset

        self.table = []
        top, mask = 1 << (width - 1), (1 << width) - 1
        for byte in range(256):
            register = byte << (width - 8)
            for _ in range(8):
                register = ((register << 1) & mask) ^ (polynomial if register & top else 0)
            self.table.append(register)

    def update(self, value: int, data: bytes) -> int:
        mask = (1 << self.width) - 1
        for byte in data:
            value = self.table[(value >> (self.width - 8)) ^ byte] ^ ((value << 8) & mask)
        return value

    def update_bit(self, value: int, bit: int) -> int:
        feedback = (value >> (self.width - 1)) ^ (1 if bit else 0)
        value = ((value << 1) & ((1 << self.width) - 1)) ^ (self.polynomial if feedback else 0)
        return value

    def compute(self, data: bytes, *, additional_bits: typing.Iterable[int] = ()) -> int:
        value = self.update(self.initial, data)
        for bit in additional_bits:
            value = self.update_bit(value, bit)
        return value ^ self.coset

    def __call__(self, data: bytes, *, additional_bits: typing.Iterable[int] = ()) -> int:
        return self.compute(data, additional_bits=additional_bits)


# Core checksums
atm_hec = CRC(0x07, 8, 0, 0x55)  # ITU-T I.432.1 (§ 7.3.2.2)
aal5_crc = CRC(0x04C11DB7, 32, 0xFFFFFFFF, 0xFFFFFFFF)  # ITU-T I.363.5 (§ 9.2.1.2)
oam_edc = CRC(0x233, 10, 0, 0)  # ITU-T I.610 (§ 10.1)
