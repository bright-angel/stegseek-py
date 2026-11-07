"""Port of ``src/EmbData.cc`` -- steghide's embedded-data container."""

from __future__ import annotations

import os

from .bitstring import BitString
from .const import (
    CODE_VERSION,
    MAGIC,
    NBITS_CRC32,
    NBITS_MAGIC,
    NBITS_NPLAINBITS,
    NBITS_NUNCOMPRESSEDBITS,
)
from .crypto import get_cipher, mhash_crc32
from .errors import CorruptDataError, SteghideError


def _strip_dir(name: bytes) -> bytes:
    pos = max(name.rfind(b"/"), name.rfind(b"\\"))
    return name[pos + 1:] if pos >= 0 else name


class EmbData:
    """The steghide embedded-data state machine (EXTRACT) and writer (EMBED)."""

    def __init__(self, mode: str, passphrase: bytes = b"", filename: bytes = b""):
        self.mode = mode
        self.passphrase = passphrase
        self.filename = filename
        self.version = CODE_VERSION
        self.enc_algo = 0
        self.enc_mode = 0
        self.nplain_bits = 0
        self.compression = 0
        self.checksum = False
        self.crc32 = 0
        self.data = b""

        self.state = "READ_MAGIC" if mode == "extract" else "EMBED"
        self.num_bits_needed = NBITS_MAGIC if mode == "extract" else 0
        self.num_bits_requested = NBITS_MAGIC if mode == "extract" else 0
        self.reservoir = BitString()

    # ------------------------------------------------------------------ EXTRACT
    def finished(self) -> bool:
        return self.state == "END"

    def get_num_bits_requested(self) -> int:
        return self.num_bits_requested

    @staticmethod
    def _bminus(a: int, b: int) -> int:
        return a - b if a > b else 0

    def add_bits(self, addbits: BitString) -> None:
        self.reservoir.append(addbits)
        if self.reservoir.length < self.num_bits_needed:
            raise CorruptDataError("the stego file is too short to contain the embedded data.")
        bits = self.reservoir.cut_bits(0, self.num_bits_needed)

        if self.state == "READ_MAGIC":
            if bits.get_value(0, NBITS_MAGIC) != MAGIC:
                raise SteghideError("could not extract any data with that passphrase!")
            self.num_bits_needed = 1
            self.num_bits_requested = self._bminus(1, self.reservoir.length)
            self.state = "READ_VERSION"

        elif self.state == "READ_VERSION":
            if bits[0]:
                self.version += 1
                self.num_bits_needed = self._bminus(1, self.reservoir.length)
            else:
                if self.version > CODE_VERSION:
                    raise CorruptDataError(
                        "attempting to read an embedding of version %d but steghide 0.5.1 "
                        "only supports embeddings of version %d." % (self.version, CODE_VERSION))
                self.num_bits_needed = 5 + 3
                self.num_bits_requested = self._bminus(8, self.reservoir.length)
                self.state = "READ_ENCINFO"

        elif self.state == "READ_ENCINFO":
            algo = bits.get_value(0, 5)
            if algo < 23:
                self.enc_algo = algo
            mode = bits.get_value(5, 3)
            if mode < 8:
                self.enc_mode = mode
            self.num_bits_needed = NBITS_NPLAINBITS
            self.num_bits_requested = self._bminus(32, self.reservoir.length)
            self.state = "READ_NPLAINBITS"

        elif self.state == "READ_NPLAINBITS":
            self.nplain_bits = bits.get_value(0, NBITS_NPLAINBITS)
            self.num_bits_needed = get_cipher(self.enc_algo, self.enc_mode).encrypted_size(
                self.nplain_bits)
            self.num_bits_requested = self._bminus(self.num_bits_needed, self.reservoir.length)
            self.state = "READ_ENCRYPTED"

        elif self.state == "READ_ENCRYPTED":
            self._parse_plain(bits)
            self.num_bits_needed = 0
            self.num_bits_requested = 0
            self.state = "END"
        else:
            raise AssertionError("bad EmbData state")

    def _parse_plain(self, bits: BitString) -> None:
        if self.enc_algo == 0:
            plain = bits
        else:
            cipher = get_cipher(self.enc_algo, self.enc_mode)
            raw = cipher.decrypt(bytes(bits.data[: bits.length // 8]), self.passphrase)
            plain = BitString(source=raw)
        plain.truncate(0, self.nplain_bits)

        pos = 0
        self.compression = 9 if plain[pos] else 0
        pos += 1
        if self.compression > 0:
            nuncompressed = plain.get_value(pos, NBITS_NUNCOMPRESSEDBITS)
            pos += NBITS_NUNCOMPRESSEDBITS
            plain.truncate(pos, plain.length)
            pos = 0
            plain.uncompress(nuncompressed)

        self.checksum = bool(plain[pos])
        pos += 1
        if self.checksum:
            self.crc32 = plain.get_value(pos, NBITS_CRC32)
            pos += NBITS_CRC32

        name = bytearray()
        while True:
            ch = plain.get_value(pos, 8)
            pos += 8
            if ch == 0:
                break
            name.append(ch)
        self.filename = _strip_dir(bytes(name))

        if (plain.length - pos) % 8:
            raise CorruptDataError("the embedded data has an invalid length.")
        self.data = bytes(plain.get_value(pos + 8 * i, 8) for i in range((plain.length - pos) // 8))

    def checksum_ok(self) -> bool:
        if not self.checksum:
            return True
        return mhash_crc32(self.data) == self.crc32

    # -------------------------------------------------------------------- EMBED
    def set_data(self, data: bytes) -> None:
        self.data = data

    def set_filename(self, filename: bytes) -> None:
        self.filename = _strip_dir(filename)

    def get_bit_string(self) -> BitString:
        compr = BitString()
        compr.append(1 if self.checksum else 0)
        if self.checksum:
            compr.append(mhash_crc32(self.data), NBITS_CRC32)
        compr.append(self.filename)
        compr.append(0, 8)
        compr.append(self.data)

        plain = BitString()
        plain.append(1 if self.compression > 0 else 0)
        if self.compression > 0:
            plain.append(compr.length, NBITS_NUNCOMPRESSEDBITS)
            compr.compress(self.compression)
            plain.append(compr)
        else:
            plain.append(compr)

        main = BitString()
        main.append(MAGIC, NBITS_MAGIC)
        for _ in range(CODE_VERSION):
            main.append(1)
        main.append(0)
        main.append(self.enc_algo, 5)
        main.append(self.enc_mode, 3)
        main.append(plain.length, NBITS_NPLAINBITS)

        if self.enc_algo != 0:
            cipher = get_cipher(self.enc_algo, self.enc_mode)
            block_bits = 8 * cipher.block_size
            # C++ padRandom() adds *individual* random bits.  The plain bit
            # string is not byte aligned (1 compression bit + 32 length bits),
            # so padding a byte at a time would never reach a block boundary.
            while plain.length % block_bits:
                plain.append(os.urandom(1)[0] & 1, 1)
            iv = os.urandom(cipher.iv_size) if cipher.has_iv else b""
            encrypted = cipher.encrypt(plain.get_bytes(), self.passphrase, iv)
            main.append(encrypted)
        else:
            main.append(plain)
        return main
