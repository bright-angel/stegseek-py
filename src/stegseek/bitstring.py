"""Port of ``src/BitString.cc``.

Bits are stored LSB-first inside each byte.  ``append(value, n)`` pushes the
``n`` low bits of ``value``, least significant first.
"""

from __future__ import annotations

import zlib
from typing import Iterable

from .const import NBITS_NUNCOMPRESSEDBITS
from .errors import SteghideError


class BitString:
    __slots__ = ("data", "length", "arity", "arity_nbits")

    def __init__(self, arity: int = 2, source: bytes | bytearray | str | None = None):
        self.data = bytearray()
        self.length = 0
        self.set_arity(arity)
        if source is not None:
            self.append(source)

    def set_arity(self, arity: int) -> None:
        tmp = self.arity = arity
        n = 0
        while tmp > 1:
            if tmp % 2:
                raise ValueError("arity must be a power of two")
            tmp //= 2
            n += 1
        self.arity_nbits = n

    # ------------------------------------------------------------------ append
    def _append(self, value: int) -> None:
        if self.length % 8 == 0:
            self.data.append(0)
        if value & 1:
            self.data[self.length // 8] |= 1 << (self.length % 8)
        self.length += 1

    def append(self, value, n: int | None = None) -> "BitString":
        if n is None:
            if isinstance(value, BitString):
                for i in range(value.length):
                    self._append(value[i])
            elif isinstance(value, (bytes, bytearray)):
                for b in value:
                    self.append(b, 8)
            elif isinstance(value, str):
                for ch in value:
                    self.append(ord(ch) & 0xFF, 8)
            elif isinstance(value, bool):
                self._append(int(value))
            elif isinstance(value, int):
                self._append(value & 1)
            else:
                raise TypeError(f"cannot append {type(value)!r}")
        else:
            for i in range(n):
                self._append((value >> i) & 1)
        return self

    def append_nary(self, value: int) -> "BitString":
        for i in range(self.arity_nbits):
            self._append((value >> i) & 1)
        return self

    # ------------------------------------------------------------------- access
    def __len__(self) -> int:
        return self.length

    def __getitem__(self, i: int) -> int:
        if i >= self.length:
            raise IndexError(i)
        return (self.data[i // 8] >> (i % 8)) & 1

    def get_value(self, start: int, length: int) -> int:
        if length > 32:
            raise ValueError("at most 32 bits")
        retval = 0
        for i in range(length):
            retval |= self[start + i] << i
        return retval

    def get_bytes(self) -> bytes:
        if self.length % 8:
            raise ValueError("length is not a multiple of 8")
        return bytes(self.data[: self.length // 8])

    def cut_bits(self, start: int, length: int) -> "BitString":
        """Remove and return ``length`` bits at ``start`` (C++ ``cutBits``)."""
        if start + length > self.length:
            raise ValueError("cut out of range")
        retval = BitString()
        for i in range(start, start + length):
            retval._append(self[i])
        # shift the remainder down
        remaining = self.length - (start + length)
        for i in range(remaining):
            bit = self[start + length + i]
            pos = start + i
            self.data[pos // 8] &= ~(1 << (pos % 8)) & 0xFF
            if bit:
                self.data[pos // 8] |= 1 << (pos % 8)
        self.length -= length
        del self.data[(self.length + 7) // 8:]
        self._clear_unused()
        return retval

    def truncate(self, start: int, end: int) -> "BitString":
        newsize = end - start
        for i in range(newsize):
            bit = self[start + i]
            self.data[i // 8] &= ~(1 << (i % 8)) & 0xFF
            if bit:
                self.data[i // 8] |= 1 << (i % 8)
        self.length = newsize
        del self.data[(newsize + 7) // 8:]
        self._clear_unused()
        return self

    def pad(self, mult: int, bit: int = 0) -> "BitString":
        while self.length % mult:
            self._append(bit)
        return self

    def _clear_unused(self) -> None:
        if self.length % 8:
            nbits = self.length % 8
            self.data[-1] &= (1 << nbits) - 1

    # -------------------------------------------------------------- compression
    def compress(self, level: int) -> "BitString":
        if not 1 <= level <= 9:
            raise ValueError("compression level must be 1..9")
        self.pad(8, 0)
        compressed = zlib.compress(bytes(self.data), level)
        self.data = bytearray(compressed)
        self.length = 8 * len(compressed)
        return self

    def uncompress(self, destlen_bits: int) -> "BitString":
        if self.length % 8:
            raise SteghideError("can not uncompress data. compressed data is corrupted.")
        try:
            raw = zlib.decompress(bytes(self.data))
        except zlib.error as exc:
            raise SteghideError("can not uncompress data. compressed data is corrupted.") from exc
        expected = (destlen_bits + 7) // 8
        if len(raw) != expected:
            raise SteghideError("can not uncompress data. compressed data is corrupted.")
        self.data = bytearray(raw)
        self.length = destlen_bits
        self._clear_unused()
        return self

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, BitString) or other.length != self.length:
            return False
        return all(self[i] == other[i] for i in range(self.length))


def bitstring_from_nary(values: Iterable[int], arity: int) -> BitString:
    bs = BitString(arity)
    for value in values:
        bs.append_nary(value)
    return bs


def format_nuncompressed_bits(n: int) -> int:
    """Width of the stored uncompressed-length field."""
    return NBITS_NUNCOMPRESSEDBITS
