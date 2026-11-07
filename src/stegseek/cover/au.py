"""Sun/NeXT .au audio cover files (``src/AuFile.cc``)."""

from __future__ import annotations

import struct

from ..errors import UnSupFileFormat
from .base import CoverFile


class AuFile(CoverFile):
    format_name = "au audio"

    def __init__(self, path: str, raw: bytes):
        super().__init__(path, raw)
        if len(raw) < 24 or raw[:4] != b".snd":
            raise UnSupFileFormat("not an au file")
        self.offset, size, self.encoding, self.sample_rate, self.channels = \
            struct.unpack_from(">5I", raw, 4)
        self.data = bytearray(raw[self.offset:])
        if self.encoding == 1:
            self.bytes_per_sample, self.signed = 1, False
        elif self.encoding == 2:
            self.bytes_per_sample, self.signed = 1, True
        elif self.encoding == 3:
            self.bytes_per_sample, self.signed = 2, True
        else:
            raise UnSupFileFormat(
                'the au file "%s" uses the unknown encoding %d.' % (path, self.encoding))
        if size != 0xFFFFFFFF:
            self.data = self.data[:size]
        self.header = bytearray(raw[:self.offset])
        self.samples_per_vertex = 2
        self.modulus = 2
        n = len(self.data) // self.bytes_per_sample
        self._finalize_evalues([self._read(i) & 1 for i in range(n)])

    def _read(self, pos: int) -> int:
        chunk = self.data[pos * self.bytes_per_sample:(pos + 1) * self.bytes_per_sample]
        value = int.from_bytes(chunk, "big")
        if self.signed and value >= (1 << (8 * self.bytes_per_sample - 1)):
            value -= 1 << (8 * self.bytes_per_sample)
        return value

    def _write(self, pos: int, value: int) -> None:
        bits = 8 * self.bytes_per_sample
        encoded = value & ((1 << bits) - 1)
        self.data[pos * self.bytes_per_sample:(pos + 1) * self.bytes_per_sample] = \
            encoded.to_bytes(self.bytes_per_sample, "big")

    def set_embedded_value(self, pos: int, target: int) -> None:
        if self.evalues[pos] == target:
            return
        value = self._read(pos)
        new_value = value + 1 if (value & 1) != target else value
        bits = 8 * self.bytes_per_sample
        if self.signed:
            if new_value >= (1 << (bits - 1)):
                new_value = value - 1
        elif new_value >= (1 << bits):
            new_value = value - 1
        self._write(pos, new_value)
        self.evalues[pos] = target

    def to_bytes(self) -> bytes:
        return bytes(self.header) + bytes(self.data)
