"""Windows / OS2 BMP cover files (``src/BmpFile.cc``)."""

from __future__ import annotations

import struct

from ..errors import UnSupFileFormat
from .base import CoverFile


class BmpFile(CoverFile):
    def __init__(self, path: str, raw: bytes):
        super().__init__(path, raw)
        data = raw
        if len(data) < 18 or data[:2] != b"BM":
            raise UnSupFileFormat("not a BMP file")
        self.off_bits = struct.unpack_from("<I", data, 10)[0]
        header_size = struct.unpack_from("<I", data, 14)[0]
        self.subformat = "WIN" if header_size == 40 else "OS2" if header_size == 12 else None
        if self.subformat == "WIN":
            self.width = struct.unpack_from("<i", data, 18)[0]
            self.height = struct.unpack_from("<i", data, 22)[0]
            self.bitcount = struct.unpack_from("<H", data, 28)[0]
            self.format_name = "Windows 3.x bitmap"
        elif self.subformat == "OS2":
            self.width = struct.unpack_from("<H", data, 18)[0]
            self.height = struct.unpack_from("<H", data, 20)[0]
            self.bitcount = struct.unpack_from("<H", data, 24)[0]
            self.format_name = "OS/2 1.x bitmap"
        else:
            raise UnSupFileFormat(
                'the bmp file "%s" has a format that is not supported (biSize: %lu).'
                % (path, header_size))

        if self.bitcount in (1, 4):
            self.samples_per_vertex, self.modulus = 2, 2
        elif self.bitcount == 8:
            self.samples_per_vertex, self.modulus = 3, 4
        elif self.bitcount == 24:
            self.samples_per_vertex, self.modulus = 2, 4
        else:
            raise UnSupFileFormat(
                'the bmp file "%s" has a format that is not supported (biBitCount: %d).'
                % (path, self.bitcount))

        self.line_length = (self.width * self.bitcount + 7) // 8
        self.padding = (4 - self.line_length % 4) % 4
        self.prefix = bytearray(data[:self.off_bits])
        self.bitmap = bytearray()
        cursor = self.off_bits
        for _ in range(self.height):
            self.bitmap.extend(data[cursor:cursor + self.line_length])
            cursor += self.line_length + self.padding
        self.atend = data[cursor:]

        values = [self._sample_value(pos) % self.modulus for pos in range(self.width * self.height)]
        self._finalize_evalues(values)

    def calc_index(self, pos: int) -> tuple[int, int]:
        width, bitcount = self.width, self.bitcount
        bytes_per_line = (width * bitcount + 7) // 8
        row, col_in_row = divmod(pos, width)
        if bitcount in (1, 4, 8):
            samples_per_byte = 8 // bitcount
            column = col_in_row // samples_per_byte
            firstbit = (samples_per_byte - (col_in_row % samples_per_byte) - 1) * bitcount
        else:
            column = col_in_row * 3
            firstbit = 0
        return bytes_per_line * row + column, firstbit

    def _sample_value(self, pos: int) -> int:
        index, firstbit = self.calc_index(pos)
        if self.bitcount in (1, 4, 8):
            value = 0
            for i in range(self.bitcount):
                value |= ((self.bitmap[index] & (1 << (firstbit + i))) >> firstbit)
            return value
        r, g, b = self.bitmap[index + 2], self.bitmap[index + 1], self.bitmap[index]
        return (((r & 1) ^ (g & 1)) << 1) | ((r & 1) ^ (b & 1))

    def set_embedded_value(self, pos: int, target: int) -> None:
        index, firstbit = self.calc_index(pos)
        if self.evalues[pos] == target:
            return
        if self.bitcount in (1, 4, 8):
            old = 0
            for i in range(self.bitcount):
                old |= ((self.bitmap[index] & (1 << (firstbit + i))) >> firstbit)
            limit = 1 << self.bitcount
            candidates = [v for v in range(limit) if v % self.modulus == target]
            new = min(candidates, key=lambda v: (abs(v - old), v))
            mask = ((1 << self.bitcount) - 1) << firstbit
            self.bitmap[index] = (self.bitmap[index] & ~mask) & 0xFF
            self.bitmap[index] |= (new << firstbit) & 0xFF
        else:
            r = self.bitmap[index + 2]
            self.bitmap[index + 1] = (self.bitmap[index + 1] & 0xFE) | ((r & 1) ^ ((target >> 1) & 1))
            self.bitmap[index] = (self.bitmap[index] & 0xFE) | ((r & 1) ^ (target & 1))
        self.evalues[pos] = target

    def to_bytes(self) -> bytes:
        out = bytearray(self.prefix)
        for row in range(self.height):
            start = row * self.line_length
            out.extend(self.bitmap[start:start + self.line_length])
            out.extend(b"\x00" * self.padding)
        out.extend(self.atend)
        return bytes(out)

    def properties(self) -> list[tuple[str, str]]:
        return [("format", self.format_name)]
