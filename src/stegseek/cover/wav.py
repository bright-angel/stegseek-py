"""RIFF/WAVE PCM cover files (``src/WavFile.cc``)."""

from __future__ import annotations

import struct

from ..errors import UnSupFileFormat
from .base import CoverFile


class WavFile(CoverFile):
    format_name = "wave audio, PCM encoding"

    def __init__(self, path: str, raw: bytes):
        super().__init__(path, raw)
        if len(raw) < 12 or raw[:4] != b"RIFF" or raw[8:12] != b"WAVE":
            raise UnSupFileFormat("not a RIFF/WAVE file")
        self.data = bytearray(raw)
        pos = 12
        fmt = None
        data_offset = data_length = None
        while pos + 8 <= len(raw):
            chunk_id = raw[pos:pos + 4]
            chunk_len = struct.unpack_from("<I", raw, pos + 4)[0]
            body = pos + 8
            if chunk_id == b"fmt ":
                fmt = struct.unpack_from("<HHIIHH", raw, body)
            elif chunk_id == b"data":
                data_offset, data_length = body, chunk_len
                break
            next_pos = body + chunk_len + (chunk_len & 1)
            pos = next_pos if next_pos > pos else pos + 8
        if fmt is None or data_offset is None:
            raise UnSupFileFormat("the wav file has no usable fmt/data chunk")

        self.format_tag, self.channels, self.sample_rate, _byte_rate, _align, self.bits = fmt
        self.bytes_per_sample = (self.bits + 7) // 8
        self.first_bit = 0 if self.bits % 8 == 0 else 8 - (self.bits % 8)
        self.data_offset = data_offset
        self.data_length = min(data_length, len(raw) - data_offset)

        n = self.data_length // self.bytes_per_sample
        self.sample_offsets = [data_offset + i * self.bytes_per_sample for i in range(n)]
        self.samples_per_vertex = 2
        self.modulus = 2
        self._finalize_evalues([self._read_sample(i) & 1 for i in range(n)])

    def _read_sample(self, pos: int) -> int:
        offset = self.sample_offsets[pos]
        raw = int.from_bytes(self.data[offset:offset + self.bytes_per_sample], "little")
        value = raw >> self.first_bit
        if self.bits > 8:
            sign = 1 if ((value >> (self.bits - 1)) & 1) == 0 else -1
            if sign < 0:
                value = (~value + 1) & ((1 << self.bits) - 1)
                value = -value
        return value

    def _write_sample(self, pos: int, value: int) -> None:
        offset = self.sample_offsets[pos]
        if value < 0:
            encoded = (~(-value) + 1) & ((1 << self.bits) - 1)
        else:
            encoded = value & ((1 << self.bits) - 1)
        low_bits = int.from_bytes(self.data[offset:offset + self.bytes_per_sample], "little") \
            & ((1 << self.first_bit) - 1)
        combined = ((encoded << self.first_bit) | low_bits) & ((1 << (8 * self.bytes_per_sample)) - 1)
        self.data[offset:offset + self.bytes_per_sample] = combined.to_bytes(
            self.bytes_per_sample, "little")

    def set_embedded_value(self, pos: int, target: int) -> None:
        if self.evalues[pos] == target:
            return
        value = self._read_sample(pos)
        new_value = value + 1 if (value & 1) != target else value
        bound = 1 << (self.bits - (1 if self.bits > 8 else 0))
        if new_value >= bound:
            new_value = value - 1
        self._write_sample(pos, new_value)
        self.evalues[pos] = target

    def to_bytes(self) -> bytes:
        return bytes(self.data)
