"""Common interface for steghide cover/stego files."""

from __future__ import annotations

import math
from pathlib import Path

import numpy as np


def log2_ceil(n: int) -> int:
    return (n - 1).bit_length() if n > 1 else 0


def div_roundup(a: int, b: int) -> int:
    return (a + b - 1) // b


def format_hr_size(size: float) -> str:
    unit = "Byte(s)"
    if size > 1024.0:
        size /= 1024.0
        unit = "KB"
    if size > 1024.0:
        size /= 1024.0
        unit = "MB"
    if size > 1024.0:
        size /= 1024.0
        unit = "GB"
    return "%.1f %s" % (size, unit)


class CoverFile:
    """A cover/stego file exposing steghide's sample array."""

    format_name = "unknown"

    def __init__(self, path: str, raw: bytes):
        self.name = path
        self.raw = raw
        self.num_samples = 0
        self.samples_per_vertex = 0
        self.modulus = 2
        self.sample_values: list[int] = []
        self.evalues: np.ndarray = np.empty(0, dtype=np.uint8)

    @property
    def bits_per_emb_value(self) -> int:
        return log2_ceil(self.modulus)

    def _finalize_evalues(self, values: list[int]) -> None:
        self.sample_values = values
        self.num_samples = len(values)
        self.evalues = np.asarray(values, dtype=np.uint8)

    def capacity(self) -> int:
        # C++: float maxnvertices = getNumSamples() / getSamplesPerVertex();
        # (integer division first), then maxnbits / 8 truncated.
        max_vertices = self.num_samples // self.samples_per_vertex
        return int(max_vertices * math.log2(self.modulus) / 8)

    def properties(self) -> list[tuple[str, str]]:
        return [("format", self.format_name)]

    def set_embedded_value(self, pos: int, target: int) -> None:
        """Change one sample to the nearest value with ``target`` as EValue."""
        raise NotImplementedError

    def write(self, path: str) -> None:
        raise NotImplementedError

    def to_bytes(self) -> bytes:
        raise NotImplementedError

    def save(self, path: str) -> None:
        Path(path).write_bytes(self.to_bytes())
