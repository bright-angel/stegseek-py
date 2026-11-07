"""Port of ``src/Selector.cc`` / ``src/PseudoRandomSource.cc`` / ``Cracker::verifyMagic``."""

from __future__ import annotations

import hashlib
import struct

from .const import LCG_A, LCG_C, U32, U32_MASK


def passphrase_to_seed(passphrase: bytes) -> int:
    """``Selector(numSamples, passphrase)`` seed derivation (MD5 XOR of 4 LE words)."""
    digest = hashlib.md5(passphrase).digest()
    words = struct.unpack("<4I", digest)
    return words[0] ^ words[1] ^ words[2] ^ words[3]


def lcg_next(value: int) -> int:
    return (value * LCG_A + LCG_C) & U32_MASK


def lcg_get(value: int, n: int) -> int:
    """``PseudoRandomSource::getValue(n)`` -- advance and scale to [0, n)."""
    value = lcg_next(value)
    return int(float(n) * (float(value) / float(U32))) & U32_MASK


class Selector:
    """Random permutation of a random combination (steghide's ``Selector``)."""

    __slots__ = ("maximum", "num_in_array", "x", "y", "x_reversed", "value")

    def __init__(self, maximum: int, seed: int | bytes | str | None = None,
                 predefined: list[int] | None = None):
        self.maximum = maximum
        self.num_in_array = 0
        self.x: list[int] = []
        self.y: list[int] = []
        self.x_reversed: dict[int, int] = {}
        self.value = 0
        if predefined is not None:
            self.x = list(predefined)
            self.y = [0] * len(predefined)
            for i, v in enumerate(self.x):
                self.x_reversed[v] = i
            self.num_in_array = len(predefined)
            self.maximum = len(predefined)
        elif seed is None:
            self.x = list(range(maximum))
            self.y = [0] * maximum
            for i, v in enumerate(self.x):
                self.x_reversed[v] = i
            self.num_in_array = maximum
        else:
            if isinstance(seed, str):
                seed = passphrase_to_seed(seed.encode("utf-8", "surrogateescape"))
            elif isinstance(seed, bytes):
                seed = passphrase_to_seed(seed)
            self.value = seed & U32_MASK
            self.x = []
            self.y = []

    def _idx_x(self, value: int, limit: int) -> int:
        idx = self.x_reversed.get(value)
        return idx if idx is not None and idx < limit else -1

    def _set_x(self, index: int, value: int) -> None:
        self.x[index] = value
        self.x_reversed[value] = index

    def calculate(self, m: int) -> None:
        start = self.num_in_array
        if m > self.num_in_array:
            self.num_in_array = m
            if self.num_in_array > len(self.x):
                extra = self.num_in_array - len(self.x)
                self.x.extend([0] * extra)
                self.y.extend([0] * extra)
        for j in range(start, m):
            self.value = lcg_next(self.value)
            k = j + int(float(self.maximum - j) * (float(self.value) / float(U32)))
            i = self._idx_x(k, j)
            if i >= 0:
                self._set_x(j, self.y[i])
                if self.x[j] > j:
                    self.y[j] = j
                if self.x[i] > j:
                    self.y[i] = j
                    idx = self._idx_x(self.y[i], j)
                    if idx >= 0:
                        self.y[i] = self.y[idx]
            else:
                self._set_x(j, k)
                self.y[j] = j
            if self.x[j] > j:
                i = self._idx_x(self.y[j], j)
                if i >= 0:
                    self.y[j] = self.y[i]

    def __getitem__(self, index: int) -> int:
        if index >= self.maximum:
            raise IndexError(index)
        self.calculate(index + 1)
        return self.x[index]

    def indices(self, count: int) -> list[int]:
        if count > self.maximum:
            raise IndexError(count)
        self.calculate(count)
        return self.x[:count]
