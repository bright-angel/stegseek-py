"""Tests for the seed derivation, Selector LCG and vectorised magic filter."""

from __future__ import annotations

import numpy as np
import pytest

from stegseek.const import LCG_A, LCG_C, MAGIC, NBITS_MAGIC
from stegseek.cover import read_cover_file
from stegseek.crackers.base import MagicVerifier
from stegseek.selector import Selector, lcg_get, lcg_next, passphrase_to_seed


@pytest.mark.parametrize("password,expected", [
    (b"moana5", 0x00000291),
    (b"apple87", 0x00000E1A),
])
def test_passphrase_to_seed_known_values(password, expected):
    assert passphrase_to_seed(password) == expected


def test_passphrase_to_seed_is_md5_xor():
    import hashlib
    import struct
    pw = b"stegseek"
    digest = hashlib.md5(pw).digest()
    words = struct.unpack("<4I", digest)
    assert passphrase_to_seed(pw) == words[0] ^ words[1] ^ words[2] ^ words[3]


def test_lcg_constants_and_step():
    assert LCG_A == 1367208549
    assert LCG_C == 1
    assert lcg_next(0) == 1
    assert lcg_next(lcg_next(0)) == (LCG_A + 1) % (1 << 32)
    assert 0 <= lcg_get(12345, 100) < 100


def test_selector_is_a_permutation_and_is_deterministic():
    n = 500
    a = Selector(n, 0x12345678)
    b = Selector(n, 0x12345678)
    ia = a.indices(n)
    ib = b.indices(n)
    assert ia == ib
    assert len(set(ia)) == n
    assert all(0 <= i < n for i in ia)
    assert Selector(n, 0x12345679).indices(n) != ia


def test_magic_constant():
    # 's','h','m' plus the version-0 bit packed LSB-first
    assert NBITS_MAGIC == 24
    assert MAGIC == 0x073688D


def test_batch_magic_filter_matches_scalar(sun_jpg):
    cover = read_cover_file(str(sun_jpg))
    v = MagicVerifier(cover)
    rng = np.random.default_rng(20240607)
    seeds = rng.integers(0, 1 << 32, size=20000, dtype=np.uint64)
    batch = v.verify_batch(seeds)
    scalar = np.fromiter((v.verify(int(s)) for s in seeds), dtype=bool, count=len(seeds))
    mismatch = int(np.count_nonzero(batch != scalar))
    assert mismatch == 0, f"batch/scalar mismatch on {mismatch} seeds"


def test_batch_filter_finds_known_passphrase_seed(sun_jpg):
    """The correct passphrase must survive the vectorised magic filter."""
    cover = read_cover_file(str(sun_jpg))
    v = MagicVerifier(cover)
    seeds = np.array([1, 2, 3, passphrase_to_seed(b"stegseek"), 0xDEADBEEF], dtype=np.uint64)
    hits = v.verify_filtered(seeds)
    assert passphrase_to_seed(b"stegseek") in set(int(x) for x in hits)
