"""Tests for the LSB-first BitString port."""

from __future__ import annotations

import pytest

from stegseek.bitstring import BitString


def test_append_bytes_lsb_first():
    b = BitString()
    b.append(0xB7, 8)  # binary 1011 0111, stored LSB-first
    assert b.length == 8
    assert b.get_value(0, 8) == 0xB7
    assert bytes(b.data) == b"\xb7"


def test_append_partial_bits():
    b = BitString()
    b.append(0b101, 3)
    b.append(0b1101, 4)
    assert b.length == 7
    assert b.get_value(0, 3) == 0b101
    assert b.get_value(3, 4) == 0b1101
    assert b.get_value(0, 7) == (0b101 | (0b1101 << 3))


def test_append_bitstring_and_bytes():
    a = BitString()
    a.append(b"AB")
    b = BitString()
    b.append(a)
    assert b.get_value(0, 16) == int.from_bytes(b"AB", "little")


def test_cut_bits_and_truncate():
    b = BitString()
    b.append(0xDEADBEEF, 32)
    assert b.cut_bits(8, 16).get_value(0, 16) == 0xADBE
    assert b.length == 16

    c = BitString()
    c.append(0xDEADBEEF, 32)
    c.truncate(8, 24)
    assert c.length == 16
    assert c.get_value(0, 16) == 0xADBE


def test_compress_roundtrip():
    raw = b"the quick brown fox " * 40
    b = BitString(source=raw)
    n = b.length
    b.compress(9)
    assert b.length < n
    b.uncompress(n)
    assert b.length == n
    assert b.get_bytes() == raw


def test_uncompress_rejects_corrupt_data():
    from stegseek.errors import SteghideError
    b = BitString(source=b"not zlib data")
    with pytest.raises(SteghideError):
        b.uncompress(8 * len(b"not zlib data"))


def test_arity_must_be_power_of_two():
    with pytest.raises(ValueError):
        BitString(arity=3)


def test_append_nary():
    b = BitString(arity=4)
    for value in (0, 1, 2, 3):
        b.append_nary(value)
    assert b.arity_nbits == 2
    assert b.length == 8
    # 0b00, 0b01, 0b10, 0b11 written LSB-first -> 0b11100100
    assert b.get_value(0, 8) == 0b11100100
