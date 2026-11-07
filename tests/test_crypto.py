"""Tests for libmhash CRC32, KEYGEN_MCRYPT and every libmcrypt cipher/mode."""

from __future__ import annotations

import pytest

from stegseek import ciphers
from stegseek.const import (
    ENC_MODE_STREAM,
    ENCRYPTION_ALGORITHMS,
    algo_index,
    mode_index,
)
from stegseek.crypto import get_cipher, keygen_mcrypt, mhash_crc32

STREAM_ALGOS = {"enigma", "arcfour", "panama", "wake"}
BLOCK_MODES = ["ecb", "cbc", "ofb", "cfb", "nofb", "ncfb", "ctr"]


def test_mhash_crc32_known_values():
    # libmhash MHASH_CRC32 (non-reflected CRC-32/BZIP2 with mhash's final
    # byte ordering).  These values are confirmed by steghide oracle files.
    assert mhash_crc32(b"") == 0x00000000
    assert mhash_crc32(b"123456789") == 0xFC891918
    assert mhash_crc32(b"This is a test file\n") != 0


def test_keygen_mcrypt_matches_md5_prefix_chaining():
    import hashlib
    pw = b"P@ssw0rd"
    first = hashlib.md5(pw).digest()
    assert keygen_mcrypt(pw, 16) == first
    expected = first + hashlib.md5(pw + first).digest()
    assert keygen_mcrypt(pw, 32) == expected
    assert len(keygen_mcrypt(pw, 40)) == 40


def test_all_pure_python_ciphers_pass_known_answer_tests():
    assert ciphers.self_test() is True


@pytest.mark.parametrize("algo,mode", [
    *[(a, m) for a in ENCRYPTION_ALGORITHMS if a != "none" and a not in STREAM_ALGOS
      for m in BLOCK_MODES],
    *[(a, "stream") for a in STREAM_ALGOS],
])
def test_cipher_mode_roundtrip_and_size(algo, mode):
    """Every algorithm/mode pair encrypts to MCryptPP::getEncryptedSize bits."""
    import os
    c = get_cipher(algo_index(algo), mode_index(mode))
    block_bits = 8 * c.block_size
    plain_bits = 401  # deliberately not block aligned
    # steghide pads the plain BitString to a whole block before handing it to
    # MCryptPP; the cipher layer always receives a block-aligned byte buffer.
    padded_bits = ((plain_bits + block_bits - 1) // block_bits) * block_bits
    plain = os.urandom(padded_bits // 8)
    iv = os.urandom(c.iv_size)
    encrypted = c.encrypt(plain, b"test-passphrase", iv)
    assert len(encrypted) * 8 == c.encrypted_size(plain_bits)
    assert len(encrypted) * 8 == 8 * c.iv_size + padded_bits
    restored = c.decrypt(encrypted, b"test-passphrase")
    assert restored == plain


def test_no_encryption_is_identity():
    c = get_cipher(algo_index("none"), mode_index("cbc"))
    assert c.encrypted_size(401) == 401
    assert c.encrypt(b"abc", b"pw", b"") == b"abc"
    assert c.decrypt(b"abc", b"pw") == b"abc"


def test_encrypted_size_matches_cpp_definition():
    # IV bits + ceil(plain_bits / block_bits) * block_bits
    c = get_cipher(algo_index("rijndael-128"), mode_index("cbc"))
    assert c.encrypted_size(0) == 128          # 16-byte IV, zero blocks
    assert c.encrypted_size(1) == 128 + 128    # one padded block
    assert c.encrypted_size(129) == 128 + 256
    assert get_cipher(algo_index("arcfour"), ENC_MODE_STREAM).iv_size == 0
    assert get_cipher(algo_index("panama"), ENC_MODE_STREAM).iv_size == 32
