"""Pure-Python port of libmcrypt's GOST 28147-89.

Faithful translation of ``_reference/libsrc/algorithms/gost.c``, using the
"Applied Cryptography" / Central Bank of the Russian Federation S-box set
(``gost_k1``..``gost_k8``).

Byte / word order (matching the C code on a little-endian Windows host, where
``WORDS_BIGENDIAN`` is *not* defined):

* ``_mcrypt_set_key`` copies the 32 key bytes into eight ``word32`` values with
  no byteswap on little-endian, i.e. each 4-byte group is read little-endian.
  (The big-endian branch byteswaps, giving the same numeric words.)
* The 8-byte block is read with an explicit byteswap on little-endian:
  ``n1 = byteswap32(in[0])``, ``n2 = byteswap32(in[1])``.  byteswap32 of a
  little-endian word equals the big-endian interpretation of those 4 bytes, so
  the two halves are big-endian ``word32`` values.  The output is written back
  with the same byteswap, i.e. half ``n2`` first then ``n1``, each big-endian.
* ``f()`` replaces each 4-bit nibble of its input through k8..k1 (k8 is the
  most significant nibble, k1 the least), then rotates left 11 bits.  All
  arithmetic is modulo 2**32.

Only the Python standard library is used.
"""

from __future__ import annotations

_MASK = 0xFFFFFFFF


def _rotl32(x, n):
    x &= _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


# GOST S-boxes gost_k1..gost_k8 -- transcribed verbatim from the C source.
_K1 = (1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 2)
_K2 = (13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12)
_K3 = (4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14)
_K4 = (6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2)
_K5 = (7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3)
_K6 = (5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11)
_K7 = (14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9)
_K8 = (4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3)


def _f(x):
    """Substitution + rotate left 11 (the C ``f()``)."""
    x &= _MASK
    out = (_K8[(x >> 28) & 15] << 28 |
           _K7[(x >> 24) & 15] << 24 |
           _K6[(x >> 20) & 15] << 20 |
           _K5[(x >> 16) & 15] << 16 |
           _K4[(x >> 12) & 15] << 12 |
           _K3[(x >> 8) & 15] << 8 |
           _K2[(x >> 4) & 15] << 4 |
           _K1[x & 15])
    return _rotl32(out, 11)


# Key schedule: encryption uses K0..K7 three times then K7..K0 once;
# decryption uses K0..K7 once then K7..K0 three times (the C source).
_ENC_ORDER = tuple([0, 1, 2, 3, 4, 5, 6, 7] * 3 + [7, 6, 5, 4, 3, 2, 1, 0])
_DEC_ORDER = tuple([0, 1, 2, 3, 4, 5, 6, 7] + [7, 6, 5, 4, 3, 2, 1, 0] * 3)


class GOST:
    """GOST 28147-89 block cipher; ``block_size == 8``."""

    block_size = 8

    def __init__(self, key):
        key = bytes(key)
        # inst[0..7]: little-endian word32 of each 4-byte group (set_key).
        self._key = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]

    def _crypt(self, block, decrypt):
        block = bytes(block)
        if len(block) != 8:
            raise ValueError("block must be exactly 8 bytes")
        # byteswap32(in[0]) == big-endian interpretation of the 4 bytes.
        n1 = int.from_bytes(block[0:4], "big")
        n2 = int.from_bytes(block[4:8], "big")
        key = self._key
        order = _DEC_ORDER if decrypt else _ENC_ORDER
        for r, k in enumerate(order):
            if r % 2 == 0:
                n2 ^= _f((n1 + key[k]) & _MASK)
            else:
                n1 ^= _f((n2 + key[k]) & _MASK)
        # in[0] = byteswap32(n2); in[1] = byteswap32(n1).
        return (n2 & _MASK).to_bytes(4, "big") + (n1 & _MASK).to_bytes(4, "big")

    def encrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, False)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, True)


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def create(key: bytes) -> GOST:
    """Return a GOST cipher.  ``key`` must be exactly 32 bytes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes")
    key = bytes(key)
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return GOST(key)


# ---------------------------------------------------------------------------
# Self test
# ---------------------------------------------------------------------------

# Verbatim from gost.c ``_mcrypt_self_test``:
#     #define CIPHER "e498cf78cdf1d4a5"
# with keyword[j] = (j*2+10) % 256 and plaintext[j] = j % 256.
CIPHER = "e498cf78cdf1d4a5"


def self_test() -> bool:
    """Verify the C source's known-answer vector and a round trip; silent on success."""
    key = bytes((j * 2 + 10) % 256 for j in range(32))
    pt = bytes(j % 256 for j in range(8))

    cipher = create(key)
    ct = cipher.encrypt_block(pt)
    if ct.hex() != CIPHER:
        return False
    if cipher.decrypt_block(ct) != pt:
        return False

    c2 = create(bytes(range(32)))
    for n in range(8):
        block = bytes((j * 37 + n * 11 + 3) % 256 for j in range(8))
        if c2.decrypt_block(c2.encrypt_block(block)) != block:
            return False

    return True
