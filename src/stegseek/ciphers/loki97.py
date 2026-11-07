"""Pure-Python port of libmcrypt's LOKI97.

Faithful translation of ``_reference/libsrc/algorithms/loki97.c`` (Dr Brian
Gladman's AES-candidate implementation, wrapped for libmcrypt by Nikos
Mavroyanopoulos).

Byte / word order (matching the C code on a little-endian Windows host, where
``WORDS_BIGENDIAN`` is *not* defined):

* The 16-byte block and the 32-byte key are the raw byte buffers that libmcrypt
  hands to ``_mcrypt_encrypt`` / ``_mcrypt_decrypt`` / ``_mcrypt_set_key`` cast
  to ``word32 *``.  On little-endian each 4-byte group is read/written as a
  little-endian ``word32`` (no ``byteswap32`` in the ``#else`` branches).
* ``_mcrypt_encrypt`` loads ``blk[3]=_blk[0] .. blk[0]=_blk[3]`` (word-reverse)
  into the 4-word working state, runs 16 ``r_fun`` rounds, then writes back
  ``_blk[3]=blk[2] .. _blk[0]=blk[1]``.  Decryption uses the same I/O mapping
  with the inverse ``ir_fun`` rounds in the opposite order.

Key schedule, S-boxes (``sb1``/``sb2`` via GF(2^n) ``ff_mult``) and the ``prm``
permutation table are all generated at import time exactly as ``init_tables()``
does in the C source, so no numeric table has to be retyped here.

Only the Python standard library is used.
"""

from __future__ import annotations

_MASK = 0xFFFFFFFF
_MASK64 = 0xFFFFFFFFFFFFFFFF

# From the C source: word32 delta[2] = { 0x7f4a7c15, 0x9e3779b9 };
_DELTA = (0x7F4A7C15, 0x9E3779B9)

_S1_SIZE = 13
_S1_LEN = 1 << _S1_SIZE
_S1_MASK = _S1_LEN - 1            # 0x1fff
_S1_HMASK = _S1_MASK & ~0xFF     # 0x1f00
_S1_POLY = 0x2911

_S2_SIZE = 11
_S2_LEN = 1 << _S2_SIZE
_S2_MASK = _S2_LEN - 1            # 0x07ff
_S2_HMASK = _S2_MASK & ~0xFF     # 0x0700
_S2_POLY = 0x0AA7


def _ff_mult(a: int, b: int, tpow: int, mpol: int) -> int:
    """The C ``ff_mult`` GF(2^tpow) multiply (``a`` stays within tpow bits)."""
    s = 0
    m = 1 << tpow
    while b:
        if b & 1:
            s ^= a
        b >>= 1
        a <<= 1
        if a & m:
            a ^= mpol
    return s


def _init_tables():
    sb1 = [0] * _S1_LEN
    for i in range(_S1_LEN):
        j = v = i ^ _S1_MASK
        v = _ff_mult(v, j, _S1_SIZE, _S1_POLY)
        sb1[i] = _ff_mult(v, j, _S1_SIZE, _S1_POLY) & 0xFF

    sb2 = [0] * _S2_LEN
    for i in range(_S2_LEN):
        j = v = i ^ _S2_MASK
        v = _ff_mult(v, j, _S2_SIZE, _S2_POLY)
        sb2[i] = _ff_mult(v, j, _S2_SIZE, _S2_POLY) & 0xFF

    prm = [[0, 0] for _ in range(256)]
    for i in range(256):
        prm[i][0] = (((i & 1) << 7) | ((i & 2) << 14) |
                     ((i & 4) << 21) | ((i & 8) << 28)) & _MASK
        prm[i][1] = (((i & 16) << 3) | ((i & 32) << 10) |
                     ((i & 64) << 17) | ((i & 128) << 24)) & _MASK

    return sb1, sb2, prm


_SB1, _SB2, _PRM = _init_tables()


def _add_eq(x, xo, y, yo):
    """64-bit add of two ``word32`` pairs (``x[0]`` is the low word)."""
    vx = (x[xo + 1] << 32) | x[xo]
    vy = (y[yo + 1] << 32) | y[yo]
    s = (vx + vy) & _MASK64
    x[xo] = s & _MASK
    x[xo + 1] = (s >> 32) & _MASK


def _sub_eq(x, xo, y, yo):
    """64-bit subtract of two ``word32`` pairs (``x[0]`` is the low word)."""
    vx = (x[xo + 1] << 32) | x[xo]
    vy = (y[yo + 1] << 32) | y[yo]
    d = (vx - vy) & _MASK64
    x[xo] = d & _MASK
    x[xo + 1] = (d >> 32) & _MASK


def _f_fun(res, ro, inp, io, key, ko):
    """The C ``f_fun(res, in, key)``; ``res`` is modified in place (XOR)."""
    k0 = key[ko]
    k1 = key[ko + 1]
    in0 = inp[io]
    in1 = inp[io + 1]
    nk0 = (~k0) & _MASK
    t0 = ((in0 & nk0) | (in1 & k0)) & _MASK
    t1 = ((in1 & nk0) | (in0 & k0)) & _MASK

    pp0 = 0
    pp1 = 0

    i = _SB1[((t1 >> 24) | (t0 << 8)) & _S1_MASK]
    pp0 |= _PRM[i][0] >> 7
    pp1 |= _PRM[i][1] >> 7
    i = _SB2[(t1 >> 16) & _S2_MASK]
    pp0 |= _PRM[i][0] >> 6
    pp1 |= _PRM[i][1] >> 6
    i = _SB1[(t1 >> 8) & _S1_MASK]
    pp0 |= _PRM[i][0] >> 5
    pp1 |= _PRM[i][1] >> 5
    i = _SB2[t1 & _S2_MASK]
    pp0 |= _PRM[i][0] >> 4
    pp1 |= _PRM[i][1] >> 4
    i = _SB2[((t0 >> 24) | (t1 << 8)) & _S2_MASK]
    pp0 |= _PRM[i][0] >> 3
    pp1 |= _PRM[i][1] >> 3
    i = _SB1[(t0 >> 16) & _S1_MASK]
    pp0 |= _PRM[i][0] >> 2
    pp1 |= _PRM[i][1] >> 2
    i = _SB2[(t0 >> 8) & _S2_MASK]
    pp0 |= _PRM[i][0] >> 1
    pp1 |= _PRM[i][1] >> 1
    i = _SB1[t0 & _S1_MASK]
    pp0 |= _PRM[i][0]
    pp1 |= _PRM[i][1]

    pp0 &= _MASK
    pp1 &= _MASK

    b0 = pp0 & 0xFF
    b1 = (pp0 >> 8) & 0xFF
    b2 = (pp0 >> 16) & 0xFF
    b3 = (pp0 >> 24) & 0xFF
    c0 = pp1 & 0xFF
    c1 = (pp1 >> 8) & 0xFF
    c2 = (pp1 >> 16) & 0xFF
    c3 = (pp1 >> 24) & 0xFF

    v0 = (_SB1[b0 | ((k1 << 8) & _S1_HMASK)]
          | (_SB1[b1 | ((k1 << 3) & _S1_HMASK)] << 8)
          | (_SB2[b2 | ((k1 >> 2) & _S2_HMASK)] << 16)
          | (_SB2[b3 | ((k1 >> 5) & _S2_HMASK)] << 24))
    v1 = (_SB1[c0 | ((k1 >> 8) & _S1_HMASK)]
          | (_SB1[c1 | ((k1 >> 13) & _S1_HMASK)] << 8)
          | (_SB2[c2 | ((k1 >> 18) & _S2_HMASK)] << 16)
          | (_SB2[c3 | ((k1 >> 21) & _S2_HMASK)] << 24))

    res[ro] = (res[ro] ^ v0) & _MASK
    res[ro + 1] = (res[ro + 1] ^ v1) & _MASK


def _set_key(key: bytes):
    """The C ``_mcrypt_set_key``; returns the 96-word ``l_key`` schedule."""
    in_key = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]

    k4 = [in_key[1], in_key[0]]
    k3 = [in_key[3], in_key[2]]
    k2 = [in_key[5], in_key[4]]
    k1 = [in_key[7], in_key[6]]
    del_ = [_DELTA[0], _DELTA[1]]

    l_key = [0] * 96
    for i in range(48):
        tt = [k1[0], k1[1]]
        _add_eq(tt, 0, k3, 0)
        _add_eq(tt, 0, del_, 0)
        _add_eq(del_, 0, _DELTA, 0)

        sk0, sk1 = k4[0], k4[1]
        k4[0], k4[1] = k3[0], k3[1]
        k3[0], k3[1] = k2[0], k2[1]
        k2[0], k2[1] = k1[0], k1[1]
        k1[0], k1[1] = sk0, sk1

        _f_fun(k1, 0, tt, 0, k3, 0)
        l_key[2 * i] = k1[0]
        l_key[2 * i + 1] = k1[1]

    return l_key


def _r_fun(b, l_off, r_off, lk, k_off):
    _add_eq(b, l_off, lk, k_off)
    _f_fun(b, r_off, b, l_off, lk, k_off + 2)
    _add_eq(b, l_off, lk, k_off + 4)


def _ir_fun(b, l_off, r_off, lk, k_off):
    _sub_eq(b, l_off, lk, k_off + 4)
    _f_fun(b, r_off, b, l_off, lk, k_off + 2)
    _sub_eq(b, l_off, lk, k_off)


class LOKI97:
    """LOKI97 block cipher; ``block_size == 16``."""

    block_size = 16

    def __init__(self, key: bytes):
        self._l_key = _set_key(bytes(key))

    def _crypt(self, block, decrypt: bool) -> bytes:
        block = bytes(block)
        if len(block) != 16:
            raise ValueError("block must be exactly 16 bytes")

        in_blk = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(4)]
        b = [0, 0, 0, 0]
        b[3] = in_blk[0]
        b[2] = in_blk[1]
        b[1] = in_blk[2]
        b[0] = in_blk[3]

        lk = self._l_key
        if decrypt:
            for j in range(16):
                k_off = 90 - 6 * j
                if j % 2 == 0:
                    _ir_fun(b, 0, 2, lk, k_off)
                else:
                    _ir_fun(b, 2, 0, lk, k_off)
        else:
            for j in range(16):
                k_off = 6 * j
                if j % 2 == 0:
                    _r_fun(b, 0, 2, lk, k_off)
                else:
                    _r_fun(b, 2, 0, lk, k_off)

        out_blk = [b[1], b[0], b[3], b[2]]
        return b"".join((w & _MASK).to_bytes(4, "little") for w in out_blk)

    def encrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, False)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, True)


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def create(key: bytes) -> LOKI97:
    """Return a LOKI97 cipher.  ``key`` must be exactly 32 bytes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes")
    key = bytes(key)
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return LOKI97(key)


# ---------------------------------------------------------------------------
# Self test
# ---------------------------------------------------------------------------

# Verbatim from loki97.c ``_mcrypt_self_test``:
#     #define CIPHER "8cb28c958024bae27a94c698f96f12a9"
# with keyword[j] = (j*2+10) % 256 and plaintext[j] = j % 256.
CIPHER = "8cb28c958024bae27a94c698f96f12a9"


def self_test() -> bool:
    """Verify the C source's known-answer vector and a round trip; silent on success."""
    key = bytes((j * 2 + 10) % 256 for j in range(32))
    pt = bytes(j % 256 for j in range(16))

    cipher = create(key)
    ct = cipher.encrypt_block(pt)
    if ct.hex() != CIPHER:
        return False
    if cipher.decrypt_block(ct) != pt:
        return False

    c2 = create(bytes(range(32)))
    for n in range(8):
        block = bytes((j * 37 + n * 11 + 3) % 256 for j in range(16))
        if c2.decrypt_block(c2.encrypt_block(block)) != block:
            return False

    return True
