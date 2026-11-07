"""Pure-Python port of libmcrypt's Twofish (Brian Gladman / libmcrypt).

Faithful translation of ``_reference/libsrc/algorithms/twofish.c``.

Byte / word order (matching the C code on a little-endian Windows host, i.e.
``WORDS_BIGENDIAN`` is *not* defined):

* A 16-byte block is treated as four little-endian ``word32`` values.  The
  buffer's bytes 0..3 become word 0, 4..7 word 1, and so on.  The key is
  consumed the same way (as ``len(key)//4`` little-endian ``word32`` values).
* ``byte(x, n)`` in the C source is ``(x >> (8 * n)) & 0xff`` -- byte ``n``
  of a 32-bit word.
* ``_mcrypt_encrypt`` / ``_mcrypt_decrypt`` operate in place on that word
  array.  Both apply input whitening with ``l_key[0..3]`` / ``l_key[4..7]``
  and output whitening with the other four words, and both swap the two word
  pairs on output (``out[0]=blk[2], out[1]=blk[3], out[2]=blk[0],
  out[3]=blk[1]``).

libmcrypt calls ``_mcrypt_set_key(key, keylen)`` with ``keylen == 32`` for
steghide, so ``create()`` requires a 32-byte key (``pkey->k_len == 4``).  The
C ``_mcrypt_self_test()`` vector, however, uses a 16-byte key
(``pkey->k_len == 2``); the internal ``Twofish`` class accepts 16/24/32 byte
keys so that vector can be checked too (see ``self_test``).

The q permutation tables and the MDS tables are precomputed at import time.
Only the Python standard library is used.
"""

_MASK = 0xFFFFFFFF

# ---------------------------------------------------------------------------
# finite field arithmetic, GF(2**8) with modulus x^8+x^6+x^5+x^3+1 (0x169)
# ---------------------------------------------------------------------------

_G_M = 0x0169
_tab_5b = (0, _G_M >> 2, _G_M >> 1, (_G_M >> 1) ^ (_G_M >> 2))
_tab_ef = (0, (_G_M >> 1) ^ (_G_M >> 2), _G_M >> 1, _G_M >> 2)

_ror4 = (0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15)
_ashx = (0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7)

_qt0 = (
    (8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4),
    (2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5),
)
_qt1 = (
    (14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13),
    (1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8),
)
_qt2 = (
    (11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1),
    (4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15),
)
_qt3 = (
    (13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10),
    (11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10),
)

_G_MOD = 0x0000014D


def _ffm_5b(x):
    return (x ^ (x >> 2) ^ _tab_5b[x & 3]) & 0xFF


def _ffm_ef(x):
    return (x ^ (x >> 1) ^ (x >> 2) ^ _tab_ef[x & 3]) & 0xFF


def _qp(n, x):
    """The q0 / q1 permutations (``qp`` in the C source)."""
    a0 = x >> 4
    b0 = x & 15
    a1 = a0 ^ b0
    b1 = _ror4[b0] ^ _ashx[a0]
    a2 = _qt0[n][a1]
    b2 = _qt1[n][b1]
    a3 = a2 ^ b2
    b3 = _ror4[b2] ^ _ashx[a2]
    a4 = _qt2[n][a3]
    b4 = _qt3[n][b3]
    return ((b4 << 4) | a4) & 0xFF


# -- tables built once, at import (key independent) --------------------------

# Q_TABLES: q(n, x) == qp(n, x)
_Q_TAB = (
    tuple(_qp(0, i) for i in range(256)),
    tuple(_qp(1, i) for i in range(256)),
)

# M_TABLE: mds(n, x) == m_tab[n][x]
#   m_tab[n][i] = f_0(n,q_n(i)) ^ f_1(..)<<8 ^ f_2(..)<<16 ^ f_3(..)<<24
#   with q_0=q_2=q(1,.), q_1=q_3=q(0,.) and the fm_nn byte functions.  Because
#   the four bytes are in disjoint positions, "+" == "^" here.
_M_TAB = [[0] * 256 for _ in range(4)]
for _i in range(256):
    _f01 = _Q_TAB[1][_i]
    _f5b = _ffm_5b(_f01)
    _fef = _ffm_ef(_f01)
    _M_TAB[0][_i] = (_f01 + (_f5b << 8) + (_fef << 16) + (_fef << 24)) & _MASK
    _M_TAB[2][_i] = (_f5b + (_fef << 8) + (_f01 << 16) + (_fef << 24)) & _MASK
    _f01 = _Q_TAB[0][_i]
    _f5b = _ffm_5b(_f01)
    _fef = _ffm_ef(_f01)
    _M_TAB[1][_i] = (_fef + (_fef << 8) + (_f5b << 16) + (_f01 << 24)) & _MASK
    _M_TAB[3][_i] = (_f5b + (_f01 << 8) + (_fef << 16) + (_f5b << 24)) & _MASK
_M_TAB = tuple(tuple(row) for row in _M_TAB)


def _q(n, x):
    return _Q_TAB[n][x]


def _byte(x, n):
    """``byte(x, n)`` macro: byte n (little-endian) of a word32."""
    return (x >> (8 * n)) & 0xFF


def _rotl32(x, n):
    x &= _MASK
    return ((x << n) | (x >> (32 - n))) & _MASK


def _rotr32(x, n):
    x &= _MASK
    return ((x >> n) | (x << (32 - n))) & _MASK


def _mds_rem(p0, p1):
    """Reed-Solomon (12,8) remainder (``mds_rem``), all word32 arithmetic."""
    p0 &= _MASK
    p1 &= _MASK
    for _ in range(8):
        t = p1 >> 24                       # most significant coefficient
        p1 = ((p1 << 8) | (p0 >> 24)) & _MASK
        p0 = (p0 << 8) & _MASK
        u = t << 1
        if t & 0x80:
            u ^= _G_MOD
        p1 = (p1 ^ t ^ (u << 16)) & _MASK
        u ^= (t >> 1)
        if t & 0x01:
            u ^= _G_MOD >> 1
        p1 = (p1 ^ ((u << 24) | (u << 8))) & _MASK
    return p1 & _MASK


# ---------------------------------------------------------------------------
# cipher
# ---------------------------------------------------------------------------

class Twofish:
    """Twofish block cipher; ``block_size == 16``.

    ``create()`` is the public entry point (enforces the 32-byte key).  The
    class itself accepts 16, 24 or 32 byte keys so ``self_test`` can exercise
    the C file's 16-byte known-answer vector as well.
    """

    block_size = 16

    def __init__(self, key):
        key = bytes(key)
        n = len(key)
        if n not in (16, 24, 32):
            raise ValueError("key must be 16, 24 or 32 bytes")
        self.k_len = n // 8                     # (keylen*8)/64 -> 2,3,4

        words = [int.from_bytes(key[4 * i:4 * i + 4], "little")
                 for i in range(n // 4)]
        me_key = [0] * self.k_len
        mo_key = [0] * self.k_len
        s_key = [0] * self.k_len
        for i in range(self.k_len):
            a = words[2 * i]
            b = words[2 * i + 1]
            me_key[i] = a
            mo_key[i] = b
            s_key[self.k_len - i - 1] = _mds_rem(a, b)
        self.s_key = s_key

        l_key = [0] * 40
        for i in range(0, 40, 2):
            a = (0x01010101 * i) & _MASK
            b = (a + 0x01010101) & _MASK
            a = self._h_fun(a, me_key)
            b = _rotl32(self._h_fun(b, mo_key), 8)
            l_key[i] = (a + b) & _MASK
            l_key[i + 1] = _rotl32((a + 2 * b) & _MASK, 9)
        self.l_key = l_key

    def _h_fun(self, x, key):
        """The h() function; ``key`` is me_key/mo_key or s_key.

        The C ``switch (pkey->k_len)`` has no breaks: case 4 falls through to
        case 3 and then case 2.  Reproduced with cascading ifs (case 2 always
        runs since k_len >= 2).
        """
        b0 = x & 0xFF
        b1 = (x >> 8) & 0xFF
        b2 = (x >> 16) & 0xFF
        b3 = (x >> 24) & 0xFF
        k_len = self.k_len

        if k_len >= 4:                                   # case 4
            b0 = _q(1, b0) ^ _byte(key[3], 0)
            b1 = _q(0, b1) ^ _byte(key[3], 1)
            b2 = _q(0, b2) ^ _byte(key[3], 2)
            b3 = _q(1, b3) ^ _byte(key[3], 3)
        if k_len >= 3:                                   # case 3
            b0 = _q(1, b0) ^ _byte(key[2], 0)
            b1 = _q(1, b1) ^ _byte(key[2], 1)
            b2 = _q(0, b2) ^ _byte(key[2], 2)
            b3 = _q(0, b3) ^ _byte(key[2], 3)
        # case 2 (always executed, k_len >= 2)
        b0 = _q(0, _q(0, b0) ^ _byte(key[1], 0)) ^ _byte(key[0], 0)
        b1 = _q(0, _q(1, b1) ^ _byte(key[1], 1)) ^ _byte(key[0], 1)
        b2 = _q(1, _q(0, b2) ^ _byte(key[1], 2)) ^ _byte(key[0], 2)
        b3 = _q(1, _q(1, b3) ^ _byte(key[1], 3)) ^ _byte(key[0], 3)

        return (_M_TAB[0][b0] ^ _M_TAB[1][b1] ^
                _M_TAB[2][b2] ^ _M_TAB[3][b3]) & _MASK

    # g0_fun(x) = h(x, s_key); g1_fun(x) = h(rotl32(x, 8), s_key)
    def _g0(self, x):
        return self._h_fun(x, self.s_key)

    def _g1(self, x):
        return self._h_fun(_rotl32(x, 8), self.s_key)

    def _encrypt_words(self, w):
        lk = self.l_key
        blk = [w[0] ^ lk[0], w[1] ^ lk[1], w[2] ^ lk[2], w[3] ^ lk[3]]
        for i in range(8):
            t1 = self._g1(blk[1])
            t0 = self._g0(blk[0])
            blk[2] = _rotr32(blk[2] ^ ((t0 + t1 + lk[4 * i + 8]) & _MASK), 1)
            blk[3] = (_rotl32(blk[3], 1) ^
                      ((t0 + 2 * t1 + lk[4 * i + 9]) & _MASK)) & _MASK
            t1 = self._g1(blk[3])
            t0 = self._g0(blk[2])
            blk[0] = _rotr32(blk[0] ^ ((t0 + t1 + lk[4 * i + 10]) & _MASK), 1)
            blk[1] = (_rotl32(blk[1], 1) ^
                      ((t0 + 2 * t1 + lk[4 * i + 11]) & _MASK)) & _MASK
        return [blk[2] ^ lk[4], blk[3] ^ lk[5],
                blk[0] ^ lk[6], blk[1] ^ lk[7]]

    def _decrypt_words(self, w):
        lk = self.l_key
        blk = [w[0] ^ lk[4], w[1] ^ lk[5], w[2] ^ lk[6], w[3] ^ lk[7]]
        for i in range(7, -1, -1):
            t1 = self._g1(blk[1])
            t0 = self._g0(blk[0])
            blk[2] = (_rotl32(blk[2], 1) ^
                      ((t0 + t1 + lk[4 * i + 10]) & _MASK)) & _MASK
            blk[3] = _rotr32(
                blk[3] ^ ((t0 + 2 * t1 + lk[4 * i + 11]) & _MASK), 1)
            t1 = self._g1(blk[3])
            t0 = self._g0(blk[2])
            blk[0] = (_rotl32(blk[0], 1) ^
                      ((t0 + t1 + lk[4 * i + 8]) & _MASK)) & _MASK
            blk[1] = _rotr32(
                blk[1] ^ ((t0 + 2 * t1 + lk[4 * i + 9]) & _MASK), 1)
        return [blk[2] ^ lk[0], blk[3] ^ lk[1],
                blk[0] ^ lk[2], blk[1] ^ lk[3]]

    @staticmethod
    def _to_words(block):
        return [int.from_bytes(block[4 * i:4 * i + 4], "little")
                for i in range(4)]

    @staticmethod
    def _from_words(w):
        return b"".join((x & _MASK).to_bytes(4, "little") for x in w)

    def encrypt_block(self, block: bytes) -> bytes:
        block = bytes(block)
        if len(block) != 16:
            raise ValueError("block must be exactly 16 bytes")
        return self._from_words(self._encrypt_words(self._to_words(block)))

    def decrypt_block(self, block: bytes) -> bytes:
        block = bytes(block)
        if len(block) != 16:
            raise ValueError("block must be exactly 16 bytes")
        return self._from_words(self._decrypt_words(self._to_words(block)))


# ---------------------------------------------------------------------------
# public factory
# ---------------------------------------------------------------------------

def create(key: bytes) -> Twofish:
    """Return a Twofish cipher for a 32-byte KEYGEN_MCRYPT key.

    libmcrypt/steghide always uses ``mcrypt_enc_get_key_size() == 32`` bytes,
    i.e. ``pkey->k_len == 4``.
    """
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes")
    key = bytes(key)
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return Twofish(key)


# ---------------------------------------------------------------------------
# self test
# ---------------------------------------------------------------------------

def self_test() -> bool:
    """Verify the C source's known-answer vector; print nothing on success.

    ``twofish.c`` ``_mcrypt_self_test()`` defines::

        CIPHER "019f9809de1711858faac3a3ba20fbc3"
        PT     "D491DB16E7B1C39E86CB086B789F5419"
        KEY    "9F589F5CF6122C32B6BFEC2F2AE8C35A"

    That vector uses a **16-byte** key (pkey->k_len == 2), while
    libmcrypt/steghide uses a 32-byte key (k_len == 4).  We therefore also
    verify a 32-byte-key encrypt/decrypt round trip through ``create()``.
    """
    key = bytes.fromhex("9F589F5CF6122C32B6BFEC2F2AE8C35A")
    pt = bytes.fromhex("D491DB16E7B1C39E86CB086B789F5419")
    cipher = bytes.fromhex("019f9809de1711858faac3a3ba20fbc3")

    c = Twofish(key)                                   # 16-byte KAT key
    if c.encrypt_block(pt) != cipher:
        return False
    if c.decrypt_block(cipher) != pt:
        return False

    c2 = create(bytes(range(32)))                      # 32-byte steghide key
    sample = bytes.fromhex("00112233445566778899aabbccddeeff")
    if c2.decrypt_block(c2.encrypt_block(sample)) != sample:
        return False

    return True
