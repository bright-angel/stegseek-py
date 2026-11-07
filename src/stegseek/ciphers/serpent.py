"""Pure-Python port of libmcrypt's Serpent (Gladman / Simpson bitsliced).

This is a faithful, line-by-line translation of ``serpent.c`` from libmcrypt
(Dr B. R. Gladman's independent AES-candidate implementation, with the
libmcrypt API wrapper by Nikos Mavroyanopoulos).

The C module works on an in-place 16-byte buffer cast to ``word32 *``.  On
little-endian hosts it reads/writes the words directly; on big-endian hosts it
applies ``byteswap32`` on both load and store.  The net effect is identical in
both cases: the 16 buffer bytes are interpreted as **four little-endian
32-bit words** ``a, b, c, d`` (``block[0:4] -> a`` ... ``block[12:16] -> d``),
and the four result words are written back little-endian in the same order.
The same little-endian word view is used for the 32-byte key (``word32[0..7]``
built from ``key[4*i:4*i+4]``).  ``create()`` fixes the key to 32 bytes,
matching ``mcrypt_enc_get_key_size() == 32`` and block size 16.

Only the Python standard library is used.  This is the *bitsliced* variant:
there are no 4-bit lookup tables to generate -- the eight S-boxes and their
inverses are the boolean macros ``sb0..sb7`` / ``ib0..ib7`` below.  All word
operations are masked to 32 bits (C ``word32``), and the key-schedule / round
S-box index sequences are precomputed at import time.

Public API::

    create(key: bytes) -> _Serpent      # key must be exactly 32 bytes
    _Serpent.block_size == 16
    _Serpent.encrypt_block(block: bytes) -> bytes
    _Serpent.decrypt_block(block: bytes) -> bytes
    self_test() -> bool                 # silent on success
"""

# ``word32`` is an unsigned 32-bit value in the C source.  Every arithmetic
# result is masked back to 32 bits; ``~x`` is written as ``~x & _M32`` so the
# complement stays within 32 bits (Python integers are unbounded).
_M32 = 0xFFFFFFFF

# Golden-ratio constant used by the key schedule.
_PHI = 0x9E3779B9


def _rotl(x, n):
    return ((x << n) | (x >> (32 - n))) & _M32


def _rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & _M32


# ---------------------------------------------------------------------------
# Serpent S-box boolean functions (exact ports of the ``sb*`` / ``ib*`` macros)
#
# Each function maps the four input bit-slices (a, b, c, d) to four output
# bit-slices (e, f, g, h).  The temporary names and assignment order match the
# C macros exactly, including the cases where an output word is used as an
# intermediate later in the same macro.
# ---------------------------------------------------------------------------

def sb0(a, b, c, d):
    t1 = a ^ d
    t2 = a & d
    t3 = c ^ t1
    t6 = b & t1
    t4 = b ^ t3
    t10 = ~t3 & _M32
    h = t2 ^ t4
    t7 = a ^ t6
    t14 = ~t7 & _M32
    t8 = c | t7
    t11 = t3 ^ t7
    g = t4 ^ t8
    t12 = h & t11
    f = t10 ^ t12
    e = t12 ^ t14
    return e, f, g, h


def ib0(a, b, c, d):
    t1 = ~a & _M32
    t2 = a ^ b
    t3 = t1 | t2
    t4 = d ^ t3
    t7 = d & t2
    t5 = c ^ t4
    t8 = t1 ^ t7
    g = t2 ^ t5
    t11 = a & t4
    t9 = g & t8
    t14 = t5 ^ t8
    f = t4 ^ t9
    t12 = t5 | f
    h = t11 ^ t12
    e = h ^ t14
    return e, f, g, h


def sb1(a, b, c, d):
    t1 = ~a & _M32
    t2 = b ^ t1
    t3 = a | t2
    t4 = d | t2
    t5 = c ^ t3
    g = d ^ t5
    t7 = b ^ t4
    t8 = t2 ^ g
    t9 = t5 & t7
    h = t8 ^ t9
    t11 = t5 ^ t7
    f = h ^ t11
    t13 = t8 & t11
    e = t5 ^ t13
    return e, f, g, h


def ib1(a, b, c, d):
    t1 = a ^ d
    t2 = a & b
    t3 = b ^ c
    t4 = a ^ t3
    t5 = b | d
    t7 = c | t1
    h = t4 ^ t5
    t8 = b ^ t7
    t11 = ~t2 & _M32
    t9 = t4 & t8
    f = t1 ^ t9
    t13 = t9 ^ t11
    t12 = h & f
    g = t12 ^ t13
    t15 = a & d
    t16 = c ^ t13
    e = t15 ^ t16
    return e, f, g, h


def sb2(a, b, c, d):
    t1 = ~a & _M32
    t2 = b ^ d
    t3 = c & t1
    t13 = d | t1
    e = t2 ^ t3
    t5 = c ^ t1
    t6 = c ^ e
    t7 = b & t6
    t10 = e | t5
    h = t5 ^ t7
    t9 = d | t7
    t11 = t9 & t10
    t14 = t2 ^ h
    g = a ^ t11
    t15 = g ^ t13
    f = t14 ^ t15
    return e, f, g, h


def ib2(a, b, c, d):
    t1 = b ^ d
    t2 = ~t1 & _M32
    t3 = a ^ c
    t4 = c ^ t1
    t7 = a | t2
    t5 = b & t4
    t8 = d ^ t7
    t11 = ~t4 & _M32
    e = t3 ^ t5
    t9 = t3 | t8
    t14 = d & t11
    h = t1 ^ t9
    t12 = e | h
    f = t11 ^ t12
    t15 = t3 ^ t12
    g = t14 ^ t15
    return e, f, g, h


def sb3(a, b, c, d):
    t1 = a ^ c
    t2 = d ^ t1
    t3 = a & t2
    t4 = d ^ t3
    t5 = b & t4
    g = t2 ^ t5
    t7 = a | g
    t8 = b | d
    t11 = a | d
    t9 = t4 & t7
    f = t8 ^ t9
    t12 = b ^ t11
    t13 = g ^ t9
    t15 = t3 ^ t8
    h = t12 ^ t13
    t16 = c & t15
    e = t12 ^ t16
    return e, f, g, h


def ib3(a, b, c, d):
    t1 = b ^ c
    t2 = b | c
    t3 = a ^ c
    t7 = a ^ d
    t4 = t2 ^ t3
    t5 = d | t4
    t9 = t2 ^ t7
    e = t1 ^ t5
    t8 = t1 | t5
    t11 = a & t4
    g = t8 ^ t9
    t12 = e | t9
    f = t11 ^ t12
    t14 = a & g
    t15 = t2 ^ t14
    t16 = e & t15
    h = t4 ^ t16
    return e, f, g, h


def sb4(a, b, c, d):
    t1 = a ^ d
    t2 = d & t1
    t3 = c ^ t2
    t4 = b | t3
    h = t1 ^ t4
    t6 = ~b & _M32
    t7 = t1 | t6
    e = t3 ^ t7
    t9 = a & e
    t10 = t1 ^ t6
    t11 = t4 & t10
    g = t9 ^ t11
    t13 = a ^ t3
    t14 = t10 & g
    f = t13 ^ t14
    return e, f, g, h


def ib4(a, b, c, d):
    t1 = c ^ d
    t2 = c | d
    t3 = b ^ t2
    t4 = a & t3
    f = t1 ^ t4
    t6 = a ^ d
    t7 = b | d
    t8 = t6 & t7
    h = t3 ^ t8
    t10 = ~a & _M32
    t11 = c ^ h
    t12 = t10 | t11
    e = t3 ^ t12
    t14 = c | t4
    t15 = t7 ^ t14
    t16 = h | t10
    g = t15 ^ t16
    return e, f, g, h


def sb5(a, b, c, d):
    t1 = ~a & _M32
    t2 = a ^ b
    t3 = a ^ d
    t4 = c ^ t1
    t5 = t2 | t3
    e = t4 ^ t5
    t7 = d & e
    t8 = t2 ^ e
    t10 = t1 | e
    f = t7 ^ t8
    t11 = t2 | t7
    t12 = t3 ^ t10
    t14 = b ^ t7
    g = t11 ^ t12
    t15 = f & t12
    h = t14 ^ t15
    return e, f, g, h


def ib5(a, b, c, d):
    t1 = ~c & _M32
    t2 = b & t1
    t3 = d ^ t2
    t4 = a & t3
    t5 = b ^ t1
    h = t4 ^ t5
    t7 = b | h
    t8 = a & t7
    f = t3 ^ t8
    t10 = a | d
    t11 = t1 ^ t7
    e = t10 ^ t11
    t13 = a ^ c
    t14 = b & t10
    t15 = t4 | t13
    g = t14 ^ t15
    return e, f, g, h


def sb6(a, b, c, d):
    t1 = ~a & _M32
    t2 = a ^ d
    t3 = b ^ t2
    t4 = t1 | t2
    t5 = c ^ t4
    f = b ^ t5
    t13 = ~t5 & _M32
    t7 = t2 | f
    t8 = d ^ t7
    t9 = t5 & t8
    g = t3 ^ t9
    t11 = t5 ^ t8
    e = g ^ t11
    t14 = t3 & t11
    h = t13 ^ t14
    return e, f, g, h


def ib6(a, b, c, d):
    t1 = ~a & _M32
    t2 = a ^ b
    t3 = c ^ t2
    t4 = c | t1
    t5 = d ^ t4
    t13 = d & t1
    f = t3 ^ t5
    t7 = t3 & t5
    t8 = t2 ^ t7
    t9 = b | t8
    h = t5 ^ t9
    t11 = b | h
    e = t8 ^ t11
    t14 = t3 ^ t11
    g = t13 ^ t14
    return e, f, g, h


def sb7(a, b, c, d):
    t1 = ~c & _M32
    t2 = b ^ c
    t3 = b | t1
    t4 = d ^ t3
    t5 = a & t4
    t7 = a ^ d
    h = t2 ^ t5
    t8 = b ^ t5
    t9 = t2 | t8
    t11 = d & t3
    f = t7 ^ t9
    t12 = t5 ^ f
    t15 = t1 | t4
    t13 = h & t12
    g = t11 ^ t13
    t16 = t12 ^ g
    e = t15 ^ t16
    return e, f, g, h


def ib7(a, b, c, d):
    t1 = a & b
    t2 = a | b
    t3 = c | t1
    t4 = d & t2
    h = t3 ^ t4
    t6 = ~d & _M32
    t7 = b ^ t4
    t8 = h ^ t6
    t11 = c ^ t7
    t9 = t7 | t8
    f = a ^ t9
    t12 = d | f
    e = t11 ^ t12
    t14 = a & h
    t15 = t3 ^ f
    t16 = e ^ t14
    g = t15 ^ t16
    return e, f, g, h


_SBOX = (sb0, sb1, sb2, sb3, sb4, sb5, sb6, sb7)
_ISBOX = (ib0, ib1, ib2, ib3, ib4, ib5, ib6, ib7)

# Key-schedule S-box order (serpent.c ``_mcrypt_set_key``, r = 0..32):
#   sb3, sb2, sb1, sb0, sb7, sb6, sb5, sb4, sb3, ...  == (3 - r) % 8
_KEY_SCHEDULE_SBOX = tuple((3 - r) % 8 for r in range(33))
# Round S-box order (serpent.c ``_mcrypt_encrypt``, r = 0..31): r % 8.
_ROUND_SBOX = tuple(r % 8 for r in range(32))


# ---------------------------------------------------------------------------
# Linear transformation and its inverse (exact ports of ``rot`` / ``irot``)
# ---------------------------------------------------------------------------

def _rot(a, b, c, d):
    a = _rotl(a, 13)
    c = _rotl(c, 3)
    d = (d ^ c ^ (a << 3)) & _M32
    b = (b ^ a ^ c) & _M32
    d = _rotl(d, 7)
    b = _rotl(b, 1)
    a = (a ^ b ^ d) & _M32
    c = (c ^ d ^ (b << 7)) & _M32
    a = _rotl(a, 5)
    c = _rotl(c, 22)
    return a, b, c, d


def _irot(a, b, c, d):
    c = _rotr(c, 22)
    a = _rotr(a, 5)
    c = (c ^ d ^ (b << 7)) & _M32
    a = (a ^ b ^ d) & _M32
    d = _rotr(d, 7)
    b = _rotr(b, 1)
    d = (d ^ c ^ (a << 3)) & _M32
    b = (b ^ a ^ c) & _M32
    c = _rotr(c, 3)
    a = _rotr(a, 13)
    return a, b, c, d


# ---------------------------------------------------------------------------
# Cipher instance
# ---------------------------------------------------------------------------

class _Serpent:
    """One instantiated 256-bit Serpent key schedule."""

    block_size = 16

    def __init__(self, key: bytes):
        # Port of ``_mcrypt_set_key`` (key_len == 32 -> 256 bits, lk == 8).
        l_key = [0] * 140
        for i in range(8):
            l_key[i] = int.from_bytes(key[4 * i:4 * i + 4], "little")

        # key_len == 256, so the ``key_len < 256`` padding branch is skipped.
        for i in range(132):
            lk = (l_key[i] ^ l_key[i + 3] ^ l_key[i + 5] ^ l_key[i + 7]
                  ^ _PHI ^ i)
            l_key[i + 8] = ((lk << 11) | (lk >> 21)) & _M32  # rotl32(lk, 11)

        # Apply the forward S-boxes to the 33 four-word subkeys, in place.
        for r, si in enumerate(_KEY_SCHEDULE_SBOX):
            a, b, c, d = l_key[4 * r + 8:4 * r + 12]
            e, f, g, h = _SBOX[si](a, b, c, d)
            l_key[4 * r + 8:4 * r + 12] = e, f, g, h

        self._subkeys = tuple(
            (l_key[4 * r + 8], l_key[4 * r + 9],
             l_key[4 * r + 10], l_key[4 * r + 11])
            for r in range(33)
        )

    # -- port of ``_mcrypt_encrypt`` ----------------------------------------

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must be exactly 16 bytes")
        a = int.from_bytes(block[0:4], "little")
        b = int.from_bytes(block[4:8], "little")
        c = int.from_bytes(block[8:12], "little")
        d = int.from_bytes(block[12:16], "little")
        sk = self._subkeys

        # Rounds 0..30: k_xor(r), sb(r%8), rot(...).  The round state just
        # ping-pongs between the two variable sets in the C source.
        for r in range(31):
            k0, k1, k2, k3 = sk[r]
            e, f, g, h = _SBOX[_ROUND_SBOX[r]](
                a ^ k0, b ^ k1, c ^ k2, d ^ k3)
            a, b, c, d = _rot(e, f, g, h)

        # Round 31: k_xor(31), sb7, then k_xor(32) instead of a rot().
        k0, k1, k2, k3 = sk[31]
        e, f, g, h = _SBOX[7](a ^ k0, b ^ k1, c ^ k2, d ^ k3)
        k0, k1, k2, k3 = sk[32]
        a, b, c, d = e ^ k0, f ^ k1, g ^ k2, h ^ k3

        return b"".join(x.to_bytes(4, "little") for x in (a, b, c, d))

    # -- port of ``_mcrypt_decrypt`` ----------------------------------------

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != 16:
            raise ValueError("block must be exactly 16 bytes")
        a = int.from_bytes(block[0:4], "little")
        b = int.from_bytes(block[4:8], "little")
        c = int.from_bytes(block[8:12], "little")
        d = int.from_bytes(block[12:16], "little")
        sk = self._subkeys

        # k_xor(32), ib7, k_xor(31)  ->  state after round 31's inverse S-box.
        k0, k1, k2, k3 = sk[32]
        e, f, g, h = _ISBOX[7](a ^ k0, b ^ k1, c ^ k2, d ^ k3)
        k0, k1, k2, k3 = sk[31]
        a, b, c, d = e ^ k0, f ^ k1, g ^ k2, h ^ k3

        # Rounds 30..0: irot(), ib(r%8), k_xor(r).  No trailing irot().
        for r in range(30, -1, -1):
            a, b, c, d = _irot(a, b, c, d)
            e, f, g, h = _ISBOX[_ROUND_SBOX[r]](a, b, c, d)
            k0, k1, k2, k3 = sk[r]
            a, b, c, d = e ^ k0, f ^ k1, g ^ k2, h ^ k3

        return b"".join(x.to_bytes(4, "little") for x in (a, b, c, d))


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def create(key: bytes) -> "_Serpent":
    """Return a Serpent cipher instance.  ``key`` must be exactly 32 bytes."""
    key = bytes(key)
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return _Serpent(key)


# ---------------------------------------------------------------------------
# Self test
# ---------------------------------------------------------------------------

# Verbatim from serpent.c ``_mcrypt_self_test``:
#     #define CIPHER "9a99455df5080bfccadf049b5aaf7d61"
# with keyword[j] = (j*2+10) % 256 and plaintext[j] = j % 256.
CIPHER = "9a99455df5080bfccadf049b5aaf7d61"


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

    # A few more deterministic encrypt/decrypt round trips.
    c2 = create(bytes(range(32)))
    for n in range(8):
        block = bytes((j * 37 + n * 11 + 3) % 256 for j in range(16))
        if c2.decrypt_block(c2.encrypt_block(block)) != block:
            return False

    return True
