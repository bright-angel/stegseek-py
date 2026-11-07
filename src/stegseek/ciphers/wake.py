"""Pure-Python port of libmcrypt's ``wake`` stream cipher.

Faithful translation of ``_reference/libsrc/algorithms/wake.c`` (David J.
Wheeler's "Word Auto Key Encryption", wrapped for libmcrypt by Nikos
Mavroyanopoulos).  Block size is 1 (a stream algorithm); ``create()`` fixes the
key to exactly 32 bytes (``mcrypt_enc_get_key_size() == 32``).  NOTE: although
``_mcrypt_set_key`` checks ``len == 32``, it only reads ``key[0..3]`` -- the
first 16 bytes as four little-endian ``word32`` values -- so the trailing 16
bytes of the 32-byte key are ignored by libmcrypt.  This port reproduces that.

libmcrypt's ``mcrypt_generic()`` calls ``_mcrypt_encrypt(key, buffer, len)``
with the *whole* buffer, so ``encrypt``/``decrypt`` are stateful: the four
registers ``r[0..3]``, the byte ``counter`` (0..3) and the partial word ``tmp``
advance across the entire buffer and across successive calls.  A buffer whose
length is not a multiple of 4 leaves ``counter``/``tmp`` mid-word; the next
call resumes from there -- exactly what the C ``WAKE_KEY`` struct does.  There
is therefore no block-alignment requirement on buffer lengths.

Exact C semantics reproduced here (little-endian host, ``WORDS_BIGENDIAN`` and
``USE_IV`` both undefined, as in the reference build -- cf. gost.py/serpent.py):
  * ``M(X,Y) = ((X+Y) >> 8 & 0x00ffffff) ^ t[(X+Y) & 0xff]`` with all
    arithmetic modulo 2**32 (``word32``).
  * ``((byte*)&r6)[counter]`` and ``((byte*)&r1/r2)[counter]`` access the
    little-endian in-memory bytes of a ``word32``; byte ``c`` of a word ``w``
    is ``(w >> (8*c)) & 0xff``.  No ``byteswap32`` is applied in the
    little-endian branch, so the words are used directly.
  * In both loops the feedback word written into ``tmp`` is the *ciphertext*
    byte (encrypt: ``input[i]`` after the XOR; decrypt: ``input[i]`` before
    the XOR), which is why decrypt reverses encrypt.
  * ``r1`` and ``r2`` are both ``#define``d to the single struct member
    ``wake_key->tmp``; they are never needed at the same time, so one word
    suffices.  ``r3..r6`` map to ``wake_key->r[0..3]`` and are persisted at
    the end of each call.

Only the Python standard library is used.

Public API::

    create(key: bytes) -> _Wake        # key must be exactly 32 bytes
    _Wake.block_size == 1
    _Wake.encrypt(data: bytes) -> bytes
    _Wake.decrypt(data: bytes) -> bytes
    self_test() -> bool                # silent on success
"""

from __future__ import annotations

_M32 = 0xFFFFFFFF

# wake.c ``static const word32 tt[10]`` (only tt[0..7] are used: tt[x & 7]).
_TT = (
    0x726A8F3B, 0xE69A3B5C, 0xD3C71FE5, 0xAB3C73D2,
    0x4D3A8EB3, 0x0396D6E8, 0x3D4C2F7A, 0x9EE27CF3,
)


class _Wake:
    block_size = 1

    def __init__(self, key: bytes) -> None:
        # word32 k[4] built from the first 16 key bytes, little-endian
        # (WORDS_BIGENDIAN undefined -> no byteswap).  Bytes 16..31 of key
        # are ignored by the C _mcrypt_set_key.
        k = [
            key[0] | (key[1] << 8) | (key[2] << 16) | (key[3] << 24),
            key[4] | (key[5] << 8) | (key[6] << 16) | (key[7] << 24),
            key[8] | (key[9] << 8) | (key[10] << 16) | (key[11] << 24),
            key[12] | (key[13] << 8) | (key[14] << 16) | (key[15] << 24),
        ]

        t = [0] * 257
        for p in range(4):
            t[p] = k[p]
        for p in range(4, 256):
            x = (t[p - 4] + t[p - 1]) & _M32
            t[p] = ((x >> 3) ^ _TT[x & 7]) & _M32
        for p in range(23):
            t[p] = (t[p] + t[p + 89]) & _M32

        x = t[33]
        z = (t[59] | 0x01000001) & 0xFF7FFFFF
        for p in range(256):
            x = ((x & 0xFF7FFFFF) + z) & _M32
            t[p] = ((t[p] & 0x00FFFFFF) ^ x) & _M32

        t[256] = t[0]
        x &= 0xFF
        for p in range(256):
            # C: t[p] = t[x = (t[p ^ x] ^ x) & 0xff];  t[x] = t[p + 1];
            # The RHS reads the *old* x, then assigns the new x.
            x = (t[p ^ x] ^ x) & 0xFF
            t[p] = t[x]
            t[x] = t[p + 1]

        self.t = t
        # wake_key->r[0..3] == r3,r4,r5,r6; r6 (r[3]) produces keystream.
        self.r = [k[0], k[1], k[2], k[3]]
        self.counter = 0            # wake_key->counter
        self.tmp = 0                # wake_key->tmp (a.k.a. r1 / r2)

    def _M(self, x: int, y: int) -> int:
        tmp = (x + y) & _M32
        return ((tmp >> 8) & 0x00FFFFFF) ^ self.t[tmp & 0xFF]

    def _advance(self) -> None:
        """counter hit 4: refresh r3..r6 from the completed feedback word."""
        self.counter = 0
        self.r[0] = self._M(self.r[0], self.tmp)   # r3 = M(r3, r2)
        self.r[1] = self._M(self.r[1], self.r[0])  # r4 = M(r4, r3)
        self.r[2] = self._M(self.r[2], self.r[1])  # r5 = M(r5, r4)
        self.r[3] = self._M(self.r[3], self.r[2])  # r6 = M(r6, r5)

    def _set_byte(self, value: int) -> None:
        """``((byte*)&tmp)[counter] = value`` on a little-endian word32."""
        shift = 8 * self.counter
        mask = 0xFF << shift
        self.tmp = ((self.tmp & ~mask) | (value << shift)) & _M32

    def _keystream_byte(self) -> int:
        """``((byte*)&r6)[counter]`` on a little-endian word32."""
        return (self.r[3] >> (8 * self.counter)) & 0xFF

    def encrypt(self, data: bytes) -> bytes:
        data = bytes(data)
        out = bytearray(len(data))
        for i, ch in enumerate(data):
            cipher_byte = ch ^ self._keystream_byte()
            out[i] = cipher_byte
            self._set_byte(cipher_byte)      # r2[counter] = ciphertext byte
            self.counter += 1
            if self.counter == 4:
                self._advance()
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        data = bytes(data)
        out = bytearray(len(data))
        for i, ch in enumerate(data):
            self._set_byte(ch)               # r1[counter] = ciphertext byte
            out[i] = ch ^ self._keystream_byte()
            self.counter += 1
            if self.counter == 4:
                self._advance()
        return bytes(out)


def create(key: bytes) -> _Wake:
    """Return a WAKE stream cipher; ``key`` must be exactly 32 bytes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes")
    key = bytes(key)
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return _Wake(key)


# Verbatim from wake.c ``_mcrypt_self_test``:
#     #define CIPHER "434d575db053acfe6e4076f05298bedbd5f4f000be555d029b1367cffc7cd51bba61c76aa17da3530fb7d9"
# keyword[j] = (j*5 + 10) & 0xff for j in 0..31 (32 bytes),
# plaintext[j] = (j+5) % 0xff for j in 0..42 (43 bytes), blocksize = 43.
CIPHER = "434d575db053acfe6e4076f05298bedbd5f4f000be555d029b1367cffc7cd51bba61c76aa17da3530fb7d9"


def self_test() -> bool:
    """Verify the C known-answer vector and a round trip; silent on success."""
    key = bytes((j * 5 + 10) & 0xFF for j in range(32))
    pt = bytes((j + 5) % 0xFF for j in range(43))

    ct = create(key).encrypt(pt)
    if ct.hex() != CIPHER:
        return False
    if create(key).decrypt(ct) != pt:      # fresh state for decryption
        return False

    # Stateful whole-buffer semantics: split calls must equal one big call.
    # 17 is deliberately not a multiple of 4, so it exercises the mid-word
    # carry of counter/tmp across calls as well.
    a = create(key)
    if a.encrypt(pt[:17]) + a.encrypt(pt[17:]) != ct:
        return False
    b = create(key)
    if b.decrypt(ct[:17]) + b.decrypt(ct[17:]) != pt:
        return False

    return True
