"""Pure-Python port of libmcrypt's ``enigma`` stream cipher.

Faithful translation of ``_reference/libsrc/algorithms/enigma.c`` (the
public-domain "one-rotor" UNIX ``crypt`` replacement, wrapped for libmcrypt
by Nikos Mavroyanopoulos).  Block size is 1 (a stream algorithm); ``create()``
fixes the key to exactly 13 bytes (``mcrypt_enc_get_key_size() == 13``).

libmcrypt's ``mcrypt_generic()`` calls ``_mcrypt_encrypt(key, buffer, len)``
with the *whole* buffer, so ``encrypt``/``decrypt`` are stateful: the rotor
counters advance across the entire buffer and across successive calls.  A
buffer of any length is fine -- there is no per-block alignment requirement.

Encryption and decryption are the SAME operation: the C ``_mcrypt_encrypt``
and ``_mcrypt_decrypt`` bodies are byte-for-byte identical (the cipher is a
reciprocal involution), so both methods share one ``_crypt`` implementation.
Note this means a fresh ``create()`` must be used for decrypt (the C self test
re-runs ``_mcrypt_set_key``), which is exactly how the Python API is used.

Exact C semantics reproduced here (from libmcrypt's ``enigma.h`` / libdefs.h):
  * ``ROTORSZ == 256``, ``MASK == 0377`` (octal) ``== 0xff``.
  * The CRYPT_KEY tables ``t1/t2/t3/deck`` and ``cbuf[13]`` are plain ``char``,
    i.e. *signed* on the little-endian x86 host used as reference (an Ubuntu
    patch exists that forces ``signed char`` to fix ARM, where plain ``char``
    is unsigned).  ``cbuf`` is therefore read as signed bytes (-128..127);
    the tables are kept here as 0..255 because every table read is masked with
    ``& MASK``, which makes the signed/unsigned representation equivalent.
  * ``seed`` is ``sword32`` (signed 32-bit).  The key-schedule arithmetic wraps
    modulo 2**32 as a *signed* value, and ``seed % 65521`` is C's truncated
    remainder (sign follows the dividend) assigned to an ``unsigned`` 32-bit
    ``random``.
  * ``secureflg`` is hard-coded to 0 in both C entry points, so the ``deck``
    shuffle path (and ``shuffle()``) is dead code and is omitted.  ``nr1`` is
    simply ``n1``; ``nr2`` equals ``n2`` and is only refreshed when ``n1``
    wraps from 255 back to 0.

Only the Python standard library is used.

Public API::

    create(key: bytes) -> _Enigma      # key must be exactly 13 bytes
    _Enigma.block_size == 1
    _Enigma.encrypt(data: bytes) -> bytes
    _Enigma.decrypt(data: bytes) -> bytes
    self_test() -> bool                # silent on success
"""

from __future__ import annotations

_ROTORSZ = 256
_MASK = 0xFF


def _s32(value: int) -> int:
    """Wrap ``value`` to a signed 32-bit integer (C ``sword32``)."""
    value &= 0xFFFFFFFF
    return value - 0x100000000 if value & 0x80000000 else value


def _c_rem(a: int, b: int) -> int:
    """C's truncated ``%`` (result takes the sign of ``a``), for ``b > 0``.

    Python's ``%`` is a floor remainder and would give a different result for
    a negative ``seed``; the C reference uses truncated division.
    """
    r = abs(a) % b
    return -r if a < 0 else r


class _Enigma:
    block_size = 1

    def __init__(self, key: bytes) -> None:
        # cbuf[13]: plain ``char`` -> signed on the reference host.  Bzero()
        # zero-fills the struct, then memmove() copies plen (==13) key bytes.
        cbuf = [b - 256 if b >= 128 else b for b in key[:13]]

        # Bzero(CRYPT_KEY): t1/t2/t3/deck = 0, n1=n2=nr1=nr2 = 0.
        t1 = [0] * _ROTORSZ
        t2 = [0] * _ROTORSZ
        t3 = [0] * _ROTORSZ
        self.n1 = 0
        self.n2 = 0
        self.nr2 = 0

        seed = 123
        for i in range(13):
            seed = _s32(seed * cbuf[i] + i)

        for i in range(_ROTORSZ):
            t1[i] = i
            # deck[i] = i; deck is unused because secureflg == 0.

        for i in range(_ROTORSZ):
            seed = _s32(5 * seed + cbuf[i % 13])
            random = _c_rem(seed, 65521) & 0xFFFFFFFF
            k = _ROTORSZ - 1 - i
            ic = (random & _MASK) % (k + 1)
            random >>= 8
            temp = t1[k]
            t1[k] = t1[ic]
            t1[ic] = temp
            if t3[k] != 0:
                continue
            # For k == 0 the C code would evaluate ``% k`` (division by zero,
            # undefined behaviour).  In practice t3[0] is already non-zero by
            # the last iteration so the ``continue`` above fires; guard anyway.
            if k == 0:
                continue
            ic = (random & _MASK) % k
            while t3[ic] != 0:
                ic = (ic + 1) % k
            t3[k] = ic
            t3[ic] = k

        for i in range(_ROTORSZ):
            t2[t1[i] & _MASK] = i

        self.t1 = t1
        self.t2 = t2
        self.t3 = t3

    def _crypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        t1, t2, t3 = self.t1, self.t2, self.t3
        for j, ch in enumerate(data):
            nr1 = self.n1           # secureflg == 0 -> nr1 = n1
            nr2 = self.nr2          # only refreshed when n1 wraps
            v1 = t1[(ch + nr1) & _MASK]
            v3 = t3[(v1 + nr2) & _MASK]
            v2 = t2[(v3 - nr2) & _MASK]
            out[j] = (v2 - nr1) & _MASK
            self.n1 += 1
            if self.n1 == _ROTORSZ:
                self.n1 = 0
                self.n2 += 1
                if self.n2 == _ROTORSZ:
                    self.n2 = 0
                self.nr2 = self.n2  # secureflg == 0 branch
        return bytes(out)

    def encrypt(self, data: bytes) -> bytes:
        return self._crypt(bytes(data))

    def decrypt(self, data: bytes) -> bytes:
        return self._crypt(bytes(data))


def create(key: bytes) -> _Enigma:
    """Return an Enigma stream cipher; ``key`` must be exactly 13 bytes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes")
    key = bytes(key)
    if len(key) != 13:
        raise ValueError("key must be exactly 13 bytes")
    return _Enigma(key)


# Verbatim from enigma.c ``_mcrypt_self_test``:
#     #define CIPHER "f3edda7da20f8975884600f014d32c7a08e59d7b"
# keyword = "enadyotr" placed in a calloc(1, 13) buffer (13 bytes, the unused
# tail zero-filled), plaintext[j] = j % 256 for j in 0..19, blocksize = 20.
CIPHER = "f3edda7da20f8975884600f014d32c7a08e59d7b"


def self_test() -> bool:
    """Verify the C known-answer vector and a round trip; silent on success."""
    key = b"enadyotr\x00\x00\x00\x00\x00"   # 13 bytes: strcpy + calloc tail
    pt = bytes(j % 256 for j in range(20))

    ct = create(key).encrypt(pt)
    if ct.hex() != CIPHER:
        return False
    if create(key).decrypt(ct) != pt:      # fresh state, reciprocal cipher
        return False

    # Stateful whole-buffer semantics: split calls must equal one big call.
    a = create(key)
    if a.encrypt(pt[:7]) + a.encrypt(pt[7:]) != ct:
        return False
    b = create(key)
    if b.decrypt(ct[:11]) + b.decrypt(ct[11:]) != pt:
        return False

    return True
