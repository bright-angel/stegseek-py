"""Pure-Python port of Mike Scott's table-based Rijndael as used by libmcrypt.

This is a faithful translation of ``rijndael-128.c`` / ``rijndael-192.c`` /
``rijndael-256.c`` (``libmcrypt`` modules).  The three files are identical
except for ``nb`` (the number of 32-bit words in a block: 4, 6 or 8).  The
Rijndael state is held as ``nb`` ``word32`` columns; each ``word32`` is built
from four consecutive buffer bytes with ``pack()`` (little-endian byte order
within the word) and written back with ``unpack()``.

libmcrypt always calls ``_mcrypt_set_key`` with a 32-byte key for these three
algorithms (``mcrypt_enc_get_key_size() == 32``), so ``Nk == 8`` and
``Nr == max(Nb, Nk) + 6 == 14`` for every block size.  ``create()`` therefore
requires a 32-byte key and fixes ``Nk`` to 8.

Only the Python standard library is used; the S-box, inverse S-box, round
constants and the forward/reverse T-tables are precomputed at import time.
"""

# ``byte`` is an unsigned 8-bit value and ``word32`` an unsigned 32-bit value
# in the C source.  All word operations are masked back to 32 bits.

_INCO = (0x0B, 0x0D, 0x09, 0x0E)  # inverse MixColumn coefficients


# --------------------------------------------------------------------------
# small arithmetic helpers (exact ports of the C macros/functions)
# --------------------------------------------------------------------------

def _xtime(a):
    """Multiply a byte by 2 in GF(2^8), reduced by the AES polynomial."""
    a &= 0xFF
    high = a & 0x80
    a = (a << 1) & 0xFF
    if high:
        a ^= 0x1B
    return a & 0xFF


def _rotl1(x):
    """ROTL(x): rotate a *byte* left by one bit."""
    return ((x >> 7) | (x << 1)) & 0xFF


def _rotl8(x):
    """Rotate a 32-bit word left by one byte."""
    return ((x << 8) | (x >> 24)) & 0xFFFFFFFF


def _rotl16(x):
    """Rotate a 32-bit word left by two bytes."""
    return ((x << 16) | (x >> 16)) & 0xFFFFFFFF


def _rotl24(x):
    """Rotate a 32-bit word left by three bytes."""
    return ((x << 24) | (x >> 8)) & 0xFFFFFFFF


# --------------------------------------------------------------------------
# module-level tables, built at import (port of _mcrypt_rijndael_gentables)
# --------------------------------------------------------------------------

_PTAB = [0] * 256       # power (antilog) table, 3^i
_LTAB = [0] * 256       # log table, log_3(x)
_FBSUB = [0] * 256      # forward S-box  (fbsub)
_RBSUB = [0] * 256      # reverse S-box (rbsub)
_RCO = [0] * 30         # round constants (rco)
_FTABLE = [0] * 256     # forward T-table (ftable)
_RTABLE = [0] * 256     # reverse T-table (rtable)


def _bmul(x, y):
    """GF(2^8) multiplication via log/antilog tables (C ``bmul``)."""
    if x and y:
        return _PTAB[(_LTAB[x] + _LTAB[y]) % 255]
    return 0


def _bytesub(x):
    """C ``ByteSub``: multiplicative inverse + affine transform."""
    y = _PTAB[255 - _LTAB[x]]
    xx = y
    for _ in range(4):
        xx = _rotl1(xx)
        y ^= xx
    return (y ^ 0x63) & 0xFF


def _subbyte(a):
    """Apply the S-box to each of the four bytes of a word (C ``SubByte``)."""
    b0 = _FBSUB[a & 0xFF]
    b1 = _FBSUB[(a >> 8) & 0xFF]
    b2 = _FBSUB[(a >> 16) & 0xFF]
    b3 = _FBSUB[(a >> 24) & 0xFF]
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)


def _product(x, y):
    """Dot product of two 4-byte arrays in GF(2^8) (C ``product``)."""
    xb = (x & 0xFF, (x >> 8) & 0xFF, (x >> 16) & 0xFF, (x >> 24) & 0xFF)
    yb = (y & 0xFF, (y >> 8) & 0xFF, (y >> 16) & 0xFF, (y >> 24) & 0xFF)
    r = 0
    for i in range(4):
        r ^= _bmul(xb[i], yb[i])
    return r


_INCO_PACKED = _INCO[0] | (_INCO[1] << 8) | (_INCO[2] << 16) | (_INCO[3] << 24)


def _invmixcol(x):
    """Inverse MixColumn on one word (C ``InvMixCol``)."""
    m = _INCO_PACKED
    b3 = _product(m, x)
    m = _rotl24(m)
    b2 = _product(m, x)
    m = _rotl24(m)
    b1 = _product(m, x)
    m = _rotl24(m)
    b0 = _product(m, x)
    return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)


def _gentables():
    # power / log tables (generator 3)
    _PTAB[0] = 1
    _LTAB[0] = 0
    _LTAB[1] = 0
    _PTAB[1] = 3
    _LTAB[3] = 1
    for i in range(2, 256):
        _PTAB[i] = (_PTAB[i - 1] ^ _xtime(_PTAB[i - 1])) & 0xFF
        _LTAB[_PTAB[i]] = i

    # S-boxes
    _FBSUB[0] = 0x63
    _RBSUB[0x63] = 0
    for i in range(1, 256):
        y = _bytesub(i)
        _FBSUB[i] = y
        _RBSUB[y] = i

    # round constants
    y = 1
    for i in range(30):
        _RCO[i] = y
        y = _xtime(y)

    # forward / reverse T-tables
    for i in range(256):
        yy = _FBSUB[i]
        b0 = _xtime(yy)
        b1 = yy
        b2 = yy
        b3 = (yy ^ _xtime(yy)) & 0xFF
        _FTABLE[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

        yy = _RBSUB[i]
        b3 = _bmul(_INCO[0], yy)
        b2 = _bmul(_INCO[1], yy)
        b1 = _bmul(_INCO[2], yy)
        b0 = _bmul(_INCO[3], yy)
        _RTABLE[i] = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)


_gentables()


# --------------------------------------------------------------------------
# cipher instance
# --------------------------------------------------------------------------

class _Rijndael:
    """One instantiated key schedule for a given Nb / Nk."""

    def __init__(self, key: bytes, nb: int):
        key = bytes(key)
        nk = len(key) // 4
        if nk < 4:                       # rijndael-128.c clamps Nk to >= 4
            nk = 4
        self.nb = nb
        self.nk = nk
        self.block_size = 4 * nb
        self.Nr = 6 + max(nb, nk)
        self._set_key(key)

    # -- key schedule (port of _mcrypt_set_key) ----------------------------

    def _set_key(self, key: bytes):
        nb = self.nb
        nk = self.nk
        Nr = self.Nr

        C1 = 1
        if nb < 8:
            C2, C3 = 2, 3
        else:
            C2, C3 = 3, 4

        fi = [0] * (3 * nb)
        ri = [0] * (3 * nb)
        for j in range(nb):
            m = 3 * j
            fi[m] = (j + C1) % nb
            fi[m + 1] = (j + C2) % nb
            fi[m + 2] = (j + C3) % nb
            ri[m] = (nb + j - C1) % nb
            ri[m + 1] = (nb + j - C2) % nb
            ri[m + 2] = (nb + j - C3) % nb
        self.fi = fi
        self.ri = ri

        N = nb * (Nr + 1)
        fkey = [0] * N
        for i in range(nk):
            fkey[i] = int.from_bytes(key[4 * i:4 * i + 4], "little")

        j = nk
        k = 0
        while j < N:
            fkey[j] = (fkey[j - nk]
                       ^ _subbyte(_rotl24(fkey[j - 1]))
                       ^ _RCO[k]) & 0xFFFFFFFF
            if nk <= 6:
                for i in range(1, nk):
                    if (i + j) >= N:
                        break
                    fkey[i + j] = (fkey[i + j - nk] ^ fkey[i + j - 1]) & 0xFFFFFFFF
            else:
                for i in range(1, 4):
                    if (i + j) >= N:
                        break
                    fkey[i + j] = (fkey[i + j - nk] ^ fkey[i + j - 1]) & 0xFFFFFFFF
                if (j + 4) < N:
                    fkey[j + 4] = (fkey[j + 4 - nk]
                                    ^ _subbyte(fkey[j + 3])) & 0xFFFFFFFF
                for i in range(5, nk):
                    if (i + j) >= N:
                        break
                    fkey[i + j] = (fkey[i + j - nk] ^ fkey[i + j - 1]) & 0xFFFFFFFF
            j += nk
            k += 1
        self.fkey = fkey

        # expanded decryption key, in reverse order
        rkey = [0] * N
        for j in range(nb):
            rkey[j + N - nb] = fkey[j]
        for i in range(nb, N - nb, nb):
            k = N - nb - i
            for j in range(nb):
                rkey[k + j] = _invmixcol(fkey[i + j])
        for j in range(N - nb, N):
            rkey[j - N + nb] = fkey[j]
        self.rkey = rkey

    # -- block transform (port of _mcrypt_encrypt / _mcrypt_decrypt) --------

    def _crypt(self, words, encrypt: bool):
        nb = self.nb
        Nr = self.Nr
        if encrypt:
            key = self.fkey
            table = _FTABLE
            lastbox = _FBSUB
            shifts = self.fi
        else:
            key = self.rkey
            table = _RTABLE
            lastbox = _RBSUB
            shifts = self.ri

        x = [words[i] ^ key[i] for i in range(nb)]
        y = [0] * nb
        k = nb

        for _ in range(1, Nr):
            for j in range(nb):
                m = 3 * j
                value = (key[k]
                         ^ table[x[j] & 0xFF]
                         ^ _rotl8(table[(x[shifts[m]] >> 8) & 0xFF])
                         ^ _rotl16(table[(x[shifts[m + 1]] >> 16) & 0xFF])
                         ^ _rotl24(table[(x[shifts[m + 2]] >> 24) & 0xFF]))
                y[j] = value & 0xFFFFFFFF
                k += 1
            x, y = y, x

        # last round (no MixColumn): uses the S-box directly
        for j in range(nb):
            m = 3 * j
            value = (key[k]
                     ^ lastbox[x[j] & 0xFF]
                     ^ _rotl8(lastbox[(x[shifts[m]] >> 8) & 0xFF])
                     ^ _rotl16(lastbox[(x[shifts[m + 1]] >> 16) & 0xFF])
                     ^ _rotl24(lastbox[(x[shifts[m + 2]] >> 24) & 0xFF]))
            y[j] = value & 0xFFFFFFFF
            k += 1
        return y

    # -- public single-block API --------------------------------------------

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("block must be exactly %d bytes" % self.block_size)
        words = [int.from_bytes(block[4 * i:4 * i + 4], "little")
                 for i in range(self.nb)]
        return b"".join(w.to_bytes(4, "little") for w in self._crypt(words, True))

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("block must be exactly %d bytes" % self.block_size)
        words = [int.from_bytes(block[4 * i:4 * i + 4], "little")
                 for i in range(self.nb)]
        return b"".join(w.to_bytes(4, "little") for w in self._crypt(words, False))


# --------------------------------------------------------------------------
# public factory
# --------------------------------------------------------------------------

def create(key: bytes, block_size: int) -> "_Rijndael":
    """Return a Rijndael cipher instance.

    ``key`` must be exactly 32 bytes (the full KEYGEN_MCRYPT output); ``Nk`` is
    fixed at 8 as libmcrypt does for rijndael-128/192/256.  ``block_size`` is
    16, 24 or 32 bytes (Nb = 4, 6 or 8).
    """
    if block_size not in (16, 24, 32):
        raise ValueError("block_size must be 16, 24 or 32")
    key = bytes(key)
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return _Rijndael(key, block_size // 4)


# --------------------------------------------------------------------------
# self test
# --------------------------------------------------------------------------

def self_test() -> bool:
    """Verify known-answer vectors and round trips; print nothing on success.

    The 192/256 vectors are taken verbatim from ``rijndael-192.c`` and
    ``rijndael-256.c`` ``_mcrypt_self_test`` (key = (j*2+10) % 256, plaintext
    = j).  The 128 vector uses that file's 16-byte key / Nk=4 configuration
    and is checked through the internal class to exercise the ``Nk <= 6``
    key-schedule branch as well.
    """
    key = bytes((j * 2 + 10) % 256 for j in range(32))

    kat = {
        24: "380ee49a5de1dbd4b9cc11af60b8c8ff669e367af8948a8a",
        32: "45af6c269326fd935edd24733cff74fc1aa358841a6cd80b79f242d983f8ff2e",
    }
    for bs, expected_hex in kat.items():
        pt = bytes(j % 256 for j in range(bs))
        cipher = create(key, bs)
        ct = cipher.encrypt_block(pt)
        if ct.hex() != expected_hex:
            return False
        if cipher.decrypt_block(ct) != pt:
            return False

    # rijndael-128.c self test uses a 16-byte key (Nk = 4), Nr = 10, Nb = 4.
    key128 = b"\x01" + b"\x00" * 15
    pt128 = bytes(range(16))
    c128 = _Rijndael(key128, 4)
    if c128.encrypt_block(pt128).hex() != "5352e43763eec1a8502433d6d520b1f0":
        return False

    # round trips on several deterministic blocks for every supported size
    state = 0x12345678

    def rnd():
        nonlocal state
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        return (state >> 16) & 0xFF

    for bs in (16, 24, 32):
        cipher = create(key, bs)
        for _ in range(8):
            block = bytes(rnd() for _ in range(bs))
            ct = cipher.encrypt_block(block)
            if len(ct) != bs:
                return False
            if cipher.decrypt_block(ct) != block:
                return False
            # decrypt(encrypt(x)) == x across independent key schedules
            if create(key, bs).decrypt_block(create(key, bs).encrypt_block(block)) != block:
                return False

    return True
