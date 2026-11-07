"""Pure-Python port of libmcrypt's SAFER+.

Faithful translation of ``_reference/libsrc/algorithms/saferplus.c`` (Dr Brian
Gladman's AES-candidate implementation, wrapped for libmcrypt by Nikos
Mavroyanopoulos).

Byte / word order (matching the C code on a little-endian Windows host, where
``WORDS_BIGENDIAN`` is *not* defined):

* ``_mcrypt_encrypt``/``_mcrypt_decrypt`` receive the 16-byte block as a
  ``word32 *``.  A local ``word32 __blk[16]`` is aliased by ``byte *blk``; the
  C code sets ``__blk[3]=_blk[0] .. __blk[0]=_blk[3]`` and writes back
  ``_blk[3]=__blk[0] .. _blk[0]=__blk[3]``.  On little-endian that is exactly a
  reversal of the four 4-byte words on both input and output, i.e. the working
  ``blk[0..15]`` is ``block[12:16]+block[8:12]+block[4:8]+block[0:4]`` and the
  result is the same word-reversal of the final ``blk``.
* ``_mcrypt_set_key`` reads the 32 key bytes as eight little-endian ``word32``
  values, reverses their word order into ``wlk[0..7]``, then works on the 33
  leading bytes of that word array (``lk[0..32]``, the last one a parity byte).

SAFER+ works on 16 bytes with a 2x8 (encrypt/decrypt) layout: 16 forward rounds
(8 + 4 + 4 for a 32-byte key) of ``do_fr`` (S-box layer + 4 PHT layers +
shuffle), a final key-whitening layer, and the exact inverse ``do_ir`` for
decryption.  ``safer_expf`` (256 bytes) and ``safer_logf`` (512 bytes, second
half duplicating the first) are transcribed verbatim from the C source.

Only the Python standard library is used.
"""

from __future__ import annotations

_MASK = 0xFFFFFFFF

# safer_expf[256] -- transcribed verbatim from saferplus.c
_EXPF = (
    1, 45, 226, 147, 190, 69, 21, 174, 120, 3, 135, 164, 184, 56, 207, 63,
    8, 103, 9, 148, 235, 38, 168, 107, 189, 24, 52, 27, 187, 191, 114,
    247,
    64, 53, 72, 156, 81, 47, 59, 85, 227, 192, 159, 216, 211, 243, 141,
    177,
    255, 167, 62, 220, 134, 119, 215, 166, 17, 251, 244, 186, 146, 145,
    100, 131,
    241, 51, 239, 218, 44, 181, 178, 43, 136, 209, 153, 203, 140, 132,
    29, 20,
    129, 151, 113, 202, 95, 163, 139, 87, 60, 130, 196, 82, 92, 28,
    232, 160,
    4, 180, 133, 74, 246, 19, 84, 182, 223, 12, 26, 142, 222, 224, 57,
    252,
    32, 155, 36, 78, 169, 152, 158, 171, 242, 96, 208, 108, 234, 250,
    199, 217,
    0, 212, 31, 110, 67, 188, 236, 83, 137, 254, 122, 93, 73, 201, 50,
    194,
    249, 154, 248, 109, 22, 219, 89, 150, 68, 233, 205, 230, 70, 66,
    143, 10,
    193, 204, 185, 101, 176, 210, 198, 172, 30, 65, 98, 41, 46, 14,
    116, 80,
    2, 90, 195, 37, 123, 138, 42, 91, 240, 6, 13, 71, 111, 112, 157,
    126,
    16, 206, 18, 39, 213, 76, 79, 214, 121, 48, 104, 54, 117, 125, 228,
    237,
    128, 106, 144, 55, 162, 94, 118, 170, 197, 127, 61, 175, 165, 229,
    25, 97,
    253, 77, 124, 183, 11, 238, 173, 75, 34, 245, 231, 115, 35, 33,
    200, 5,
    225, 102, 221, 179, 88, 105, 99, 86, 15, 161, 49, 149, 23, 7, 58,
    40,
)

# safer_logf[512] -- transcribed verbatim from saferplus.c (bytes 256..511
# duplicate 0..255, so the C ``logf[x + k]`` with x+k up to 510 is safe).
_LOGF = (
    128, 0, 176, 9, 96, 239, 185, 253, 16, 18, 159, 228, 105, 186, 173,
    248,
    192, 56, 194, 101, 79, 6, 148, 252, 25, 222, 106, 27, 93, 78, 168,
    130,
    112, 237, 232, 236, 114, 179, 21, 195, 255, 171, 182, 71, 68, 1,
    172, 37,
    201, 250, 142, 65, 26, 33, 203, 211, 13, 110, 254, 38, 88, 218, 50,
    15,
    32, 169, 157, 132, 152, 5, 156, 187, 34, 140, 99, 231, 197, 225,
    115, 198,
    175, 36, 91, 135, 102, 39, 247, 87, 244, 150, 177, 183, 92, 139,
    213, 84,
    121, 223, 170, 246, 62, 163, 241, 17, 202, 245, 209, 23, 123, 147,
    131, 188,
    189, 82, 30, 235, 174, 204, 214, 53, 8, 200, 138, 180, 226, 205,
    191, 217,
    208, 80, 89, 63, 77, 98, 52, 10, 72, 136, 181, 86, 76, 46, 107,
    158,
    210, 61, 60, 3, 19, 251, 151, 81, 117, 74, 145, 113, 35, 190, 118,
    42,
    95, 249, 212, 85, 11, 220, 55, 49, 22, 116, 215, 119, 167, 230, 7,
    219,
    164, 47, 70, 243, 97, 69, 103, 227, 12, 162, 59, 28, 133, 24, 4,
    29,
    41, 160, 143, 178, 90, 216, 166, 126, 238, 141, 83, 75, 161, 154,
    193, 14,
    122, 73, 165, 44, 129, 196, 199, 54, 43, 127, 67, 149, 51, 242,
    108, 104,
    109, 240, 2, 40, 206, 221, 155, 234, 94, 153, 124, 20, 134, 207,
    229, 66,
    184, 64, 120, 45, 58, 233, 100, 31, 146, 144, 125, 57, 111, 224,
    137, 48,
    # -- second half: duplicate of the first 256 entries --
    128, 0, 176, 9, 96, 239, 185, 253, 16, 18, 159, 228, 105, 186, 173,
    248,
    192, 56, 194, 101, 79, 6, 148, 252, 25, 222, 106, 27, 93, 78, 168,
    130,
    112, 237, 232, 236, 114, 179, 21, 195, 255, 171, 182, 71, 68, 1,
    172, 37,
    201, 250, 142, 65, 26, 33, 203, 211, 13, 110, 254, 38, 88, 218, 50,
    15,
    32, 169, 157, 132, 152, 5, 156, 187, 34, 140, 99, 231, 197, 225,
    115, 198,
    175, 36, 91, 135, 102, 39, 247, 87, 244, 150, 177, 183, 92, 139,
    213, 84,
    121, 223, 170, 246, 62, 163, 241, 17, 202, 245, 209, 23, 123, 147,
    131, 188,
    189, 82, 30, 235, 174, 204, 214, 53, 8, 200, 138, 180, 226, 205,
    191, 217,
    208, 80, 89, 63, 77, 98, 52, 10, 72, 136, 181, 86, 76, 46, 107,
    158,
    210, 61, 60, 3, 19, 251, 151, 81, 117, 74, 145, 113, 35, 190, 118,
    42,
    95, 249, 212, 85, 11, 220, 55, 49, 22, 116, 215, 119, 167, 230, 7,
    219,
    164, 47, 70, 243, 97, 69, 103, 227, 12, 162, 59, 28, 133, 24, 4,
    29,
    41, 160, 143, 178, 90, 216, 166, 126, 238, 141, 83, 75, 161, 154,
    193, 14,
    122, 73, 165, 44, 129, 196, 199, 54, 43, 127, 67, 149, 51, 242,
    108, 104,
    109, 240, 2, 40, 206, 221, 155, 234, 94, 153, 124, 20, 134, 207,
    229, 66,
    184, 64, 120, 45, 58, 233, 100, 31, 146, 144, 125, 57, 111, 224,
    137, 48,
)


# ---------------------------------------------------------------------------
# Key schedule (the C ``_mcrypt_set_key``)
# ---------------------------------------------------------------------------

def _set_key(key: bytes):
    k_bytes = 32
    in_key = [int.from_bytes(key[4 * i:4 * i + 4], "little") for i in range(8)]

    # wlk[9] (36 bytes).  ``lkp[i] = in_key[7-i]``; ``lk`` is the byte view.
    lk = bytearray(36)
    for i in range(8):
        lk[4 * i:4 * i + 4] = (in_key[7 - i] & _MASK).to_bytes(4, "little")

    l_key = bytearray(33 * 16)  # 528 bytes
    lk[k_bytes] = 0
    for i in range(k_bytes):
        lk[k_bytes] ^= lk[i]
        l_key[i] = lk[i]

    for i in range(k_bytes):
        # rotate every one of the 33 bytes left by 3 (byte op, truncated)
        for j in range(k_bytes + 1):
            by = lk[j]
            lk[j] = ((by << 3) | (by >> 5)) & 0xFF

        k = 17 * i + 35
        low = 16 * i + 16
        m = i + 1
        for j in range(16):
            if i < 16:
                val = lk[m] + _EXPF[_EXPF[(k + j) & 255]]
            else:
                val = lk[m] + _EXPF[(k + j) & 255]
            l_key[low + j] = val & 0xFF
            m = 0 if m == k_bytes else m + 1

    return k_bytes, l_key


# ---------------------------------------------------------------------------
# PHT helpers and layer tables
# ---------------------------------------------------------------------------

def _pht(x, a, b):
    """Forward ``x[a] += x[b]; x[b] += x[a];`` (byte arithmetic)."""
    x[a] = (x[a] + x[b]) & 0xFF
    x[b] = (x[b] + x[a]) & 0xFF


def _ipht(x, a, b):
    """Inverse ``x[a] -= x[b]; x[b] -= x[a];`` (byte arithmetic)."""
    x[a] = (x[a] - x[b]) & 0xFF
    x[b] = (x[b] - x[a]) & 0xFF


# Four forward PHT layers, each a sequence of (a, b) pairs.
_FWD_PHT = (
    ((1, 0), (3, 2), (5, 4), (7, 6), (9, 8), (11, 10), (13, 12), (15, 14)),
    ((7, 0), (1, 2), (3, 4), (5, 6), (11, 8), (9, 10), (15, 12), (13, 14)),
    ((3, 0), (15, 2), (7, 4), (1, 6), (5, 8), (13, 10), (11, 12), (9, 14)),
    ((13, 0), (5, 2), (9, 4), (11, 6), (15, 8), (1, 10), (3, 12), (7, 14)),
)

# Four inverse PHT layers, applied in this (reverse) order.
_INV_PHT = (
    ((14, 7), (12, 3), (10, 1), (8, 15), (6, 11), (4, 9), (2, 5), (0, 13)),
    ((14, 9), (12, 11), (10, 13), (8, 5), (6, 1), (4, 7), (2, 15), (0, 3)),
    ((14, 13), (12, 15), (10, 9), (8, 11), (6, 5), (4, 3), (2, 1), (0, 7)),
    ((14, 15), (12, 13), (10, 11), (8, 9), (6, 7), (4, 5), (2, 3), (0, 1)),
)


def _do_fr(x, l_key, off):
    """One forward round ``do_fr(blk, l_key + off)``."""
    # S-box layer: positions 0,3 (mod 4) use expf/+ ; 1,2 use logf/^.
    for i in range(16):
        r = i & 3
        if r == 0 or r == 3:
            x[i] = (_EXPF[x[i] ^ l_key[off + i]] + l_key[off + 16 + i]) & 0xFF
        else:
            x[i] = _LOGF[x[i] + l_key[off + i]] ^ l_key[off + 16 + i]

    for stage in _FWD_PHT:
        for a, b in stage:
            _pht(x, a, b)

    # shuffle
    t = x[0]
    x[0] = x[14]
    x[14] = x[12]
    x[12] = x[10]
    x[10] = x[2]
    x[2] = x[8]
    x[8] = x[4]
    x[4] = t

    t = x[1]
    x[1] = x[7]
    x[7] = x[11]
    x[11] = x[5]
    x[5] = x[13]
    x[13] = t

    t = x[15]
    x[15] = x[3]
    x[3] = t


def _do_ir(x, l_key, off):
    """One inverse round ``do_ir(blk, l_key + off)``."""
    # inverse shuffle
    t = x[3]
    x[3] = x[15]
    x[15] = t

    t = x[13]
    x[13] = x[5]
    x[5] = x[11]
    x[11] = x[7]
    x[7] = x[1]
    x[1] = t

    t = x[4]
    x[4] = x[8]
    x[8] = x[2]
    x[2] = x[10]
    x[10] = x[12]
    x[12] = x[14]
    x[14] = x[0]
    x[0] = t

    for stage in _INV_PHT:
        for a, b in stage:
            _ipht(x, a, b)

    # inverse S-box layer
    for i in range(16):
        r = i & 3
        if r == 0 or r == 3:
            x[i] = _LOGF[x[i] - l_key[off + 16 + i] + 256] ^ l_key[off + i]
        else:
            x[i] = (_EXPF[x[i] ^ l_key[off + 16 + i]] - l_key[off + i]) & 0xFF


def _whiten(x, l_key, off, decrypt):
    """Final key-whitening layer (``kp = l_key + 16*k_bytes``)."""
    for i in range(16):
        r = i & 3
        if r == 0 or r == 3:
            x[i] ^= l_key[off + i]          # xor (self-inverse)
        elif decrypt:
            x[i] = (x[i] - l_key[off + i]) & 0xFF
        else:
            x[i] = (x[i] + l_key[off + i]) & 0xFF


class SAFERPlus:
    """SAFER+ block cipher; ``block_size == 16``."""

    block_size = 16

    def __init__(self, key: bytes):
        self._k_bytes, self._l_key = _set_key(bytes(key))

    def _crypt(self, block, decrypt: bool) -> bytes:
        block = bytes(block)
        if len(block) != 16:
            raise ValueError("block must be exactly 16 bytes")

        # word-reverse of the input (see module docstring)
        in_blk = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(4)]
        words = [in_blk[3], in_blk[2], in_blk[1], in_blk[0]]
        x = bytearray(16)
        for i in range(4):
            x[4 * i:4 * i + 4] = (words[i] & _MASK).to_bytes(4, "little")

        l_key = self._l_key
        k_bytes = self._k_bytes
        whit_off = 16 * k_bytes

        if decrypt:
            _whiten(x, l_key, whit_off, True)
            if k_bytes > 24:
                for r in range(15, 11, -1):
                    _do_ir(x, l_key, 32 * r)
            if k_bytes > 16:
                for r in range(11, 7, -1):
                    _do_ir(x, l_key, 32 * r)
            for r in range(7, -1, -1):
                _do_ir(x, l_key, 32 * r)
        else:
            for r in range(8):
                _do_fr(x, l_key, 32 * r)
            if k_bytes > 16:
                for r in range(8, 12):
                    _do_fr(x, l_key, 32 * r)
            if k_bytes > 24:
                for r in range(12, 16):
                    _do_fr(x, l_key, 32 * r)
            _whiten(x, l_key, whit_off, False)

        # word-reverse of the working state back into the output buffer
        words = [int.from_bytes(x[4 * i:4 * i + 4], "little") for i in range(4)]
        out_blk = [words[3], words[2], words[1], words[0]]
        return b"".join((w & _MASK).to_bytes(4, "little") for w in out_blk)

    def encrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, False)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._crypt(block, True)


# ---------------------------------------------------------------------------
# Public factory
# ---------------------------------------------------------------------------

def create(key: bytes) -> SAFERPlus:
    """Return a SAFER+ cipher.  ``key`` must be exactly 32 bytes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes")
    key = bytes(key)
    if len(key) != 32:
        raise ValueError("key must be exactly 32 bytes")
    return SAFERPlus(key)


# ---------------------------------------------------------------------------
# Self test
# ---------------------------------------------------------------------------

# Verbatim from saferplus.c ``_mcrypt_self_test``:
#     #define CIPHER "97fa76704bf6b578549f65c6f75b228b"
# with keyword[j] = (j*2+10) % 256 and plaintext[j] = j % 256.
CIPHER = "97fa76704bf6b578549f65c6f75b228b"


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
