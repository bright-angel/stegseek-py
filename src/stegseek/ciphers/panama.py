"""Pure-Python port of libmcrypt's PANAMA stream cipher.

Faithful translation of ``_reference/libsrc/algorithms/panama.c``.  It is a
stream algorithm (``_is_block_algorithm() == 0``): ``block_size == 1`` and the
key size is 32 bytes.  ``create()`` fixes the key to exactly 32 bytes.

Stateful stream semantics
-------------------------
``mcrypt_generic`` calls ``_mcrypt_encrypt(key, buffer, len)`` with the *whole*
buffer and no block alignment.  The C ``PANAMA_KEY`` persists three pieces of
state across the buffer and across successive calls:

* the 17-word finite-state machine ``state``,
* the 32-stage x 8-word LFSR ``buffer`` plus ``tap_0``,
* ``wkeymat`` (32 keystream bytes) and ``keymat_pointer`` (0..31).

``_mcrypt_set_key`` resets the machine, ``pan_push``es the 32-byte key (1
block), performs 32 dummy ``pan_pull``s, then one ``pan_pull`` that fills the
first 32-byte keystream block.  ``_mcrypt_encrypt`` XORs byte ``i`` with
``keymat[keymat_pointer]``; when the pointer reaches 32 it does another
``pan_pull`` to refill.  ``_mcrypt_decrypt`` is literally ``_mcrypt_encrypt``
(XOR is symmetric).  Consequently ``encrypt``/``decrypt`` are **stateful**:
the state advances across the whole buffer and across successive calls, so
``obj.encrypt(b'ab') + obj.encrypt(b'cd') == obj.encrypt(b'abcd')``.

Byte / word order (WORDS_BIGENDIAN / byteswap32)
------------------------------------------------
The internal ``pan_push``/``pan_pull``/GAMMA/PI/THETA/SIGMA/LAMBDA machinery
is pure ``word32`` arithmetic and is endian-independent in terms of the
numeric word values.  The two byte/word boundaries are:

* Key input (``pan_push``): on a little-endian host no byteswap is applied, so
  the 8 key words are the little-endian interpretation of the 32 key bytes;
  the big-endian branch byteswaps, yielding the *same* numeric words.  Thus the
  key words are ``int.from_bytes(key[4i:4i+4], 'little')`` on every platform.
* Keystream output: ``pan_pull`` writes ``state[9..16]`` into ``wkeymat``;
  ``keymat = (byte*)wkeymat``.  The little-endian branch stores those words
  directly (little-endian bytes); the big-endian branch byteswaps ``wkeymat``
  first, which again yields little-endian bytes of the state words.  Hence the
  32 keystream bytes are always the **little-endian** serialization of the
  eight state words, i.e. ``w.to_bytes(4, 'little')``.

The C ``_mcrypt_self_test`` prints ``sprintf("%.2x", ciphertext[j])`` for
``j = 0..blocksize-1`` with ``blocksize = 20``; the CIPHER string is 20 bytes
(the first 20 keystream bytes XOR the plaintext ``0..19``).  ``length`` passed
to ``_mcrypt_encrypt`` is a byte count (despite a stale "in bits" comment).

Constants (from panama.h): ``PAN_STAGE_SIZE = 8``, ``PAN_STAGES = 32``,
``PAN_STATE_SIZE = 17``, ``WORDLENGTH = 32``.

Public API::

    create(key: bytes) -> _Panama           # key must be exactly 32 bytes
    _Panama.block_size == 1
    _Panama.encrypt(data) -> bytes          # stateful
    _Panama.decrypt(data) -> bytes          # stateful
    self_test() -> bool                     # silent on success
"""

from __future__ import annotations

_M32 = 0xFFFFFFFF
_STAGE_SIZE = 8
_STAGES = 32
_STATE_SIZE = 17
_KEY_SIZE = 32

# PI_i(i, j, k): pi[i] = ROTL32(gamma[j], k).  pi[0] = gamma[0] (k=0).
_PI_SPEC = (
    (0, 0), (7, 1), (14, 3), (4, 6), (11, 10), (1, 15), (8, 21), (15, 28),
    (5, 4), (12, 13), (2, 23), (9, 2), (16, 14), (6, 27), (13, 9), (3, 24),
    (10, 8),
)


def _rotl32(x, n):
    n %= 32
    if n == 0:
        return x & _M32
    return ((x << n) | (x >> (32 - n))) & _M32


class _Panama:
    block_size = 1

    def __init__(self, key: bytes) -> None:
        # pan_reset(): state and LFSR buffer all zero, tap_0 = 0.
        self._state = [0] * _STATE_SIZE
        self._buffer = [[0] * _STAGE_SIZE for _ in range(_STAGES)]
        self._tap_0 = 0

        # pan_push(in_key, keyblocks=1, ...).  Key words are the little-endian
        # interpretation of the 32 key bytes (no byteswap on the LE host).
        L = [int.from_bytes(key[4 * i:4 * i + 4], "little")
             for i in range(_STAGE_SIZE)]
        self._push(L)

        # pan_pull(NULL, NULL, 32, ...) : 32 dummy iterations (state advances).
        for _ in range(32):
            self._pull(out=False)

        # pan_pull(NULL, wkeymat, 1, ...) : first 32-byte keystream block.
        self._set_keymat(self._pull(out=True))
        self._keymat_pointer = 0

    # -- Panama rho cascade (GAMMA / PI / THETA), returns theta output ------
    def _nonlinear(self):
        s = self._state
        g = [0] * _STATE_SIZE
        for i in range(_STATE_SIZE):
            g[i] = (s[i] ^ (s[(i + 1) % _STATE_SIZE]
                            | ((~s[(i + 2) % _STATE_SIZE]) & _M32))) & _M32
        p = [0] * _STATE_SIZE
        for i, (j, k) in enumerate(_PI_SPEC):
            p[i] = _rotl32(g[j], k)
        t = [0] * _STATE_SIZE
        for i in range(_STATE_SIZE):
            t[i] = (p[i] ^ p[(i + 1) % _STATE_SIZE]
                    ^ p[(i + 4) % _STATE_SIZE]) & _M32
        return t

    def _lambda_25_update(self, ptap0, ptap25):
        # LAMBDA_25_i(i): stage[ptap25][i] ^= stage[ptap0][(i+2)&7]
        b0 = self._buffer[ptap0]
        b25 = self._buffer[ptap25]
        for i in range(_STAGE_SIZE):
            b25[i] = (b25[i] ^ b0[(i + 2) & (_STAGE_SIZE - 1)]) & _M32

    def _pull(self, out):
        """One pan_pull iteration; optionally return the 8 output words."""
        s = self._state
        output = s[9:17] if out else None   # gamma_in_(9..16) == current state

        t = self._nonlinear()

        t0_old = self._tap_0
        L = (t0_old + 4) & (_STAGES - 1)
        b = (t0_old + 16) & (_STAGES - 1)
        self._tap_0 = (t0_old - 1) & (_STAGES - 1)
        ptap0 = self._tap_0
        ptap25 = (self._tap_0 + 25) & (_STAGES - 1)

        # LAMBDA_PULL (tap 25 update first, then tap 0 from old state words).
        self._lambda_25_update(ptap0, ptap25)
        for i in range(_STAGE_SIZE):
            self._buffer[ptap0][i] = (s[i + 1] ^ self._buffer[ptap0][i]) & _M32

        # SIGMA (uses L = stage[t0_old+4] and b = stage[t0_old+16]).
        s[0] = (t[0] ^ 1) & _M32
        for i in range(1, 9):
            s[i] = (t[i] ^ self._buffer[L][i - 1]) & _M32
        for i in range(9, 17):
            s[i] = (t[i] ^ self._buffer[b][i - 9]) & _M32
        return output

    def _push(self, L):
        """One pan_push iteration; L is the 8-word input block."""
        s = self._state
        t = self._nonlinear()

        t0_old = self._tap_0
        b = (t0_old + 16) & (_STAGES - 1)
        self._tap_0 = (t0_old - 1) & (_STAGES - 1)
        ptap0 = self._tap_0
        ptap25 = (self._tap_0 + 25) & (_STAGES - 1)

        # LAMBDA_PUSH (tap 0 from the input block L).
        self._lambda_25_update(ptap0, ptap25)
        for i in range(_STAGE_SIZE):
            self._buffer[ptap0][i] = (L[i] ^ self._buffer[ptap0][i]) & _M32

        # SIGMA: i=1..8 uses L (input), i=9..16 uses b = stage[t0_old+16].
        s[0] = (t[0] ^ 1) & _M32
        for i in range(1, 9):
            s[i] = (t[i] ^ L[i - 1]) & _M32
        for i in range(9, 17):
            s[i] = (t[i] ^ self._buffer[b][i - 9]) & _M32

    def _set_keymat(self, words):
        # wkeymat (word32[8]) as byte[32]: little-endian serialization.
        self._keymat = b"".join((w & _M32).to_bytes(4, "little") for w in words)

    def _refill(self):
        self._set_keymat(self._pull(out=True))
        self._keymat_pointer = 0

    def encrypt(self, data: bytes) -> bytes:
        data = bytes(data)
        out = bytearray(len(data))
        for i, ch in enumerate(data):
            if self._keymat_pointer == 32:
                self._refill()
            out[i] = ch ^ self._keymat[self._keymat_pointer]
            self._keymat_pointer += 1
        return bytes(out)

    def decrypt(self, data: bytes) -> bytes:
        # _mcrypt_decrypt is literally _mcrypt_encrypt (XOR is symmetric).
        return self.encrypt(data)


def create(key: bytes) -> _Panama:
    """Return a PANAMA stream cipher; ``key`` must be exactly 32 bytes."""
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise TypeError("key must be bytes")
    key = bytes(key)
    if len(key) != _KEY_SIZE:
        raise ValueError("key must be exactly 32 bytes")
    return _Panama(key)


# Verbatim from panama.c ``_mcrypt_self_test``:
#     #define CIPHER "d76e3c2243feadd2c99edfcb95c64c852ba6c59f"
# keyword[j] = (j*2+10) % 256 (32 bytes), plaintext[j] = j % 256 (20 bytes),
# blocksize = 20.
CIPHER = "d76e3c2243feadd2c99edfcb95c64c852ba6c59f"


def self_test() -> bool:
    """Verify the C known-answer vector and a round trip; silent on success."""
    key = bytes((j * 2 + 10) % 256 for j in range(32))
    pt = bytes(j % 256 for j in range(20))

    ct = create(key).encrypt(pt)
    if ct.hex() != CIPHER:
        return False
    # Fresh state for the round trip (the C self test calls _mcrypt_set_key
    # again before _mcrypt_decrypt).
    if create(key).decrypt(ct) != pt:
        return False

    # Stateful whole-buffer semantics: split calls equal one big call, also
    # across the 32-byte keystream refill boundary.
    big = bytes((j * 7 + 3) % 256 for j in range(100))
    whole = create(key).encrypt(big)
    stream = create(key)
    split = (stream.encrypt(big[:1]) + stream.encrypt(big[1:33])
             + stream.encrypt(big[33:70]) + stream.encrypt(big[70:]))
    if split != whole:
        return False
    if create(key).decrypt(whole) != big:
        return False
    return True
