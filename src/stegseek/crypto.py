"""Crypto layer: libmhash CRC32, KEYGEN_MCRYPT and libmcrypt ciphers/modes.

The C++ original uses libmhash for the CRC32 checksum and key derivation, and
libmcrypt for the actual block/stream ciphers.  This module reproduces those
semantics with ``hashlib`` + the cipher backends in :mod:`stegseek.ciphers`
(pure-Python ports plus a few pycryptodome primitives).
"""

from __future__ import annotations

import hashlib

from .ciphers import make_cipher
from .const import (
    ENC_ALGO_NONE,
    ENC_MODE_CBC,
    ENC_MODE_CFB,
    ENC_MODE_CTR,
    ENC_MODE_ECB,
    ENC_MODE_NCFB,
    ENC_MODE_NOFB,
    ENC_MODE_OFB,
    ENC_MODE_STREAM,
    MCRYPT_BLOCK_SIZE,
    MCRYPT_IV_SIZE,
    MCRYPT_KEY_SIZE,
    MODES_WITH_IV,
    algo_name,
    mode_name,
)
from .errors import NotImplementedInPython

# ---------------------------------------------------------------------------
# libmhash MHASH_CRC32 (the MSB-first, non-reflected variant in crc32.c)
# ---------------------------------------------------------------------------

def _make_crc32_table() -> list[int]:
    table = []
    for n in range(256):
        c = n << 24
        for _ in range(8):
            c = ((c << 1) ^ 0x04C11DB7) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
        table.append(c)
    return table


_CRC32_TABLE = _make_crc32_table()


def mhash_crc32(data: bytes) -> int:
    """Return libmhash's MHASH_CRC32 value (CRC-32/BZIP2, little-endian word)."""
    crc = 0xFFFFFFFF
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _CRC32_TABLE[((crc >> 24) ^ byte) & 0xFF]
    return (~crc) & 0xFFFFFFFF


def keygen_mcrypt(password: bytes, key_size: int) -> bytes:
    """``mhash_keygen_ext(KEYGEN_MCRYPT, MHASH_MD5, ...)`` (lib/keygen_mcrypt.c)."""
    if key_size <= 0:
        return b""
    key = bytearray()
    while len(key) < key_size:
        digest = hashlib.md5(password + bytes(key)).digest()
        take = min(16, key_size - len(key))
        key.extend(digest[:take])
    return bytes(key)


# ---------------------------------------------------------------------------
# libmcrypt mode implementations (modules/modes/*.c)
# ---------------------------------------------------------------------------

def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _inc_counter(counter: bytearray) -> None:
    for i in range(len(counter) - 1, -1, -1):
        if counter[i] == 0xFF:
            counter[i] = 0
        else:
            counter[i] += 1
            break


def _ecb(cipher, data: bytes, decrypt: bool) -> bytes:
    fn = cipher.decrypt_block if decrypt else cipher.encrypt_block
    bs = cipher.block_size
    return b"".join(fn(data[i:i + bs]) for i in range(0, len(data), bs))


def _cbc(cipher, data: bytes, iv: bytes, decrypt: bool) -> bytes:
    bs = cipher.block_size
    out = bytearray()
    prev = iv
    if decrypt:
        for i in range(0, len(data), bs):
            block = data[i:i + bs]
            out.extend(_xor(cipher.decrypt_block(block), prev))
            prev = block
    else:
        for i in range(0, len(data), bs):
            block = data[i:i + bs]
            prev = cipher.encrypt_block(_xor(block, prev))
            out.extend(prev)
    return bytes(out)


def _cfb8(cipher, data: bytes, iv: bytes, decrypt: bool) -> bytes:
    """libmcrypt ``cfb``: 8-bit CFB with a shifting register."""
    reg = bytearray(iv)
    out = bytearray()
    for byte in data:
        keystream = cipher.encrypt_block(bytes(reg))[0]
        if decrypt:
            reg[:] = reg[1:] + bytes([byte])
            out.append(byte ^ keystream)
        else:
            cipher_byte = byte ^ keystream
            reg[:] = reg[1:] + bytes([cipher_byte])
            out.append(cipher_byte)
    return bytes(out)


def _ofb8(cipher, data: bytes, iv: bytes) -> bytes:
    """libmcrypt ``ofb``: 8-bit OFB with a shifting register."""
    reg = bytearray(iv)
    out = bytearray()
    for byte in data:
        enc = cipher.encrypt_block(bytes(reg))
        reg[:] = reg[1:] + enc[:1]
        out.append(byte ^ enc[0])
    return bytes(out)


def _nofb(cipher, data: bytes, iv: bytes) -> bytes:
    """libmcrypt ``nofb``: full-block OFB (data length is always a full block)."""
    bs = cipher.block_size
    reg = iv
    out = bytearray()
    for i in range(0, len(data), bs):
        enc = cipher.encrypt_block(reg)
        reg = enc
        out.extend(_xor(data[i:i + bs], enc[:len(data[i:i + bs])]))
    return bytes(out)


def _ncfb(cipher, data: bytes, iv: bytes, decrypt: bool) -> bytes:
    """libmcrypt ``ncfb``: full-block CFB."""
    bs = cipher.block_size
    reg = iv
    out = bytearray()
    for i in range(0, len(data), bs):
        chunk = data[i:i + bs]
        enc = cipher.encrypt_block(reg)
        result = _xor(chunk, enc[:len(chunk)])
        reg = chunk if decrypt else result
        out.extend(result)
    return bytes(out)


def _ctr(cipher, data: bytes, iv: bytes) -> bytes:
    """libmcrypt ``ctr``: encrypt big-endian counter, increment after each block."""
    bs = cipher.block_size
    counter = bytearray(iv)
    out = bytearray()
    for i in range(0, len(data), bs):
        chunk = data[i:i + bs]
        stream = cipher.encrypt_block(bytes(counter))
        out.extend(_xor(chunk, stream[:len(chunk)]))
        if len(chunk) == bs:
            _inc_counter(counter)
    return bytes(out)


# ---------------------------------------------------------------------------
# Public cipher API
# ---------------------------------------------------------------------------

class StegCipher:
    """A libmcrypt algorithm/mode pair."""

    def __init__(self, algo: int, mode: int):
        self.algo_index = algo
        self.mode_index = mode
        self.name = algo_name(algo)
        self.mode = mode_name(mode)
        self.key_size = MCRYPT_KEY_SIZE.get(self.name, 16)
        self.block_size = MCRYPT_BLOCK_SIZE.get(self.name, 16)
        # Most algorithms return their block size from _mcrypt_get_algo_iv_size,
        # but the stream ciphers have their own (often zero) IV sizes.
        iv_size = MCRYPT_IV_SIZE.get(self.name, self.block_size)
        if self.name == "none" or mode not in MODES_WITH_IV:
            iv_size = 0
        self.iv_size = iv_size
        self.has_iv = iv_size > 0

    def encrypted_size(self, plain_bits: int) -> int:
        """``MCryptPP::getEncryptedSize`` -- number of bits of ciphertext."""
        if self.algo_index == ENC_ALGO_NONE:
            return plain_bits
        bits = 8 * self.iv_size
        block_bits = 8 * self.block_size
        blocks = (plain_bits + block_bits - 1) // block_bits
        return bits + blocks * block_bits

    def _make(self, password: bytes):
        key = keygen_mcrypt(password, self.key_size)
        try:
            return make_cipher(self.name, key)
        except KeyError:
            raise NotImplementedInPython(
                f'the encryption algorithm "{self.name}" is not available in the Python crypto backend'
            ) from None

    def encrypt(self, plain: bytes, password: bytes, iv: bytes) -> bytes:
        if self.algo_index == ENC_ALGO_NONE:
            return plain
        cipher = self._make(password)
        mode = self.mode_index
        if mode == ENC_MODE_STREAM:
            body = cipher.encrypt(plain)
        elif mode == ENC_MODE_ECB:
            body = _ecb(cipher, plain, False)
        elif mode == ENC_MODE_CBC:
            body = _cbc(cipher, plain, iv, False)
        elif mode == ENC_MODE_CFB:
            body = _cfb8(cipher, plain, iv, False)
        elif mode == ENC_MODE_OFB:
            body = _ofb8(cipher, plain, iv)
        elif mode == ENC_MODE_NOFB:
            body = _nofb(cipher, plain, iv)
        elif mode == ENC_MODE_NCFB:
            body = _ncfb(cipher, plain, iv, False)
        elif mode == ENC_MODE_CTR:
            body = _ctr(cipher, plain, iv)
        else:
            raise NotImplementedInPython(f"unsupported encryption mode {self.mode}")
        return (iv + body) if self.has_iv else body

    def decrypt(self, ciphertext: bytes, password: bytes) -> bytes:
        if self.algo_index == ENC_ALGO_NONE:
            return ciphertext
        iv = ciphertext[:self.iv_size] if self.has_iv else b""
        body = ciphertext[self.iv_size:]
        cipher = self._make(password)
        mode = self.mode_index
        if mode == ENC_MODE_STREAM:
            return cipher.decrypt(body)
        if mode == ENC_MODE_ECB:
            return _ecb(cipher, body, True)
        if mode == ENC_MODE_CBC:
            return _cbc(cipher, body, iv, True)
        if mode == ENC_MODE_CFB:
            return _cfb8(cipher, body, iv, True)
        if mode == ENC_MODE_OFB:
            return _ofb8(cipher, body, iv)
        if mode == ENC_MODE_NOFB:
            return _nofb(cipher, body, iv)
        if mode == ENC_MODE_NCFB:
            return _ncfb(cipher, body, iv, True)
        if mode == ENC_MODE_CTR:
            return _ctr(cipher, body, iv)
        raise NotImplementedInPython(f"unsupported encryption mode {self.mode}")


def get_cipher(algo: int, mode: int) -> StegCipher:
    return StegCipher(algo, mode)


def get_encrypted_size(algo: int, mode: int, plain_bits: int) -> int:
    return get_cipher(algo, mode).encrypted_size(plain_bits)
