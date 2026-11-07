"""Common interface for the pure-Python libmcrypt algorithm ports.

Every algorithm module exposes ``create(key: bytes)`` returning an object with
``block_size`` and, for block ciphers, ``encrypt_block`` / ``decrypt_block``.
Stream ciphers instead expose stateful ``encrypt`` / ``decrypt`` methods.

The contract mirrors libmcrypt's ``_mcrypt_set_key`` / ``_mcrypt_encrypt`` /
``_mcrypt_decrypt``: ``key`` has exactly ``MCRYPT_KEY_SIZE[algo]`` bytes and a
block has exactly ``MCRYPT_BLOCK_SIZE[algo]`` bytes, with the byte order used
by libmcrypt (no implicit padding or reordering).
"""

from __future__ import annotations


class BlockCipherBase:
    """Convenience base implementing whole-buffer ECB on top of one block."""

    block_size = 0

    def encrypt_block(self, block: bytes) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def decrypt_block(self, block: bytes) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def encrypt(self, data: bytes) -> bytes:
        bs = self.block_size
        return b"".join(self.encrypt_block(data[i:i + bs])
                        for i in range(0, len(data), bs))

    def decrypt(self, data: bytes) -> bytes:
        bs = self.block_size
        return b"".join(self.decrypt_block(data[i:i + bs])
                        for i in range(0, len(data), bs))


class PyCryptodomeAdapter:
    """Wrap a pycryptodome ECB cipher into the common contract."""

    def __init__(self, cipher):
        self._cipher = cipher
        self.block_size = cipher.block_size

    def encrypt_block(self, block: bytes) -> bytes:
        return self._cipher.encrypt(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return self._cipher.decrypt(block)

    def encrypt(self, data: bytes) -> bytes:
        return self._cipher.encrypt(data)

    def decrypt(self, data: bytes) -> bytes:
        return self._cipher.decrypt(data)
