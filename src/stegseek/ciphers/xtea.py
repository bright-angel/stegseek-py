"""Minimal XTEA block cipher (8-byte block, 16-byte key, 32 rounds).

libmcrypt's xtea.c uses the usual big-endian word order for the block and the
key, which is what ``struct.unpack('>2I')`` / ``'>4I'`` below reproduce.
"""

from __future__ import annotations

import struct

from .base import BlockCipherBase


class _XTEA(BlockCipherBase):
    block_size = 8

    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("xtea requires a 16-byte key")
        self.k = struct.unpack(">4I", key)

    def encrypt_block(self, block: bytes) -> bytes:
        k = self.k
        v0, v1 = struct.unpack(">2I", block)
        total = 0
        for _ in range(32):
            v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (total + k[total & 3]))) & 0xFFFFFFFF
            total = (total + 0x9E3779B9) & 0xFFFFFFFF
            v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (total + k[(total >> 11) & 3]))) & 0xFFFFFFFF
        return struct.pack(">2I", v0, v1)

    def decrypt_block(self, block: bytes) -> bytes:
        k = self.k
        v0, v1 = struct.unpack(">2I", block)
        total = (0x9E3779B9 * 32) & 0xFFFFFFFF
        for _ in range(32):
            v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (total + k[(total >> 11) & 3]))) & 0xFFFFFFFF
            total = (total - 0x9E3779B9) & 0xFFFFFFFF
            v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (total + k[total & 3]))) & 0xFFFFFFFF
        return struct.pack(">2I", v0, v1)


def create(key: bytes) -> _XTEA:
    return _XTEA(key)


def self_test() -> bool:
    # libmcrypt xtea.c: keyword[j] = (j*2+10)%256, plaintext[j] = j%256,
    # CIPHER = "f61e7ff6da7cdb27"
    key = bytes((j * 2 + 10) % 256 for j in range(16))
    pt = bytes(range(8))
    ct = bytes.fromhex("f61e7ff6da7cdb27")
    c = create(key)
    return c.encrypt_block(pt) == ct and c.decrypt_block(ct) == pt
