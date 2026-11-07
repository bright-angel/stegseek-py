"""Pure-Python / pycryptodome cipher backends reproducing libmcrypt.

``make_cipher(algo, key)`` returns an object with a ``block_size`` attribute and
either (block ciphers) ``encrypt_block`` / ``decrypt_block`` or (stream ciphers)
stateful ``encrypt`` / ``decrypt`` methods.  See :mod:`stegseek.ciphers.base`.
"""

from __future__ import annotations

from . import (
    cast256,
    enigma,
    gost,
    loki97,
    panama,
    rijndael,
    safer64,
    safer128,
    saferplus,
    serpent,
    threeway,
    twofish,
    wake,
    xtea,
)
from .base import BlockCipherBase, PyCryptodomeAdapter

# Algorithms libmcrypt reports as stream algorithms (_is_block_algorithm()==0).
STREAM_ALGORITHMS = frozenset({"enigma", "arcfour", "panama", "wake"})


def _pycryptodome(algo: str, key: bytes):
    from Crypto.Cipher import AES, ARC2, CAST, DES, DES3, Blowfish

    if algo == "rijndael-128":
        return PyCryptodomeAdapter(AES.new(key, AES.MODE_ECB))
    if algo == "des":
        return PyCryptodomeAdapter(DES.new(key, DES.MODE_ECB))
    if algo == "tripledes":
        return PyCryptodomeAdapter(DES3.new(key, DES3.MODE_ECB))
    if algo == "blowfish":
        return PyCryptodomeAdapter(Blowfish.new(key, Blowfish.MODE_ECB))
    if algo == "cast-128":
        return PyCryptodomeAdapter(CAST.new(key, CAST.MODE_ECB))
    if algo == "rc2":
        return PyCryptodomeAdapter(ARC2.new(key, ARC2.MODE_ECB, effective_keylen=1024))
    if algo == "xtea":
        return xtea.create(key)
    if algo == "arcfour":
        from Crypto.Cipher import ARC4
        return ARC4.new(key)
    raise KeyError(algo)


def make_cipher(algo: str, key: bytes):
    """Return the cipher object for a libmcrypt algorithm name."""
    if algo in ("rijndael-192", "rijndael-256"):
        return rijndael.create(key, 24 if algo == "rijndael-192" else 32)
    if algo == "twofish":
        return twofish.create(key)
    if algo == "serpent":
        return serpent.create(key)
    if algo == "cast-256":
        return cast256.create(key)
    if algo == "gost":
        return gost.create(key)
    if algo == "loki97":
        return loki97.create(key)
    if algo == "saferplus":
        return saferplus.create(key)
    if algo == "safer-sk64":
        return safer64.create(key)
    if algo == "safer-sk128":
        return safer128.create(key)
    if algo == "threeway":
        return threeway.create(key)
    if algo == "panama":
        return panama.create(key)
    if algo == "enigma":
        return enigma.create(key)
    if algo == "wake":
        return wake.create(key)
    return _pycryptodome(algo, key)


def self_test() -> bool:
    """Run every pure-Python cipher's known-answer self test."""
    return all(m.self_test() for m in (
        rijndael, twofish, serpent, cast256, gost, loki97, saferplus,
        safer64, safer128, threeway, panama, enigma, wake, xtea,
    ))


__all__ = ["BlockCipherBase", "PyCryptodomeAdapter", "STREAM_ALGORITHMS",
           "make_cipher", "self_test"]
