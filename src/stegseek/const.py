"""Constants transcribed from the StegSeek / steghide C++ sources."""

from __future__ import annotations

U32 = 1 << 32
U32_MASK = U32 - 1

# src/Cracker.h, src/EmbData.h -- 's', 'h', 'm' followed by a zero bit
MAGIC = 0x073688D
NBITS_MAGIC = 24

# src/PseudoRandomSource.h
LCG_A = 1367208549
LCG_C = 1

# src/EmbData.h
NBITS_NPLAINBITS = 32
NBITS_NUNCOMPRESSEDBITS = 32
NBITS_CRC32 = 32
CODE_VERSION = 0

# src/ProgressOutput / Cracker.h
PROGRESS_DELTA_MS = 40
PROGRESS_DELTA_ACCESSIBLE_MS = 500
ACCESSIBLE_UPDATE_THRESHOLD = 1.0

# src/EncryptionAlgorithm.cc, ordered by integer representation
ENCRYPTION_ALGORITHMS = (
    "none",
    "twofish",
    "rijndael-128",
    "rijndael-192",
    "rijndael-256",
    "saferplus",
    "rc2",
    "xtea",
    "serpent",
    "safer-sk64",
    "safer-sk128",
    "cast-256",
    "loki97",
    "gost",
    "threeway",
    "cast-128",
    "blowfish",
    "des",
    "tripledes",
    "enigma",
    "arcfour",
    "panama",
    "wake",
)

# src/EncryptionMode.cc, ordered by integer representation
ENCRYPTION_MODES = (
    "ecb",
    "cbc",
    "ofb",
    "cfb",
    "nofb",
    "ncfb",
    "ctr",
    "stream",
)

ENC_ALGO_NONE = 0
ENC_ALGO_RIJNDAEL128 = 2
ENC_MODE_ECB = 0
ENC_MODE_CBC = 1
ENC_MODE_OFB = 2
ENC_MODE_CFB = 3
ENC_MODE_NOFB = 4
ENC_MODE_NCFB = 5
ENC_MODE_CTR = 6
ENC_MODE_STREAM = 7

STEGSEEK_VERSION = "0.6"
STEGHIDE_VERSION = "0.5.1"

# libmcrypt algorithm properties: name -> (key size in bytes, block size in bytes)
# ``mcrypt_enc_get_key_size`` / ``mcrypt_enc_get_block_size``.
MCRYPT_KEY_SIZE = {
    "none": 0,
    "twofish": 32,
    # libmcrypt reports the *maximum* key size and passes that length to
    # mcrypt_generic_init(), so rijndael-128 is actually used as AES-256.
    "rijndael-128": 32,
    "rijndael-192": 32,
    "rijndael-256": 32,
    "saferplus": 32,
    "rc2": 128,
    "xtea": 16,
    "serpent": 32,
    "safer-sk64": 8,
    "safer-sk128": 16,
    "cast-256": 32,
    "loki97": 32,
    "gost": 32,
    "threeway": 12,
    "cast-128": 16,
    "blowfish": 56,
    "des": 8,
    "tripledes": 24,
    "enigma": 13,
    "arcfour": 256,
    "panama": 32,
    "wake": 32,
}

MCRYPT_BLOCK_SIZE = {
    "none": 1,
    "twofish": 16,
    "rijndael-128": 16,
    "rijndael-192": 24,
    "rijndael-256": 32,
    "saferplus": 16,
    "rc2": 8,
    "xtea": 8,
    "serpent": 16,
    "safer-sk64": 8,
    "safer-sk128": 8,
    "cast-256": 16,
    "loki97": 16,
    "gost": 8,
    "threeway": 12,
    "cast-128": 8,
    "blowfish": 8,
    "des": 8,
    "tripledes": 8,
    "enigma": 1,
    "arcfour": 1,
    "panama": 1,
    "wake": 1,
}

# Modes that libmcrypt reports as having an IV (mcrypt_enc_mode_has_iv).
MODES_WITH_IV = frozenset({ENC_MODE_CBC, ENC_MODE_OFB, ENC_MODE_CFB,
                           ENC_MODE_NOFB, ENC_MODE_NCFB, ENC_MODE_CTR,
                           ENC_MODE_STREAM})

# ``mcrypt_enc_get_iv_size`` is *not* simply the block size for stream
# algorithms: libmcrypt calls the algorithm's ``_mcrypt_get_algo_iv_size``.
# In the reference libmcrypt 2.5.x build USE_IV is undefined, so arcfour and
# wake report 0, enigma reports 0 and panama reports 32.  steghide's
# MCryptPP::_encrypt() prepends exactly this many random bytes (stream.c's
# _init_mcrypt ignores them entirely), so a wrong value shifts the whole
# ciphertext by one byte and breaks decompression.
MCRYPT_IV_SIZE = {
    "enigma": 0,
    "arcfour": 0,
    "panama": 32,
    "wake": 0,
}


def algo_name(index: int) -> str:
    try:
        return ENCRYPTION_ALGORITHMS[index]
    except IndexError:
        return "none"


def mode_name(index: int) -> str:
    try:
        return ENCRYPTION_MODES[index]
    except IndexError:
        return "ecb"


def algo_index(name: str) -> int:
    return ENCRYPTION_ALGORITHMS.index(name)


def mode_index(name: str) -> int:
    return ENCRYPTION_MODES.index(name)
