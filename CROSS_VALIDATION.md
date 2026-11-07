# Cross-validation report

## Setup

| Item | Value |
| --- | --- |
| Target | `stegseek-py` 0.6.0 (pure Python, `src/` layout) |
| Reference oracle | `steghide 0.5.1` Windows/Cygwin build, the exact upstream version StegSeek 0.6 is based on |
| Oracle path | `_reference/tools/steghide-win/steghide/steghide.exe` |
| Upstream sources | `_reference/stegseek/` (v0.6), `_reference/libsrc/` (libmcrypt algorithms/modes, libmhash keygen) |
| Environment | Windows, Python 3.13.14, NumPy 2.5.4, pycryptodome 4.3.0 |
| Reproduce | `python scripts/cross_validate.py` → `crossval/validation_report.json` |

**Why not the original StegSeek binary?** `wsl.exe` is blocked by the local
security policy and no native C++ toolchain (`gcc`/`cmake`/`make`/`clang`/`docker`)
is available, so StegSeek 0.6 cannot be compiled here. StegSeek only adds
`--crack` / `--seed` on top of steghide 0.5.1; those two paths are validated
against the upstream StegSeek test corpus (`sun.jpg`, `rngcollision.jpg`, the
documented passwords and seed values) instead.

## Result summary

```
=== SUMMARY: 50/50 checks passed ===
```

| Group | Cases | Result |
| --- | --- | --- |
| Oracle version sanity | 1 | pass (steghide 0.5.1) |
| Capacity for all reference cover files | 15 | 15/15 identical |
| Oracle embed → Python extract (all cover formats) | 15 | 15/15 identical payload + CRC |
| Python embed → Oracle extract (all cover formats) | 15 | 15/15 identical payload |
| Encryption matrix, **both directions** | 109 algorithm/mode pairs | 109/109 |
| `--crack` upstream cases | 2 | 2/2 (incl. RNG-collision case) |
| `--seed` unencrypted recovery | 1 | pass |
| Total | **50** | **50 pass / 0 fail** |

Additional independent runs:

* **131/131** internal Python-embed → Python-extract combinations covering all
  22 algorithm names × their valid modes (including `safer-sk64`,
  `safer-sk128`, `threeway`, `panama`, which are absent from this particular
  libmcrypt build).
* **14 pure-Python cipher ports** reproduce the exact `#define CIPHER`
  known-answer vectors from the libmcrypt C sources (`ciphers.self_test()`).
* **20,000 random seeds**: vectorised `MagicVerifier.verify_batch()` agrees
  bit-for-bit with the scalar C++-equivalent `verify()` (0 mismatches).
* **226 pytest tests** pass; `ruff check src tests scripts` is clean; the
  wheel and sdist build and the installed `stegseek` console script performs a
  full embed/extract round trip against the oracle.

## Cover format details

15 carrier variants from the upstream test corpus. `capacity` is in whole bytes
and matches `steghide info` exactly:

| File | Samples | Samples/vertex | Modulus | Capacity |
| --- | ---: | ---: | ---: | ---: |
| `std.jpg` (baseline JPEG) | 3548 | 3 | 2 | 147 |
| `prog.jpg` (progressive JPEG) | 4887 | 3 | 2 | 203 |
| `sun.jpg` (upstream crack sample) | 21937 | 3 | 2 | 914 |
| `os21x1_std.bmp` / `win3x1_std.bmp` | 2304 | 2 | 2 | 144 |
| `os21x4_std.bmp` / `win3x4_std.bmp` | 2304 | 2 | 2 | 144 |
| `os21x8_std.bmp` / `win3x8_std.bmp` | 2304 | 3 | 4 | 192 |
| `os21x24_std.bmp` / `win3x24_std.bmp` | 2304 | 2 | 4 | 288 |
| `pcm8_std.wav` | 2216 | 2 | 2 | 138 |
| `pcm16_std.wav` | 2701 | 2 | 2 | 168 |
| `pcm8_std.au` / `pcm16_std.au` / `mulaw_std.au` | 2341 | 2 | 2 | 146 |

Both directions of embed/extract were checked on every one of these files with
the payload `b"This is a test file\n"`, passphrase `P@ssw0rd`, default
`rijndael-128/cbc`, compression 9 and CRC enabled.

## Encryption matrix

All 15 block algorithms available in the reference build × 7 block modes
(`ecb cbc ofb cfb nofb ncfb ctr`) = 105, plus 3 stream algorithms × `stream`
= 3, plus `none/cbc` = 1 → **109 pairs**. For each pair:

1. `steghide embed -e <algo> <mode>` → `stegseek --extract` (Python) → payload
   bytes and CRC must match;
2. `stegseek --embed -e <algo> <mode>` (Python) → `steghide extract` → payload
   bytes must match.

This also validates key sizes, IV prefixes, random bit padding, the encrypted
size formula `IVbits + ceil(plainbits / blockbits) * blockbits`, zlib framing
and the non-reflected CRC32.

The four remaining names (`safer-sk64`, `safer-sk128`, `threeway`, `panama`)
are recognised by steghide but not compiled into this Windows libmcrypt build;
their Python implementations are validated against the C source self-test
vectors and a full internal embed/extract round trip.

## StegSeek-specific paths

| Case | Expected | Result |
| --- | --- | --- |
| `sun.jpg` + wordlist containing `stegseek` | passphrase `stegseek`, `This is a very secret file\n` | pass |
| `rngcollision.jpg` + wordlist containing `iluv1josh` | passphrase `iluv1josh`, `This is a secret message.\n- RdJ\n` | pass |
| unencrypted file embedded with `moana5` | seed `0x00000291`, payload recovered without passphrase | pass |
| `--seed` with `-t 1` and `-t 4` | identical seed and payload | pass |
| `-v`, `-q`, `-a`, `-f`, `-xf -`, `-e none`, `-Z`, `-K`, `-N` | CLI-compatible behaviour | pass |

Seed derivation cross-checks: `moana5 → 0x00000291`, `apple87 → 0x00000e1a`
(MD5 XOR of four little-endian words), matching the upstream test suite.

## Defects found and fixed during this validation

1. **JPEG coefficient linearisation.** Baseline scans were initially decoded as
   progressive AC-only scans, giving 3,276 non-zero coefficients instead of
   21,937. Ported libjpeg's component-major / block-row / block-column ordering
   and the DC+AC baseline path; added per-scan DHT/DQT/DRI snapshots.
2. **Progressive MCU grid.** libjpeg's padded virtual arrays must not be
   linearised; using unpadded `width_in_blocks * height_in_blocks` fixed
   `prog.jpg` (`capacity 203 Byte`).
3. **16-bit DQT tables.** `to_bytes()` now emits 16-bit quant values according
   to the table maximum.
4. **AES key size.** libmcrypt's `rijndael-128` reports a 32-byte key, i.e.
   AES-256, not AES-128. This was the cause of garbage decryption on `sun.jpg`.
5. **IV length for stream ciphers.** `mcrypt_enc_get_iv_size()` is 0 for
   `arcfour`/`enigma`/`wake` and 32 for `panama` in this libmcrypt build.
   Treating it as the block size shifted the whole ciphertext by one byte and
   broke `arcfour/stream`; added an explicit `MCRYPT_IV_SIZE` table.
6. **Vectorised magic filter.** An early version OR-ed "any RNG collision" into
   the result, producing ~11% false positives. Rewritten to reproduce
   `Cracker::verifyMagic`'s early exit (collision must precede the first magic
   mismatch). 20,000 random seeds now agree with the scalar implementation.
7. **Random padding granularity.** `EmbData::padRandom()` adds individual bits,
   not bytes; the plain bit string is not byte aligned after the compression
   flag and length field.
8. **Capacity integer division.** `CvrStgFile::getCapacity()` performs integer
   division on `numSamples / samplesPerVertex` before the float computation.
9. **`--seed` plain-size formatting.** C++ passes an `unsigned long` produced by
   integer division; Python was passing a float and printing `50.1 Byte(s)`
   instead of `50.0 Byte(s)`.
10. **`--info` stdin title** emitted `data from standard input::`.

## Remaining differences

* The embedding heuristic (see README "Known limitations") changes one sample
  per vertex instead of using steghide's graph matching. File compatibility is
  unaffected; distortion minimisation is not identical.
* `--encinfo` prints every algorithm name known to steghide, while the original
  prints only the modules installed in the local libmcrypt (`18` in this build).
* Debug/graph options are parsed but do not emit graph output.
* `-t` now drives a real `ThreadPoolExecutor` over the seed space (measured
  ~3.5× speed-up at 8 workers); the C++ version remains faster overall.
