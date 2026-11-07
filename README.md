# stegseek-py

A pure-Python, standard-layout reimplementation of
[StegSeek 0.6](https://github.com/RickdeJager/stegseek) and the underlying
**steghide 0.5.1** file format. It reads and writes stego files that are
byte-for-byte compatible with the original programs, without a C++ toolchain.

```
stegseek [stegofile.jpg] [wordlist.txt]
stegseek --seed [stegofile.jpg]
stegseek --embed -cf cover.jpg -ef secret.txt -p pass
stegseek --extract -sf stego.jpg -p pass
```

## Why this exists

The original project is C++ and needs libmcrypt/libmhash/libjpeg plus CMake.
This port keeps the same CLI, the same on-disk format and the same crypto, but
runs with `python >= 3.9`, `numpy` and `pycryptodome`. All 22 encryption
algorithms and all 8 modes known to steghide are implemented — the 14 that
pycryptodome does not provide are pure-Python ports of the libmcrypt C sources
(each with a known-answer self test).

## Features

| Area | Covered |
| --- | --- |
| Commands | `--crack` (default), `--seed`, `--embed`, `--extract`, `--info`, `--encinfo`, `--version`, `--license`, `--help` |
| Carriers | JPEG (baseline **and** progressive), BMP (Windows 3.x / OS/2, 1/4/8/24-bit), WAV (8/16-bit PCM), AU (8/16-bit PCM + µ-law) |
| Encryption | `none`, `twofish`, `rijndael-128/192/256`, `saferplus`, `safer-sk64`, `safer-sk128`, `rc2`, `xtea`, `serpent`, `cast-128`, `cast-256`, `loki97`, `gost`, `threeway`, `blowfish`, `des`, `tripledes`, `enigma`, `arcfour`, `panama`, `wake` |
| Modes | `ecb`, `cbc`, `cfb`, `ofb`, `nofb`, `ncfb`, `ctr`, `stream` |
| Payload | zlib compression levels 1–9, optional CRC32, embedded original filename, random padding, IV prefix |
| Cracking | wordlist chunking, three default CTF guesses (`""`, filename, stem), vectorised NumPy magic filter, `--continue`, `-s`, `-t` thread-parallel seed scan |
| I/O | stdin/stdout (`-`), `-f` overwrite, `-q`/`-v`/`-a`/`-n`, accessible output |
| Packaging | `src/` layout, PEP 621 `pyproject.toml`, console scripts, `py.typed`, pytest + ruff |

## Install

```bash
python -m pip install .            # or: python -m pip install -e ".[dev]"
```

Two console scripts are installed (`stegseek`, `stegseek-py`); both point at
`stegseek.cli:main`. Without installing, use `PYTHONPATH=src python -m stegseek.cli ...`.

## Usage

```bash
# Crack with a wordlist (positional stegofile + wordlist + output)
stegseek stego.jpg wordlist.txt found.bin

# Brute-force the 32-bit embedding seed; recovers the file when -e none was used
stegseek --seed stego.jpg recovered.bin -t 8

# Embed / extract
stegseek --embed   -cf cover.jpg -ef secret.txt -p "pass" -sf out.jpg -f
stegseek --extract -sf out.jpg -p "pass" -xf -                 # to stdout

# Inspect
stegseek --info    -p "pass" out.jpg
stegseek --encinfo
stegseek --help -v        # include the steghide help section
```

`-e` accepts `<algo> <mode>` in either order, `-e none`, `-z <1..9>`,
`-Z`, `-K` (no checksum), `-N` (no embedded filename).

## How it works

| Module | C++ counterpart |
| --- | --- |
| `args.py`, `cli.py` | `Arguments.cc`, `Session.cc` |
| `bitstring.py` | `BitString.cc` (LSB-first bit storage) |
| `selector.py` | `Selector.cc`, `PseudoRandomSource.cc` (LCG `A=1367208549`, `C=1`) |
| `embdata.py` | `EmbData.cc` (25-bit magic, version, encinfo, NPlainBits, payload state machine) |
| `crypto.py` | `MCryptPP.cc`, `MHashPP.cc`, `MHashKeyGen.cc` |
| `ciphers/` | libmcrypt `algorithms/*.c` (pure-Python ports + pycryptodome primitives) |
| `cover/` | `JpegFile.cc`, `BmpFile.cc`, `WavFile.cc`, `AuFile.cc` |
| `extractor.py`, `embedder.py` | `Extractor.cc`, `Embedder.cc` |
| `crackers/` | `Cracker.cc`, `PasswordCracker.cc`, `SeedCracker.cc` |

Compatibility-critical details that were reproduced exactly:

* `MHASH_CRC32` is the **non-reflected** CRC-32/BZIP2 variant with libmhash's
  final byte ordering, not `zlib.crc32`.
* `KEYGEN_MCRYPT` derives the key by repeatedly hashing
  `MD5(password || already-generated-key-prefix)`.
* libmcrypt reports a **32-byte** key size for `rijndael-128`, so steghide
  actually uses AES-256; the wide-block variants use Rijndael with 24/32-byte
  blocks and 14 rounds.
* IV length comes from `mcrypt_enc_get_iv_size()`, not the block size:
  `arcfour`/`enigma`/`wake` use **0** IV bytes, `panama` uses 32.
* JPEG samples are the **non-zero DCT coefficients** in libjpeg's
  component-major / block-row / block-column / 64-coefficient order; the
  embedded value is `abs(coeff) % 2`. Progressive scans use unpadded MCU grids
  and per-scan DHT/DRI snapshots.
* The vectorised magic filter reproduces `Cracker::verifyMagic`'s early-exit
  semantics: an RNG collision only makes a seed a candidate if it occurs
  **before** the first magic-bit mismatch.

## Verification

`scripts/cross_validate.py` runs the full two-way comparison against the
original `steghide 0.5.1` binary (the exact version StegSeek 0.6 is based on):

```bash
python scripts/cross_validate.py                 # writes crossval/validation_report.json
python scripts/cross_validate.py --quick        # skip the 109-pair cipher matrix
```

Current results: **50/50 checks pass**, including

* capacity for all 15 reference cover files (BMP/WAV/AU/JPEG, progressive JPEG),
* oracle-embed → Python-extract and Python-embed → oracle-extract for all 15,
* **109 algorithm/mode pairs, both directions**, with identical payload bytes
  and CRC,
* `--crack` on upstream `sun.jpg` / `rngcollision.jpg` (the RNG-collision case),
* `--seed` recovering an unencrypted payload at seed `0x00000291`.

An additional 131 internal embed→extract combinations cover the four
algorithm names (`safer-sk64`, `safer-sk128`, `threeway`, `panama`) that are
not installed in the local reference libmcrypt build; those are validated with
their C-source known-answer vectors instead. See
[`CROSS_VALIDATION.md`](CROSS_VALIDATION.md) for the full report.

## Tests and lint

```bash
python -m pytest            # 226 tests, ~14 s
python -m ruff check src tests scripts
python -m build             # wheel + sdist
```

## Known limitations

* **Embedding distortion.** steghide uses a graph-matching heuristic to pick
  which sample of each vertex to change. This port changes one sample per
  vertex (the extractor only sees `sum(evalues) % modulus`), so files are fully
  compatible but the visual/audible distortion is not minimised the same way.
  Consequently `-r/--radius` and `-g/--goal` are accepted but have no effect.
* **`--seed` throughput.** The full 2^32 search is NumPy-vectorised and
  thread-parallel (`-t`), but is still slower than StegSeek's optimised C++.
* **`--encinfo`** lists every algorithm steghide knows by name; a given
  libmcrypt installation lists only its compiled-in modules, so line ordering
  and the exact set may differ from a particular original binary.
* Debug commands (`--printgraph`, `--printstats`, `--debuglevel`, …) are
  parsed for CLI compatibility but do not produce graph/statistics output.
* `--info` prints `Byte(s)` (StegSeek's `Utils::formatHRSize`); steghide 0.5.1
  prints `Byte`.

## Layout

```
src/stegseek/          package (console scripts, core, cover/, crackers/, ciphers/)
tests/                 pytest suite
scripts/               reproducible cross-validation harness
_reference/            upstream StegSeek / libmcrypt sources + reference binary (study only)
crossval/              generated verification artifacts and JSON report
```

## License

GPL-2.0-or-later — see [`LICENSE`](LICENSE). This is a derivative work of
StegSeek (Rick de Jager) and steghide (Stefan Hetzl); the libmcrypt C sources
were used as a specification for the pure-Python cipher ports.
