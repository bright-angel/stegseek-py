"""End-to-end embed -> extract round trips (no external oracle required)."""

from __future__ import annotations

import os

import pytest

from stegseek.args import parse_arguments
from stegseek.const import ENCRYPTION_ALGORITHMS
from stegseek.cover import read_cover_file
from stegseek.crackers.seed import try_seed
from stegseek.embedder import build_payload, check_capacity, embed
from stegseek.extractor import extract
from stegseek.selector import passphrase_to_seed

PAYLOAD = b"This is a test file\n"
PASSWORD = "UnitTestPW"

STREAM_ALGOS = {"enigma", "arcfour", "panama", "wake"}


def _embed_args(cover: str, payload_path: str, out: str, *extra: str):
    return parse_arguments(["--embed", "-cf", cover, "-ef", payload_path,
                            "-sf", out, "-p", PASSWORD, "-f", "-q", *extra])


def _roundtrip(tmp_path, cover_path, payload_path, *extra, password=PASSWORD):
    out = str(tmp_path / ("stego" + os.path.splitext(cover_path)[1]))
    args = _embed_args(cover_path, payload_path, out, *extra)
    data = embed(args)
    with open(out, "wb") as fh:
        fh.write(data)
    emb = extract(read_cover_file(out), password.encode())
    return emb


@pytest.mark.parametrize("suffix", [".jpg", ".bmp", ".wav", ".au"])
def test_embed_extract_all_four_families(tmp_path, payload, cover_files, suffix):
    path = next(p for p in cover_files if p.suffix.lower() == suffix)
    emb = _roundtrip(tmp_path, str(path), str(payload))
    assert emb.data == PAYLOAD
    assert emb.checksum_ok()
    assert emb.filename == b"payload.bin"


def test_all_fifteen_cover_variants(tmp_path, payload, cover_files):
    for path in cover_files:
        out = str(tmp_path / ("stego_" + path.name))
        args = _embed_args(str(path), str(payload), out)
        with open(out, "wb") as fh:
            fh.write(embed(args))
        emb = extract(read_cover_file(out), PASSWORD.encode())
        assert emb.data == PAYLOAD, path.name
        assert emb.checksum_ok(), path.name


@pytest.mark.parametrize("algo", [a for a in ENCRYPTION_ALGORITHMS if a != "none"])
def test_every_encryption_algorithm_roundtrips(tmp_path, payload, sun_jpg, algo):
    mode = "stream" if algo in STREAM_ALGOS else "cbc"
    spec = ["-e", algo, mode]
    emb = _roundtrip(tmp_path, str(sun_jpg), str(payload), *spec)
    assert emb.data == PAYLOAD
    assert emb.checksum_ok()


@pytest.mark.parametrize("mode", ["ecb", "cbc", "ofb", "cfb", "nofb", "ncfb", "ctr"])
def test_every_encryption_mode_roundtrips(tmp_path, payload, sun_jpg, mode):
    emb = _roundtrip(tmp_path, str(sun_jpg), str(payload), "-e", "rijndael-128", mode)
    assert emb.data == PAYLOAD


@pytest.mark.parametrize("extra,expected_compressed", [
    (["-e", "none"], True),
    (["-Z"], False),
    (["-z", "1"], True),
    (["-K"], True),
    (["-N"], True),
])
def test_embed_options(tmp_path, payload, sun_jpg, extra, expected_compressed):
    emb = _roundtrip(tmp_path, str(sun_jpg), str(payload), *extra)
    assert emb.data == PAYLOAD
    assert (emb.compression > 0) is expected_compressed
    if extra == ["-N"]:
        assert emb.filename == b""


def test_no_checksum_flag(tmp_path, payload, sun_jpg):
    emb = _roundtrip(tmp_path, str(sun_jpg), str(payload), "-K")
    assert emb.checksum is False
    assert emb.checksum_ok() is True  # no checksum means nothing to fail


def test_capacity_check_rejects_oversized_payload(tmp_path, sun_jpg):
    big = tmp_path / "big.bin"
    big.write_bytes(os.urandom(200 * 1024))  # incompressible -> exceeds 914 B capacity
    args = _embed_args(str(sun_jpg), str(big), str(tmp_path / "out.jpg"))
    from stegseek.errors import SteghideError
    with pytest.raises(SteghideError):
        embed(args)
    bits = build_payload(b"small", args)
    assert check_capacity(read_cover_file(str(sun_jpg)), bits) > 0


def test_seed_cracker_recovers_unencrypted_data(tmp_path, payload, sun_jpg):
    out = str(tmp_path / "seed.jpg")
    args = _embed_args(str(sun_jpg), str(payload), out, "-e", "none")
    with open(out, "wb") as fh:
        fh.write(embed(args))
    cover = read_cover_file(out)
    seed = passphrase_to_seed(PASSWORD.encode())
    result = try_seed(cover, seed)
    assert result.found
    assert result.seed == seed
    assert result.enc_algo == 0
    emb = extract(cover, seed=seed)
    assert emb.data == PAYLOAD


def test_wrong_passphrase_is_detected(tmp_path, payload, sun_jpg):
    from stegseek.errors import SteghideError
    out = str(tmp_path / "wrong.jpg")
    args = _embed_args(str(sun_jpg), str(payload), out)
    with open(out, "wb") as fh:
        fh.write(embed(args))
    cover = read_cover_file(out)
    with pytest.raises(SteghideError):
        extract(cover, b"definitely-wrong")
