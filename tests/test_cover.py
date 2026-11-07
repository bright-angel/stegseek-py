"""Tests for the JPEG / BMP / WAV / AU cover-file parsers."""

from __future__ import annotations

import pytest

from stegseek.cover import read_cover_file
from stegseek.errors import UnSupFileFormat

# Values cross-checked against `steghide info` (capacity in whole bytes).
CAPACITIES = {
    "mulaw_std.au": 146,
    "os21x1_std.bmp": 144,
    "os21x24_std.bmp": 288,
    "os21x4_std.bmp": 144,
    "os21x8_std.bmp": 192,
    "pcm16_std.au": 146,
    "pcm16_std.wav": 168,
    "pcm8_std.au": 146,
    "pcm8_std.wav": 138,
    "prog.jpg": 203,
    "std.jpg": 147,
    "win3x1_std.bmp": 144,
    "win3x24_std.bmp": 288,
    "win3x4_std.bmp": 144,
    "win3x8_std.bmp": 192,
}


@pytest.mark.parametrize("name,expected", sorted(CAPACITIES.items()))
def test_capacity_matches_steghide(cover_files, name, expected):
    path = next(p for p in cover_files if p.name == name)
    cover = read_cover_file(str(path))
    assert cover.capacity() == expected
    assert cover.num_samples > 0
    assert len(cover.evalues) == cover.num_samples


def test_baseline_and_progressive_jpeg_parse(cover_files):
    for name in ("std.jpg", "prog.jpg"):
        path = next(p for p in cover_files if p.name == name)
        cover = read_cover_file(str(path))
        assert cover.properties()[0][1] == "jpeg"
        assert all(0 <= v < cover.modulus for v in cover.evalues)


def test_embedded_value_setter_is_observable(cover_files):
    path = next(p for p in cover_files if p.name == "std.jpg")
    cover = read_cover_file(str(path))
    original = int(cover.evalues[0])
    for target in range(cover.modulus):
        cover.set_embedded_value(0, target)
        assert int(cover.evalues[0]) == target
    cover.set_embedded_value(0, original)
    assert int(cover.evalues[0]) == original


def test_unsupported_format_raises(tmp_path):
    bad = tmp_path / "bad.bin"
    bad.write_bytes(b"this is not an image\n")
    with pytest.raises(UnSupFileFormat):
        read_cover_file(str(bad))


def test_roundtrip_serialisation_preserves_samples(cover_files):
    for path in cover_files:
        cover = read_cover_file(str(path))
        data = cover.to_bytes()
        assert isinstance(data, (bytes, bytearray)) and len(data) > 0
        # Parsing the re-serialised file must produce the same sample vector.
        again = read_cover_file(str(path), bytes(data))
        assert list(again.evalues) == list(cover.evalues)
