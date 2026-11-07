"""Cover/stego file format detection and loading (``CvrStgFile::readFile``)."""

from __future__ import annotations

from pathlib import Path

from ..errors import UnSupFileFormat
from .au import AuFile
from .base import CoverFile, format_hr_size
from .bmp import BmpFile
from .jpeg import JpegFile
from .wav import WavFile


def read_cover_file(path: str | Path, raw: bytes | None = None) -> CoverFile:
    path = str(path)
    if raw is None:
        try:
            raw = Path(path).read_bytes()
        except OSError as exc:
            raise UnSupFileFormat('could not open the file "%s".' % path) from exc
    head = raw[:4]
    if head[:2] == b"BM":
        return BmpFile(path, raw)
    if head[:2] == b"\xff\xd8":
        return JpegFile(path, raw)
    if head == b".snd":
        return AuFile(path, raw)
    if head == b"RIFF":
        return WavFile(path, raw)
    raise UnSupFileFormat('the file format of the file "%s" is not supported.' % path)


__all__ = ["read_cover_file", "CoverFile", "format_hr_size",
           "JpegFile", "BmpFile", "WavFile", "AuFile"]
