"""Shared ``Cracker`` behaviour (``src/Cracker.cc``)."""

from __future__ import annotations

import os
import sys

from ..args import Arguments
from ..cover import read_cover_file
from ..cover.base import CoverFile
from ..embdata import EmbData
from ..errors import BinaryOutputError, CorruptDataError, SteghideError
from ..messages import msg
from ..selector import passphrase_to_seed
from .base import MagicVerifier


def load_stego(args: Arguments) -> CoverFile:
    if not args.is_set("stg_fn"):
        raise SteghideError("No stegofile specified as input.")
    if args.stg_fn == "":
        return read_cover_file("", sys.stdin.buffer.read())
    return read_cover_file(args.stg_fn)


def strip_dir(path: str) -> str:
    return os.path.basename(path.replace("\\", "/"))


def _check_force(path: str, args: Arguments) -> None:
    if args.force or not os.path.exists(path):
        return
    try:
        answer = input('the file "%s" does already exist. overwrite ? (y/n) ' % path)
    except (EOFError, OSError):
        answer = "n"
    if not answer.strip().lower().startswith("y"):
        raise SteghideError('did not write to file "%s".' % path)


class CrackerBase:
    def __init__(self, args: Arguments, cover: CoverFile | None = None):
        self.args = args
        self.cover = cover if cover is not None else load_stego(args)
        self.verifier = MagicVerifier(self.cover)
        self.result_num = 0
        self.save_file_index = 0
        self.success = False
        self.stopped = False

    def write_result(self, emb: EmbData) -> None:
        """``Cracker::extract``: choose the output file and write the payload."""
        original = emb.filename.decode("utf-8", "surrogateescape") if isinstance(
            emb.filename, bytes) else emb.filename
        out_fn = strip_dir(self.args.stg_fn or "") + ".out"
        if self.args.is_set("ext_fn"):
            out_fn = self.args.ext_fn or ""

        if original:
            msg('Original filename: "%s".\n', original)
        if out_fn == "":
            msg("Extracting to stdout.\n\n")
            sys.stdout.buffer.write(emb.data)
            sys.stdout.buffer.flush()
            return

        file_num = self.save_file_index
        self.save_file_index += 1
        if file_num:
            out_fn += ".%d" % file_num
        msg('Extracting to "%s".\n', out_fn)
        _check_force(out_fn, self.args)
        try:
            with open(out_fn, "wb") as fh:
                fh.write(emb.data)
        except OSError as exc:
            raise BinaryOutputError('could not open the file "%s".' % out_fn) from exc

    def full_extract(self, passphrase: bytes | None = None,
                     seed: int | None = None) -> EmbData | None:
        """Strict re-extraction with the real ``Selector``; ``None`` on failure."""
        from ..extractor import extract
        try:
            return extract(self.cover, passphrase=passphrase, seed=seed)
        except (SteghideError, ValueError, IndexError, KeyError):
            return None

    def handle_passphrase(self, passphrase: bytes) -> bool:
        if not (self.args.continue_after or self.result_num == 0):
            return False
        self.result_num += 1
        msg('Found passphrase: "%s"\n', passphrase.decode("utf-8", "surrogateescape"))
        emb = self.full_extract(passphrase=passphrase)
        if emb is None:
            raise CorruptDataError("could not extract any data with that passphrase!")
        self.write_result(emb)
        return True


def verify_passphrase_batch(verifier: MagicVerifier, passwords: list[bytes]):
    """Return the passwords whose fast magic check passes."""
    import numpy as np

    if not passwords:
        return []
    seeds = np.fromiter((passphrase_to_seed(p) for p in passwords),
                        dtype=np.uint64, count=len(passwords))
    mask = verifier.verify_batch(seeds)
    return [p for p, hit in zip(passwords, mask) if hit]
