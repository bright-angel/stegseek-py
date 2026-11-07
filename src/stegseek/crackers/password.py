"""Port of ``src/PasswordCracker.cc`` (wordlist cracking)."""

from __future__ import annotations

import os
from typing import Iterable

from ..args import Arguments
from ..cover.base import format_hr_size
from ..errors import SteghideError
from ..messages import msg, msg_raw, verbose
from ..selector import passphrase_to_seed
from .common import CrackerBase, strip_dir, verify_passphrase_batch

CHUNK = 65536


class PasswordCracker(CrackerBase):
    def __init__(self, args: Arguments, cover=None):
        super().__init__(args, cover)
        verbose('Using wordlist file "%s".\n', args.wordlist_fn)

    def crack(self) -> bool:
        path = self.args.wordlist_fn
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            raise SteghideError('could not open the wordlist "%s".' % path) from exc

        # The C++ worker threads split the wordlist by byte offset; the first
        # worker additionally tries three "silly CTF guesses" up front.
        if not self.args.skip_default:
            filename = strip_dir(self.args.stg_fn or "")
            stem = filename.rsplit(".", 1)[0] if "." in filename else filename
            for guess in (b"", filename.encode("utf-8", "surrogateescape"),
                          stem.encode("utf-8", "surrogateescape")):
                verbose('Added password guess: "%s".\n', guess.decode("utf-8", "surrogateescape"))
                if self._try(guess):
                    self.success = True
                    if not self.args.continue_after:
                        return True

        with open(path, "rb") as fh:
            while True:
                chunk = fh.readlines(CHUNK * 32)
                if not chunk:
                    break
                passwords = [line.rstrip(b"\r\n") for line in chunk]
                for sub in _chunks(passwords, CHUNK):
                    for candidate in verify_passphrase_batch(self.verifier, sub):
                        if self._try(candidate):
                            self.success = True
                            if not self.args.continue_after:
                                return True
                if self.args.verbosity not in ("quiet",):
                    # Match the C++ metrics threshold (only for large lists).
                    if size > 500000:
                        percent = 100.0 * min(1.0, fh.tell() / max(size, 1))
                        msg_raw("Progress: %.2f%% (%s)           \r",
                                percent, format_hr_size(fh.tell()))
        if not self.success:
            raise SteghideError("Could not find a valid passphrase.")
        if self.args.verbosity != "quiet" and size > 500000:
            msg_raw("\n")
        return True

    def _try(self, passphrase: bytes) -> bool:
        if not self.verifier.verify(passphrase_to_seed(passphrase)):
            return False
        emb = self.full_extract(passphrase=passphrase)
        if emb is None:
            return False
        if not (self.args.continue_after or self.result_num == 0):
            return False
        self.result_num += 1
        msg('Found passphrase: "%s"\n', passphrase.decode("utf-8", "surrogateescape"))
        self.write_result(emb)
        return True


def _chunks(items: list[bytes], size: int) -> Iterable[list[bytes]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]
