"""Port of ``src/SeedCracker.cc`` (brute-force embedding-pattern cracking).

The C++ version splits the 2^32 seed space across worker threads.  NumPy's
``verify_filtered`` releases the GIL for its heavy array work, so a
ThreadPoolExecutor gives a real speed-up while keeping the cover file shared
(read-only) and the candidate order deterministic.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import numpy as np

from ..args import Arguments
from ..const import ENCRYPTION_ALGORITHMS, ENCRYPTION_MODES, MAGIC
from ..cover.base import CoverFile, format_hr_size
from ..errors import SteghideError
from ..messages import msg, msg_raw
from ..selector import Selector
from .common import CrackerBase

REQUESTED_VALUES = 25 + 3 + 5 + 32
DEFAULT_CHUNK = 1 << 16
SEED_LIMIT = 1 << 32


class SeedResult:
    __slots__ = ("found", "seed", "plain_size", "enc_algo", "enc_mode")

    def __init__(self, found=False, seed=0, plain_size=0, enc_algo=0, enc_mode=0):
        self.found = found
        self.seed = seed
        self.plain_size = plain_size
        self.enc_algo = enc_algo
        self.enc_mode = enc_mode


def try_seed(cover: CoverFile, seed: int) -> SeedResult:
    """``SeedCracker::trySeed``: strict header check via the real ``Selector``."""
    spv = cover.samples_per_vertex
    bpv = cover.bits_per_emb_value
    modulus = cover.modulus
    sel = Selector(cover.num_samples, seed)
    indices = sel.indices(REQUESTED_VALUES * spv)
    sv_idx = 0
    bits: list[int] = []
    for _ in range(REQUESTED_VALUES):
        ev = 0
        for _ in range(spv):
            ev = (ev + int(cover.evalues[indices[sv_idx]])) % modulus
            sv_idx += 1
        for k in range(bpv):
            bits.append((ev >> k) & 1)

    def field(start: int, count: int) -> int:
        return sum(bits[start + i] << i for i in range(count))

    # 's','h','m' followed by the version bit (0)
    if field(0, 25) != MAGIC:
        return SeedResult()
    enc_algo = field(25, 5)
    if enc_algo > 22:
        return SeedResult()
    enc_mode = field(30, 3)
    plain_size = field(33, 32)
    if plain_size * spv > cover.num_samples - REQUESTED_VALUES * spv:
        return SeedResult()
    return SeedResult(True, seed, plain_size, enc_algo, enc_mode)


class SeedCracker(CrackerBase):
    def __init__(self, args: Arguments, cover: CoverFile | None = None,
                 chunk: int = DEFAULT_CHUNK, limit: int = SEED_LIMIT):
        super().__init__(args, cover)
        self.chunk = chunk
        self.limit = limit

    def _candidates(self, seeds: np.ndarray, workers: int, executor) -> np.ndarray:
        if executor is None:
            return self.verifier.verify_filtered(seeds)
        # Each worker gets roughly self.chunk seeds, so peak memory does not
        # grow with the thread count.  Results are concatenated in seed order.
        parts = np.array_split(seeds, workers)
        results = executor.map(lambda p: self.verifier.verify_filtered(p), parts)
        return np.concatenate(list(results))

    def crack(self) -> bool:
        workers = max(1, min(int(self.args.threads or 1), 32))
        chunk = self.chunk if workers == 1 else max(4096, self.chunk // workers)
        step = chunk * workers
        executor = ThreadPoolExecutor(max_workers=workers) if workers > 1 else None
        total = 0
        next_progress = 5_000_000
        try:
            for start in range(0, self.limit, step):
                stop = min(start + step, self.limit)
                seeds = np.arange(start, stop, dtype=np.uint32)
                candidates = self._candidates(seeds, workers, executor)
                for seed in candidates:
                    result = try_seed(self.cover, int(seed))
                    if not result.found:
                        continue
                    self.success = True
                    self._handle(result)
                    if not self.args.continue_after:
                        if self.args.verbosity != "quiet" and total > 500000:
                            msg_raw("\n")
                        return True
                total += stop - start
                if self.args.verbosity != "quiet" and total >= next_progress:
                    if self.args.accessible:
                        msg("%.0f%%\n", 100.0 * total / SEED_LIMIT)
                    else:
                        msg("Progress: %.2f%% (%d seeds)           \r",
                            100.0 * total / SEED_LIMIT, total)
                    next_progress = total + 5_000_000
        finally:
            if executor is not None:
                executor.shutdown(wait=True)
        if not self.success:
            raise SteghideError("Could not find a valid seed.")
        return True

    def _handle(self, result: SeedResult) -> None:
        if not (self.args.continue_after or self.result_num == 0):
            return
        self.result_num += 1
        algo = ENCRYPTION_ALGORITHMS[result.enc_algo] if result.enc_algo < len(ENCRYPTION_ALGORITHMS) else "none"
        mode = ENCRYPTION_MODES[result.enc_mode] if result.enc_mode < len(ENCRYPTION_MODES) else "ecb"
        msg('Found (possible) seed: "%08x"            \n'
            '\tPlain size: %s (compressed)\n'
            '\tEncryption Algorithm: %s\n'
            '\tEncryption Mode:      %s\n',
            result.seed, format_hr_size(result.plain_size // 8), algo, mode)
        # Unencrypted data can be recovered without a passphrase.
        if result.enc_algo == 0:
            emb = self.full_extract(seed=result.seed)
            if emb is not None:
                self.write_result(emb)
