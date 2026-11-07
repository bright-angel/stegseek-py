"""Port of ``Cracker::verifyMagic`` plus vectorised NumPy equivalents."""

from __future__ import annotations

import numpy as np

from ..const import LCG_A, LCG_C, MAGIC, NBITS_MAGIC, U32, U32_MASK
from ..cover.base import CoverFile, div_roundup


class MagicVerifier:
    """Fast magic check on the 24-bit 'shm' header."""

    def __init__(self, cover: CoverFile):
        self.values = np.ascontiguousarray(cover.evalues, dtype=np.int32)
        self.num_samples = cover.num_samples
        self.spv = cover.samples_per_vertex
        self.bpv = cover.bits_per_emb_value
        self.modulus = cover.modulus
        self.n_groups = div_roundup(NBITS_MAGIC, self.bpv)
        self.n_steps = self.n_groups * self.spv
        self.expected = [
            (MAGIC >> (g * self.bpv)) & ((1 << self.bpv) - 1)
            for g in range(self.n_groups)
        ]

    # ------------------------------------------------------------ scalar version
    def verify(self, seed: int) -> bool:
        """Bit-for-bit equivalent of ``Cracker::verifyMagic(UWORD32)``."""
        if self.spv * self.n_groups >= self.num_samples:
            return False
        rng_buf: list[int] = []
        state = seed & U32_MASK
        ev = 0
        sv_idx = 0
        for i in range(self.n_groups):
            for _ in range(self.spv):
                state = (state * LCG_A + LCG_C) & U32_MASK
                val_idx = sv_idx + int((state / U32) * (self.num_samples - sv_idx))
                if val_idx in rng_buf:
                    return True  # C++ treats an RNG collision as a possible hit
                rng_buf.append(val_idx)
                ev = (ev + int(self.values[val_idx])) % self.modulus
                sv_idx += 1
            for k in range(self.bpv):
                bits_seen = i * self.bpv + k
                if bits_seen < 25 and ((ev >> k) & 1) != ((MAGIC >> bits_seen) & 1):
                    return False
            ev = 0
        return True

    # --------------------------------------------------- full-batch (wordlists)
    def verify_batch(self, seeds: np.ndarray) -> np.ndarray:
        """Vectorised equivalent of :meth:`verify`.

        A seed is a candidate iff either all magic bits match, or the *first*
        RNG collision is encountered before the *first* mismatching magic
        group.  Simply OR-ing ``ok`` with ``any collision`` (an earlier version
        of this code) is wrong: ``Cracker::verifyMagic`` returns ``false`` as
        soon as a magic bit mismatches, so a later collision can never rescue
        that seed.
        """
        seeds = np.asarray(seeds, dtype=np.uint64).reshape(-1) & U32_MASK
        n = seeds.size
        if n == 0:
            return np.zeros(0, dtype=bool)

        state = seeds.copy()
        idx = np.empty((self.n_steps, n), dtype=np.int32)
        for step in range(self.n_steps):
            state = (state * LCG_A + LCG_C) & U32_MASK
            scaled = (state.astype(np.float64) / float(U32)) * float(self.num_samples - step)
            idx[step] = step + scaled.astype(np.int64)

        bad = np.empty((self.n_groups, n), dtype=bool)
        bitmask = (1 << self.bpv) - 1
        for g in range(self.n_groups):
            group = idx[g * self.spv:(g + 1) * self.spv]
            ev = self.values[group].sum(axis=0) % self.modulus
            bad[g] = (ev & bitmask) != self.expected[g]

        any_bad = bad.any(axis=0)
        first_bad = np.where(any_bad, bad.argmax(axis=0), self.n_groups)

        # First step at which a previously seen sample index is drawn again.
        order = np.argsort(idx, axis=0, kind="stable")
        sorted_idx = np.take_along_axis(idx, order, axis=0)
        duplicate = sorted_idx[1:] == sorted_idx[:-1]
        detection_step = np.maximum(order[1:], order[:-1])
        first_collision = np.where(duplicate, detection_step, self.n_steps).min(axis=0)
        collision_group = first_collision // self.spv

        return (~any_bad) | (collision_group <= first_bad)

    # ------------------------------------------------ progressive (seed search)
    def verify_filtered(self, seeds: np.ndarray) -> np.ndarray:
        """Return the subset of ``seeds`` that passes :meth:`verify_batch`."""
        seeds = np.asarray(seeds, dtype=np.uint64).reshape(-1) & U32_MASK
        if seeds.size == 0:
            return np.zeros(0, dtype=np.uint32)
        return seeds[self.verify_batch(seeds)].astype(np.uint32)
