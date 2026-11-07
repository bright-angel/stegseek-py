"""Port of ``src/Extractor.cc``."""

from __future__ import annotations

from .bitstring import BitString
from .cover.base import CoverFile, div_roundup
from .embdata import EmbData
from .errors import CorruptDataError
from .selector import Selector


def extract(cover: CoverFile, passphrase: bytes | None = None,
            seed: int | None = None) -> EmbData:
    """Extract embedded data using a passphrase or (for unencrypted data) a seed."""
    if passphrase is None and seed is None:
        raise ValueError("either passphrase or seed must be given")
    emb = EmbData("extract", passphrase if passphrase is not None else b"")
    sel = Selector(cover.num_samples, passphrase if passphrase is not None else seed)
    bpv = cover.bits_per_emb_value
    spv = cover.samples_per_vertex
    modulus = cover.modulus
    values = cover.evalues
    num_samples = cover.num_samples
    sv_idx = 0

    while not emb.finished():
        requested = emb.get_num_bits_requested()
        embvalues_requested = div_roundup(requested, bpv)
        if sv_idx + spv * embvalues_requested >= num_samples:
            raise CorruptDataError(
                'the stego file "%s" is too short to contain the embedded data.' % cover.name)
        bits = BitString(modulus)
        for _ in range(embvalues_requested):
            ev = 0
            for _ in range(spv):
                ev = (ev + int(values[sel[sv_idx]])) % modulus
                sv_idx += 1
            bits.append_nary(ev)
        emb.add_bits(bits)
    return emb
