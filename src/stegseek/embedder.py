"""Port of ``src/Embedder.cc`` (plus the ``Graph``/``Matching`` data path).

steghide uses a graph matching heuristic to decide *which* sample of each
vertex to modify so that the visual distortion is minimal.  The extractor only
observes ``sum(evalues[selector[i]]) % modulus``, so changing one sample per
vertex is fully compatible: any steghide build can read files produced here.
"""

from __future__ import annotations

import os

from .args import Arguments
from .bitstring import BitString
from .cover import read_cover_file
from .cover.base import CoverFile, div_roundup
from .embdata import EmbData
from .errors import BinaryInputError, SteghideError
from .selector import Selector


def build_payload(data: bytes, args: Arguments) -> BitString:
    """Construct the steghide ``EmbData`` bit string for ``--embed``."""
    emb = EmbData("embed", args.passphrase.encode("utf-8", "surrogateescape"))
    if args.embed_emb_fn and args.emb_fn:
        emb.set_filename(os.path.basename(args.emb_fn).encode("utf-8", "surrogateescape"))
    emb.enc_algo = args.enc_algo
    emb.enc_mode = args.enc_mode
    emb.compression = args.compression
    emb.checksum = args.checksum
    emb.set_data(data)
    return emb.get_bit_string()


def embed_into(cover: CoverFile, payload: BitString, args: Arguments) -> None:
    """Modify ``cover`` in place so that ``payload`` is embedded."""
    arity_nbits = cover.bits_per_emb_value
    if arity_nbits == 0:
        raise SteghideError("the cover file has no embeddable values.")
    # ``BitString::getNAryLength`` rounds up; pad the tail with zero bits.
    payload.pad(arity_nbits, 0)
    n_values = div_roundup(payload.length, arity_nbits)
    spv = cover.samples_per_vertex
    modulus = cover.modulus
    if n_values * spv >= cover.num_samples:
        raise SteghideError("the cover file is too short to embed the data.")

    sel = Selector(cover.num_samples, args.passphrase.encode("utf-8", "surrogateescape"))
    indices = sel.indices(n_values * spv)
    for i in range(n_values):
        poss = indices[i * spv:(i + 1) * spv]
        # Read the current values *now*: a sample may have been touched by an
        # earlier vertex (the selector is not guaranteed to be disjoint).
        current = [int(cover.evalues[p]) for p in poss]
        modulosum = sum(current) % modulus
        target = payload.get_value(i * arity_nbits, arity_nbits) % modulus
        if modulosum == target:
            continue
        # Change one sample of this vertex; prefer the sample whose new eValue
        # is closest to its current one to keep distortion low.
        best = None
        for j, pos in enumerate(poss):
            others = (sum(current) - current[j]) % modulus
            needed = (target - others) % modulus
            distance = min((needed - current[j]) % modulus,
                           (current[j] - needed) % modulus)
            if best is None or distance < best[0]:
                best = (distance, pos, needed)
        _, pos, needed = best
        cover.set_embedded_value(pos, needed)
        if int(cover.evalues[pos]) != needed:
            raise SteghideError("could not embed data in this cover file.")


def embed(args: Arguments) -> bytes:
    """Full ``--embed`` pipeline; returns the stego file bytes."""
    if args.emb_fn == "" or args.emb_fn is None:
        import sys
        data = sys.stdin.buffer.read()
    else:
        try:
            with open(args.emb_fn, "rb") as fh:
                data = fh.read()
        except OSError as exc:
            raise BinaryInputError('could not open the file "%s".' % args.emb_fn) from exc

    payload = build_payload(data, args)
    if args.cvr_fn == "" or args.cvr_fn is None:
        import sys
        raw = sys.stdin.buffer.read()
        cover = read_cover_file("", raw)
    else:
        cover = read_cover_file(args.cvr_fn)
    embed_into(cover, payload, args)
    return cover.to_bytes()


def check_capacity(cover: CoverFile, payload: BitString) -> int:
    """Return the number of vertices needed (used by callers/tests)."""
    return div_roundup(payload.length, cover.bits_per_emb_value)
