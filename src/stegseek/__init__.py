"""stegseek-py: a Python reimplementation of StegSeek 0.6 / steghide 0.5.1.

The package exposes the same functionality as the original C++ program:

* wordlist cracking (``--crack``, the default)
* seed cracking / passwordless extraction (``--seed``)
* steghide-compatible embedding and extraction (``--embed`` / ``--extract``)
* information commands (``--info``, ``--encinfo``, ``--version``, ``--license``, ``--help``)
"""

__version__ = "0.6.0"
__steghide_version__ = "0.5.1"

from .cover import read_cover_file  # noqa: F401  (public convenience API)
from .embdata import EmbData  # noqa: F401
from .extractor import extract  # noqa: F401
from .selector import Selector, passphrase_to_seed  # noqa: F401

__all__ = [
    "__version__",
    "__steghide_version__",
    "read_cover_file",
    "EmbData",
    "extract",
    "Selector",
    "passphrase_to_seed",
]
