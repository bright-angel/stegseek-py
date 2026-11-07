"""Terminal output, mirroring ``src/msg.cc`` / ``src/SteghideError.cc``.

All human readable diagnostics go to **stderr** exactly like the C++ program.
Extracted payload bytes go to stdout (or to a file).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TextIO

RESET = "\x1b[0m"
RED = "\x1b[31m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"


@dataclass
class OutputConfig:
    verbosity: str = "normal"  # quiet | normal | verbose | stats
    accessible: bool = False
    color: bool = False
    stream: TextIO | None = None

    @property
    def stream_(self) -> TextIO:
        return self.stream if self.stream is not None else sys.stderr

    def at_least_normal(self) -> bool:
        return self.verbosity in ("normal", "verbose")

    def is_verbose(self) -> bool:
        return self.verbosity == "verbose"


OUT = OutputConfig()


def configure(verbosity: str = "normal", accessible: bool = False,
              color: bool | None = None, stream: TextIO | None = None) -> None:
    OUT.verbosity = verbosity
    OUT.accessible = accessible
    OUT.color = (sys.stderr.isatty() if color is None else color)
    OUT.stream = stream


def _c(text: str, code: str) -> str:
    return code + text + RESET if OUT.color else text


def _prefix(tag: str, code: str) -> str:
    return "" if OUT.accessible else "[" + _c(tag, code) + "] "


def _write(text: str) -> None:
    OUT.stream_.write(text)
    OUT.stream_.flush()


def message(fmt: str, *args: object) -> None:
    """``Message::printMessage`` -- no prefix, always newline."""
    if OUT.at_least_normal():
        _write(fmt % args + "\n")


def msg(fmt: str, *args: object) -> None:
    """``Message::print`` -- informational message with [i] prefix."""
    if OUT.at_least_normal():
        _write(_prefix("i", BLUE) + fmt % args)


def msg_raw(fmt: str, *args: object) -> None:
    if OUT.at_least_normal():
        _write(fmt % args)


def verbose(fmt: str, *args: object) -> None:
    if OUT.is_verbose():
        _write(_prefix("v", YELLOW) + fmt % args)


def verbose_raw(fmt: str, *args: object) -> None:
    if OUT.is_verbose():
        _write(fmt % args)


def warning(fmt: str, *args: object) -> None:
    if OUT.verbosity != "quiet":
        _write(_prefix("w", RED) + "warning: " + fmt % args)


def critical_warning(fmt: str, *args: object) -> None:
    _write(_prefix("w", RED) + "warning: " + fmt % args)


def error(text: str) -> None:
    _write(_prefix("!", RED) + "error: " + text + "\n")


def arg_error(text: str) -> None:
    error(text)
    _write('stegseek: type "stegseek --help" for help.\n')


def corrupt_data_hint() -> None:
    _write("Other possible reasons for this error are that the passphrase is wrong\n"
           "or that there is no embedded data.\n")
