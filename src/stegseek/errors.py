"""Exception hierarchy mirroring ``src/error.h``."""

from __future__ import annotations


class SteghideError(Exception):
    """Base error; ``printMessage`` is emulated by ``messages.error``."""


class ArgError(SteghideError):
    """A command line error; also prints the --help hint."""


class CorruptDataError(SteghideError):
    """The embedded data could not be decoded (wrong password / no data)."""


class UnSupFileFormat(SteghideError):
    """Unsupported cover/stego file format."""


class NotImplementedInPython(SteghideError):
    """Feature intentionally not available in the Python port."""


class BinaryInputError(SteghideError):
    pass


class BinaryOutputError(SteghideError):
    pass
