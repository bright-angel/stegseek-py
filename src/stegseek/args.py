"""Command line parsing, ported from ``src/Arguments.cc``.

The C++ ``Arg<>`` template distinguishes "explicitly set by the user" from
"filled in by setDefaults()"; that distinction is observable (stdin/stdout
selection, ``--info`` passphrase prompting, embed output defaults), so this
module keeps an explicit ``_explicit`` set.
"""

from __future__ import annotations

import getpass
import os
import sys
from dataclasses import dataclass, field

from .const import (
    ENCRYPTION_ALGORITHMS,
    ENCRYPTION_MODES,
    algo_index,
    mode_index,
)
from .errors import ArgError, SteghideError

COMMANDS = {
    "--crack": "crack",
    "--embed": "embed",
    "--extract": "extract",
    "--seed": "seed",
    "--info": "info",
    "--encinfo": "encinfo",
    "--version": "version",
    "--license": "license",
    "--help": "help",
}

# Algorithms whose libmcrypt module reports _is_block_algorithm() == 0.
STREAM_ALGORITHMS = frozenset({"enigma", "arcfour", "panama", "wake"})
# Modes whose libmcrypt module reports _is_block_algorithm_mode() == 0.
STREAM_MODES = frozenset({"stream"})

DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"


@dataclass
class Arguments:
    command: str = "crack"
    emb_fn: str | None = None
    cvr_fn: str | None = None
    stg_fn: str | None = None
    ext_fn: str | None = None
    wordlist_fn: str = DEFAULT_WORDLIST
    passphrase: str = ""
    enc_algo: int = algo_index("rijndael-128")
    enc_mode: int = mode_index("cbc")
    checksum: bool = True
    compression: int = 9
    embed_emb_fn: bool = True
    force: bool = False
    skip_default: bool = False
    accessible: bool = False
    color: bool = False
    continue_after: bool = False
    threads: int = 0
    verbosity: str = "normal"
    radius: int = 0
    goal: float = 100.0
    check: bool = False
    debug_command: str | None = None
    debug_level: int = 0
    gml_rec_depth: int = 0
    gml_start_vertex: int = 0
    _explicit: set[str] = field(default_factory=set)

    # -------------------------------------------------------------- Arg<> API
    def is_set(self, name: str) -> bool:
        return name in self._explicit

    def _set(self, name: str, value) -> None:
        if self.is_set(name):
            raise ArgError('the "%s" argument can be used only once.' % name)
        setattr(self, name, value)
        self._explicit.add(name)

    # --------------------------------------------------------------- defaults
    def set_defaults(self) -> None:
        self.color = bool(sys.stderr.isatty())
        if not self.is_set("threads"):
            self.threads = os.cpu_count() or 1

    # ------------------------------------------------------------- validation
    @staticmethod
    def require_command(command: str, allowed: tuple[str, ...], flag: str) -> None:
        if command not in allowed:
            raise ArgError('the argument "%s" is not compatible with the current command' % flag)

    @staticmethod
    def algo_supports_mode(algo: str, mode: str) -> bool:
        """``MCryptPP::AlgoSupportsMode``: block algo <-> block algorithm mode."""
        return (algo not in STREAM_ALGORITHMS) == (mode not in STREAM_MODES)


def _to_path(value: str) -> str:
    return "" if value == "-" else value


def parse_arguments(argv: list[str]) -> Arguments:
    """Parse ``argv`` (without program name) into an :class:`Arguments`."""
    args = Arguments()
    if not argv:
        args.command = "help"
        return args

    # 1. command (only a leading double-dash token is recognised)
    i = 0
    if argv[0] in COMMANDS:
        args.command = COMMANDS[argv[0]]
        i = 1
    else:
        args.command = "crack"
    args.set_defaults()

    command = args.command
    leftovers: list[str] = []

    # 2. keyword arguments
    while i < len(argv):
        token = argv[i]
        if not token.startswith("-") or token == "-":
            leftovers.append(_to_path(token))
            i += 1
            continue

        if token in ("-ef", "--embedfile"):
            args.require_command(command, ("embed",), token)
            args._set("emb_fn", _need_value(argv, i, token))
            i += 2
        elif token in ("-xf", "--extractfile"):
            args.require_command(command, ("extract", "crack", "seed"), token)
            args._set("ext_fn", _need_value(argv, i, token))
            i += 2
        elif token in ("-cf", "--coverfile"):
            args.require_command(command, ("embed",), token)
            args._set("cvr_fn", _need_value(argv, i, token))
            i += 2
        elif token in ("-sf", "--stegofile"):
            args.require_command(command, ("embed", "extract", "crack", "seed"), token)
            args._set("stg_fn", _need_value(argv, i, token))
            i += 2
        elif token in ("-wl", "--wordlist"):
            args.require_command(command, ("crack",), token)
            args._set("wordlist_fn", _need_value(argv, i, token))
            i += 2
        elif token in ("-p", "--passphrase"):
            args._set("passphrase", _need_value(argv, i, token))
            i += 2
        elif token in ("-K", "--nochecksum"):
            args._set("checksum", False)
            i += 1
        elif token in ("-N", "--dontembedname"):
            args.require_command(command, ("embed",), token)
            args._set("embed_emb_fn", False)
            i += 1
        elif token in ("-f", "--force"):
            args.require_command(command, ("embed", "extract", "crack", "seed"), token)
            args._set("force", True)
            i += 1
        elif token in ("-s", "--skipdefault"):
            args.require_command(command, ("crack",), token)
            args._set("skip_default", True)
            i += 1
        elif token in ("-a", "--accessible"):
            args._set("accessible", True)
            i += 1
        elif token in ("-n", "--nocolor"):
            args._set("color", False)
            i += 1
        elif token in ("-c", "--continue"):
            args.require_command(command, ("seed", "crack"), token)
            args._set("continue_after", True)
            i += 1
        elif token in ("-t", "--threads"):
            args.require_command(command, ("crack", "seed"), token)
            if args.is_set("threads"):
                raise ArgError('the "%s" argument can be used only once.' % token)
            value = _need_value(argv, i, token)
            try:
                n = int(value.split()[0])
            except (ValueError, IndexError):
                raise ArgError("The number of threads must be an integer") from None
            if n <= 0:
                raise ArgError("The number of threads must be greater than 0.")
            args._set("threads", n)
            i += 2
        elif token in ("-z", "--compress", "-Z", "--dontcompress"):
            args.require_command(command, ("embed",), token)
            if args.is_set("compression"):
                raise ArgError("the compression argument can be used only once.")
            if token in ("-Z", "--dontcompress"):
                args._set("compression", 0)
                i += 1
            else:
                value = _need_value(argv, i, token)
                try:
                    level = int(value.split()[0])
                except (ValueError, IndexError):
                    level = 0
                if not 1 <= level <= 9:
                    raise ArgError('"%s" is not a valid compression level.' % value)
                args._set("compression", level)
                i += 2
        elif token in ("-e", "--encryption"):
            args.require_command(command, ("embed",), token)
            if args.is_set("enc_algo") or args.is_set("enc_mode"):
                raise ArgError("the encryption argument can be used only once.")
            i = _parse_encryption(args, argv, i)
        elif token in ("-r", "--radius"):
            args.require_command(command, ("embed",), token)
            value = _need_value(argv, i, token)
            args._set("radius", _scan_uint(value))
            i += 2
        elif token in ("-g", "--goal"):
            args.require_command(command, ("embed",), token)
            value = _need_value(argv, i, token)
            try:
                goal = float(value.split()[0])
            except (ValueError, IndexError):
                goal = -1.0
            if not 0 <= goal <= 100:
                raise ArgError('the "%s" argument must be followed by a number between 0 and 100.' % token)
            args._set("goal", goal)
            i += 2
        elif token in ("-q", "--quiet", "-v", "--verbose"):
            allowed = ("embed", "extract", "crack", "seed")
            if token in ("-v", "--verbose"):
                allowed += ("help", "version")
            args.require_command(command, allowed, token)
            if args.is_set("verbosity"):
                raise ArgError('the "%s" argument cannot be used here because the verbosity has already been set.' % token)
            args._set("verbosity", "quiet" if token in ("-q", "--quiet") else "verbose")
            i += 1
        elif token in ("--printgraph", "--printgmlgraph", "--printgmlvertex", "--printstats",
                       "--debuglevel", "--check"):
            if args.debug_command is not None and token != "--debuglevel" and token != "--check":
                raise SteghideError("you cannot use more than one debug command at a time.")
            if token == "--printstats":
                args._set("verbosity", "stats")
                args.debug_command = "printstats"
                i += 1
            elif token == "--check":
                args._set("check", True)
                i += 1
            elif token == "--debuglevel":
                args._set("debug_level", _scan_uint(_need_value(argv, i, token)))
                i += 2
            elif token == "--printgmlvertex":
                args.debug_command = "printgmlvertex"
                args.gml_rec_depth = _scan_uint(_need_value(argv, i, token))
                args.gml_start_vertex = _scan_uint(_need_value(argv, i + 1, token))
                i += 3
            else:
                args.debug_command = token[2:]
                i += 1
        else:
            raise ArgError('unknown argument "%s".' % token)

    # 3. positional arguments
    positional: dict[str, tuple[str, ...]] = {
        "crack": ("stg_fn", "wordlist_fn", "ext_fn"),
        "seed": ("stg_fn", "ext_fn"),
        "embed": ("emb_fn", "cvr_fn", "stg_fn"),
        "extract": ("stg_fn", "ext_fn"),
        "info": ("cvr_fn",),
    }
    for name, value in zip(positional.get(command, ()), leftovers):
        if not args.is_set(name):
            setattr(args, name, value)
            args._explicit.add(name)

    # 4. command-specific post-processing
    if command == "embed":
        cvr = args.cvr_fn or ""
        emb = args.emb_fn or ""
        if cvr == "" and emb == "":
            raise ArgError("standard input cannot be used for cover data AND data to be embedded.")
        if not args.is_set("stg_fn") and args.is_set("cvr_fn"):
            args.stg_fn = args.cvr_fn
            args.force = True

    if command in ("embed", "extract") and not args.is_set("passphrase"):
        if command == "embed":
            if (args.cvr_fn or "") == "" or (args.emb_fn or "") == "":
                raise ArgError("if standard input is used, the passphrase must be specified on the command line.")
            args.passphrase = _prompt_passphrase(True)
        else:
            if (args.stg_fn or "") == "":
                raise ArgError("if standard input is used, the passphrase must be specified on the command line.")
            args.passphrase = _prompt_passphrase(False)

    return args


def _need_value(argv: list[str], i: int, flag: str) -> str:
    if i + 1 >= len(argv):
        raise ArgError('the argument "%s" requires a value' % flag)
    return _to_path(argv[i + 1])


def _scan_uint(value: str) -> int:
    try:
        return int(value.split()[0])
    except (ValueError, IndexError):
        return 0


def _parse_encryption(args: Arguments, argv: list[str], i: int) -> int:
    """Port of ``Arguments::parse_Encryption``; returns the new argv index."""
    flag = argv[i]
    if i + 1 >= len(argv) or argv[i + 1].startswith("-"):
        raise ArgError('the "%s" argument must be followed by encryption parameters.' % flag)
    s1 = argv[i + 1]
    s2 = ""
    consumed = 2
    if i + 2 < len(argv) and not argv[i + 2].startswith("-"):
        s2 = argv[i + 2]
        consumed = 3

    if s1 == "none" and s2 == "":
        args._set("enc_algo", algo_index("none"))
        return i + consumed

    def classify(s: str) -> tuple[bool, bool]:
        if not s:
            return False, False
        is_algo = s in ENCRYPTION_ALGORITHMS
        is_mode = s in ENCRYPTION_MODES
        if not (is_algo or is_mode):
            raise SteghideError('"%s" is neither an algorithm nor a mode supported by libmcrypt.' % s)
        return is_algo, is_mode

    a1, m1 = classify(s1)
    a2, m2 = classify(s2)
    if a1 and a2:
        raise SteghideError('"%s" and "%s" are both libmcrypt algorithms. please specify only one.' % (s1, s2))
    if m1 and m2:
        raise SteghideError('"%s" and "%s" are both libmcrypt modes. please specify only one.' % (s1, s2))
    if a1:
        args.enc_algo = algo_index(s1)
        args._explicit.add("enc_algo")
    if m1:
        args.enc_mode = mode_index(s1)
        args._explicit.add("enc_mode")
    if a2:
        args.enc_algo = algo_index(s2)
        args._explicit.add("enc_algo")
    if m2:
        args.enc_mode = mode_index(s2)
        args._explicit.add("enc_mode")

    from .const import ENCRYPTION_ALGORITHMS as A
    from .const import ENCRYPTION_MODES as M
    if not Arguments.algo_supports_mode(A[args.enc_algo], M[args.enc_mode]):
        raise SteghideError('the encryption algorithm "%s" can not be used with the mode "%s".'
                            % (A[args.enc_algo], M[args.enc_mode]))
    return i + consumed


def _prompt_passphrase(doublecheck: bool) -> str:
    first = getpass.getpass("Enter passphrase: ")
    if doublecheck:
        second = getpass.getpass("Re-Enter passphrase: ")
        if first != second:
            raise SteghideError("the passphrases do not match.")
    return first
