"""Command line entry point: port of ``src/Session.cc`` and ``src/main.cc``."""

from __future__ import annotations

import os
import sys

from .args import Arguments, parse_arguments
from .const import ENCRYPTION_ALGORITHMS, ENCRYPTION_MODES, STEGHIDE_VERSION, STEGSEEK_VERSION
from .cover import read_cover_file
from .cover.base import format_hr_size
from .crackers.password import PasswordCracker
from .crackers.seed import SeedCracker
from .embedder import embed
from .errors import ArgError, BinaryOutputError, SteghideError
from .extractor import extract
from .messages import arg_error, configure, critical_warning, error, message, verbose

VERSION_LINE = "StegSeek %s - https://github.com/RickdeJager/StegSeek" % STEGSEEK_VERSION

HELP_STEGSEEK = """
=== StegSeek Help ===
To crack a stegofile:
stegseek [stegofile.jpg] [wordlist.txt]

Commands:
 --crack                 Crack a stego file using a wordlist. This is the default mode.
 --seed                  Crack a stego file by attempting all embedding patterns.
                         This mode can be used to detect a file encoded by steghide.
                         In case the file was encoded without encryption, this mode will
                         even recover the embedded file.
Positional arguments:
 --crack [stegofile.jpg] [wordlist.txt] [output.txt]
 --seed  [stegofile.jpg] [output.txt]

Keyword arguments:
 -sf, --stegofile        select stego file
 -wl, --wordlist         select the wordlist file
 -xf, --extractfile      select file name for extracted data
 -t, --threads           set the number of threads. Defaults to the number of cores.
 -f, --force             overwrite existing files
 -v, --verbose           display detailed information
 -q, --quiet             hide performance metrics (can improve performance)
 -s, --skipdefault       don't add guesses to the wordlist (empty password, filename, ...)
 -n, --nocolor           disable colors in output
 -c, --continue          continue cracking after a result has been found.
                         (A stego file might contain multiple embedded files)
 -a, --accessible        simplify the output to be more screen reader friendly

"""

HELP_STEGHIDE = """
the first argument must be one of the following:
 --embed                 embed data
 --extract               extract data
 --info                  display information about a cover- or stego-file
 --encinfo               display a list of supported encryption algorithms
 --version               display version information
 --license               display StegSeek's license
 --help                  display this usage information

embedding options:
 -ef, --embedfile        select file to be embedded
   -ef <filename>        embed the file <filename>
 -cf, --coverfile        select cover-file
   -cf <filename>        embed into the file <filename>
 -p, --passphrase        specify passphrase
   -p <passphrase>       use <passphrase> to embed data
 -sf, --stegofile        select stego file
   -sf <filename>        write result to <filename> instead of cover-file
 -e, --encryption        select encryption parameters
   -e <a>[<m>]|<m>[<a>]  specify an encryption algorithm and/or mode
   -e none               do not encrypt data before embedding
 -z, --compress          compress data before embedding (default)
   -z <l>                 using level <l> (1 best speed...9 best compression)
 -Z, --dontcompress      do not compress data before embedding
 -K, --nochecksum        do not embed crc32 checksum of embedded data
 -N, --dontembedname     do not embed the name of the original file
 -f, --force             overwrite existing files
 -q, --quiet             suppress information messages
 -v, --verbose           display detailed information

extracting options:
 -sf, --stegofile        select stego file
   -sf <filename>        extract data from <filename>
 -p, --passphrase        specify passphrase
   -p <passphrase>       use <passphrase> to extract data
 -xf, --extractfile      select file name for extracted data
   -xf <filename>        write the extracted data to <filename>
 -f, --force             overwrite existing files
 -q, --quiet             suppress information messages
 -v, --verbose           display detailed information

options for the info command:
 -p, --passphrase        specify passphrase
   -p <passphrase>       use <passphrase> to get info about embedded data

To embed emb.txt in cvr.jpg: stegseek --embed -cf cvr.jpg -ef emb.txt
To extract embedded data from stg.jpg: stegseek --extract -sf stg.jpg
"""

LICENSE_TEXT = """Copyright (C) 2021 Rick de Jager ( https://github.com/rickdejager )

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
"""


def print_version(args: Arguments) -> None:
    sys.stderr.write(VERSION_LINE + "\n")
    if args.verbosity == "verbose":
        sys.stderr.write("based on steghide version %s\n" % STEGHIDE_VERSION)
    sys.stderr.write("\n")


def print_help(args: Arguments) -> None:
    print_version(args)
    sys.stdout.write(HELP_STEGSEEK)
    if args.verbosity == "verbose":
        sys.stdout.write("=== Steghide Help ===\n")
        sys.stdout.write(HELP_STEGHIDE)
    else:
        sys.stdout.write('Use "stegseek --help -v" to include steghide\'s help.\n')


def print_encinfo() -> None:
    sys.stdout.write("encryption algorithms:\n<algorithm>: <supported modes>...\n")
    block_modes = sorted(m for m in ENCRYPTION_MODES if m != "stream")
    for algo in ENCRYPTION_ALGORITHMS:
        if algo == "none":
            continue
        modes = ["stream"] if algo in ("enigma", "arcfour", "panama", "wake") else block_modes
        sys.stdout.write("%s:%s\n" % (algo, "".join(" " + m for m in modes)))


def _check_force(path: str, args: Arguments) -> None:
    if args.force or not os.path.exists(path):
        return
    try:
        answer = input('the file "%s" does already exist. overwrite ? (y/n) ' % path)
    except (EOFError, OSError):
        answer = "n"
    if not answer.strip().lower().startswith("y"):
        raise SteghideError('did not write to file "%s".' % path)


def do_info(args: Arguments) -> None:
    path = args.cvr_fn or ""
    cover = read_cover_file(path, None if path else sys.stdin.buffer.read())
    if path:
        sys.stdout.write('"%s":\n' % os.path.basename(path.replace("\\", "/")))
    else:
        sys.stdout.write("data from standard input:\n")
    for key, value in cover.properties():
        sys.stdout.write("  %s: %s\n" % (key, value))
    sys.stdout.write("  capacity: %s\n" % format_hr_size(cover.capacity()))

    print_emb = args.is_set("passphrase")
    if not print_emb:
        sys.stderr.write("Try to get information about embedded data ? (y/n) ")
        sys.stderr.flush()
        try:
            answer = sys.stdin.readline()
        except (EOFError, OSError):
            answer = ""
        print_emb = answer.strip().lower().startswith("y")
    if not print_emb:
        return

    try:
        emb = extract(cover, args.passphrase.encode("utf-8", "surrogateescape"))
    except SteghideError:
        sys.stdout.write("could not extract any data with that passphrase!\n")
        return
    filename = emb.filename.decode("utf-8", "surrogateescape") if isinstance(
        emb.filename, bytes) else emb.filename
    if filename:
        sys.stdout.write('  embedded file "%s":\n' % filename)
    else:
        sys.stdout.write("  embedded data:\n")
    sys.stdout.write("    size: %s\n" % format_hr_size(len(emb.data)))
    if emb.enc_algo == 0:
        enc = "no"
    else:
        enc = "%s, %s" % (ENCRYPTION_ALGORITHMS[emb.enc_algo], ENCRYPTION_MODES[emb.enc_mode])
    sys.stdout.write("    encrypted: %s\n" % enc)
    sys.stdout.write("    compressed: %s\n" % ("yes" if emb.compression > 0 else "no"))


def do_extract(args: Arguments) -> None:
    path = args.stg_fn or ""
    verbose('reading stego file "%s"...\n', path)
    cover = read_cover_file(path, None if path else sys.stdin.buffer.read())
    verbose("done\n")
    verbose("extracting data...\n")
    emb = extract(cover, args.passphrase.encode("utf-8", "surrogateescape"))
    verbose("done\n")
    if not emb.checksum_ok():
        critical_warning("crc32 checksum failed! extracted data is probably corrupted.\n")

    filename = emb.filename.decode("utf-8", "surrogateescape") if isinstance(
        emb.filename, bytes) else emb.filename
    if args.is_set("ext_fn"):
        out = args.ext_fn or ""
    else:
        out = filename
        if not out:
            raise SteghideError("please specify a file name for the extracted data "
                                "(there is no name embedded in the stego file).")
    if out == "":
        verbose("writing extracted data to standard output...\n")
        sys.stdout.buffer.write(emb.data)
        sys.stdout.buffer.flush()
    else:
        verbose('writing extracted data to "%s"...', out)
        _check_force(out, args)
        try:
            with open(out, "wb") as fh:
                fh.write(emb.data)
        except OSError as exc:
            raise BinaryOutputError('could not open the file "%s".' % out) from exc
        verbose(" done\n")
        if args.verbosity != "verbose":
            message('wrote extracted data to "%s".', out)


def do_embed(args: Arguments) -> None:
    data = embed(args)
    out = args.stg_fn or ""
    if out == "":
        message("writing stego file to standard output... ")
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return
    _check_force(out, args)
    try:
        with open(out, "wb") as fh:
            fh.write(data)
    except OSError as exc:
        raise BinaryOutputError('could not open the file "%s".' % out) from exc
    if args.verbosity == "normal":
        message('embedding "%s" in "%s"... done', args.emb_fn or "standard input",
                args.cvr_fn or "standard input")
        if out != args.cvr_fn:
            message('writing stego file "%s"... done', out)


def run(args: Arguments) -> None:
    command = args.command
    if command in ("crack", "seed"):
        if not args.accessible:
            print_version(args)
    if command == "crack":
        verbose("Running on %d threads.\n", args.threads)
        PasswordCracker(args).crack()
    elif command == "seed":
        verbose("Running on %d threads.\n", args.threads)
        SeedCracker(args).crack()
    elif command == "embed":
        do_embed(args)
    elif command == "extract":
        do_extract(args)
    elif command == "info":
        do_info(args)
    elif command == "encinfo":
        print_encinfo()
    elif command == "version":
        print_version(args)
    elif command == "license":
        sys.stdout.write(LICENSE_TEXT)
    elif command == "help":
        print_help(args)
    else:
        raise SteghideError("unknown command")


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    try:
        args = parse_arguments(list(argv))
        configure(verbosity=args.verbosity, accessible=args.accessible, color=args.color)
        run(args)
    except ArgError as exc:
        arg_error(str(exc))
        return 1
    except SteghideError as exc:
        error(str(exc))
        return 1
    except (OSError, ValueError, IndexError, KeyError) as exc:
        error(str(exc))
        return 1
    except KeyboardInterrupt:
        error("interrupted.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
