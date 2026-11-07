"""Command-line interface tests (StegSeek 0.6 / steghide 0.5.1 compatible)."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from stegseek import cli
from stegseek.const import ENCRYPTION_ALGORITHMS

PASSWORD = "CliTestPW"
PAYLOAD = b"This is a test file\n"


@pytest.fixture(autouse=True)
def reset_output_config():
    from stegseek.messages import configure
    configure(verbosity="normal", accessible=False, color=False, stream=None)
    yield
    configure(verbosity="normal", accessible=False, color=False, stream=None)


def test_version(capsys):
    assert cli.main(["--version"]) == 0
    err = capsys.readouterr().err
    assert "StegSeek 0.6 - https://github.com/RickdeJager/StegSeek" in err


def test_version_verbose(capsys):
    assert cli.main(["--version", "-v"]) == 0
    assert "based on steghide version 0.5.1" in capsys.readouterr().err


def test_help_and_verbose_help(capsys):
    assert cli.main(["--help"]) == 0
    out = capsys.readouterr().out
    assert "=== StegSeek Help ===" in out
    assert 'Use "stegseek --help -v"' in out
    assert cli.main(["--help", "-v"]) == 0
    out = capsys.readouterr().out
    assert "=== Steghide Help ===" in out
    assert "To embed emb.txt in cvr.jpg" in out


def test_encinfo_lists_all_algorithms(capsys):
    assert cli.main(["--encinfo"]) == 0
    out = capsys.readouterr().out
    assert "encryption algorithms:" in out
    for algo in ENCRYPTION_ALGORITHMS:
        if algo != "none":
            assert algo + ":" in out


def test_license(capsys):
    assert cli.main(["--license"]) == 0
    assert "GNU General Public License" in capsys.readouterr().out


def test_unknown_argument_returns_error(capsys):
    assert cli.main(["--not-a-real-flag"]) == 1
    err = capsys.readouterr().err
    assert "error:" in err
    assert 'type "stegseek --help" for help.' in err


def test_info_with_passphrase(capsys, tmp_path, payload, cover_files):
    jpg = next(p for p in cover_files if p.name == "std.jpg")
    stego = tmp_path / "info.jpg"
    assert cli.main(["--embed", "-cf", str(jpg), "-ef", str(payload),
                     "-sf", str(stego), "-p", PASSWORD, "-f", "-q"]) == 0
    capsys.readouterr()
    assert cli.main(["--info", "-p", PASSWORD, str(stego)]) == 0
    out = capsys.readouterr().out
    assert '"info.jpg":' in out
    assert "format: jpeg" in out
    assert "capacity:" in out
    assert "embedded file" in out
    assert "encrypted: rijndael-128, cbc" in out


def test_embed_and_extract_via_cli(tmp_path, payload, cover_files, capsys):
    jpg = next(p for p in cover_files if p.name == "std.jpg")
    stego = tmp_path / "stego.jpg"
    out = tmp_path / "extracted.bin"
    assert cli.main(["--embed", "-cf", str(jpg), "-ef", str(payload),
                     "-sf", str(stego), "-p", PASSWORD, "-f"]) == 0
    assert stego.exists()
    assert cli.main(["--extract", "-sf", str(stego), "-p", PASSWORD,
                     "-xf", str(out), "-f", "-q"]) == 0
    assert out.read_bytes() == PAYLOAD


def test_extract_to_stdout(tmp_path, payload, cover_files):
    jpg = next(p for p in cover_files if p.name == "std.jpg")
    stego = tmp_path / "stdout.jpg"
    assert cli.main(["--embed", "-cf", str(jpg), "-ef", str(payload),
                     "-sf", str(stego), "-p", PASSWORD, "-f", "-q"]) == 0
    env = dict(os.environ, PYTHONPATH=str(Path(cli.__file__).parents[1]))
    r = subprocess.run([sys.executable, "-m", "stegseek.cli", "--extract",
                        "-sf", str(stego), "-p", PASSWORD, "-xf", "-", "-q"],
                       capture_output=True, env=env)
    assert r.returncode == 0
    assert r.stdout == PAYLOAD


def test_crack_via_cli(tmp_path, payload, cover_files, capsys):
    jpg = next(p for p in cover_files if p.name == "std.jpg")
    stego = tmp_path / "crack.jpg"
    assert cli.main(["--embed", "-cf", str(jpg), "-ef", str(payload),
                     "-sf", str(stego), "-p", PASSWORD, "-f", "-q"]) == 0
    wl = tmp_path / "words.txt"
    wl.write_text("\n".join([f"wrong_{i}" for i in range(50)] + [PASSWORD]) + "\n")
    out = tmp_path / "cracked.bin"
    assert cli.main(["--crack", str(stego), str(wl), "-xf", str(out), "-f"]) == 0
    assert out.read_bytes() == PAYLOAD
    assert f'Found passphrase: "{PASSWORD}"' in capsys.readouterr().err


@pytest.mark.parametrize("threads", [1, 4])
def test_seed_via_cli(tmp_path, payload, cover_files, threads):
    jpg = next(p for p in cover_files if p.name == "std.jpg")
    stego = tmp_path / "seed.jpg"
    # "moana5" derives seed 0x00000291, so the bounded CLI search terminates
    # after the first 64K seeds.  -t exercises both the sequential and the
    # ThreadPoolExecutor scan paths.
    assert cli.main(["--embed", "-cf", str(jpg), "-ef", str(payload),
                     "-sf", str(stego), "-p", "moana5", "-f", "-q", "-e", "none"]) == 0
    out = tmp_path / "seed.out"
    assert cli.main(["--seed", "-t", str(threads), str(stego),
                     "-xf", str(out), "-f", "-q"]) == 0
    assert out.read_bytes() == PAYLOAD


def test_quiet_suppresses_information_messages(tmp_path, payload, cover_files, capsys):
    jpg = next(p for p in cover_files if p.name == "std.jpg")
    stego = tmp_path / "quiet.jpg"
    assert cli.main(["--embed", "-cf", str(jpg), "-ef", str(payload),
                     "-sf", str(stego), "-p", PASSWORD, "-f", "-q"]) == 0
    assert capsys.readouterr().err == ""
