#!/usr/bin/env python3
"""Reproducible cross-validation of stegseek-py against steghide 0.5.1.

The original C++ StegSeek cannot be built on this machine (no C++ toolchain,
WSL is blocked), so the reference oracle is the Windows build of
``steghide 0.5.1`` -- the exact upstream version StegSeek 0.6 is based on.
StegSeek's --crack / --seed behaviour is additionally checked against the
sample stego files and passwords from the upstream test suite.

Usage (from the project root)::

    python scripts/cross_validate.py
    python scripts/cross_validate.py --steghide /path/to/steghide.exe --quick

The script writes ``crossval/validation_report.json`` and prints a summary.
It is intentionally dependency-free apart from the project's own runtime
requirements and the external oracle executable.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from stegseek.args import parse_arguments  # noqa: E402
from stegseek.cover import read_cover_file  # noqa: E402
from stegseek.embedder import embed  # noqa: E402
from stegseek.extractor import extract  # noqa: E402
from stegseek.selector import passphrase_to_seed  # noqa: E402

ORACLE_DEFAULT = ROOT / "_reference/tools/steghide-win/steghide/steghide.exe"
STEGSEEK_DATA = ROOT / "_reference/stegseek/tests/stegseek/data"
STEGHIDE_DATA = ROOT / "_reference/stegseek/tests/steghide/data"
WORK = ROOT / "crossval/validation"

PAYLOAD = b"This is a test file\n"
PASSWORD = "P@ssw0rd"

BLOCK_ALGOS = [
    "twofish", "rijndael-128", "rijndael-192", "rijndael-256", "saferplus",
    "rc2", "xtea", "serpent", "cast-256", "loki97", "gost", "cast-128",
    "blowfish", "des", "tripledes",
]
STREAM_ALGOS = ["enigma", "arcfour", "wake"]
BLOCK_MODES = ["ecb", "cbc", "ofb", "cfb", "nofb", "ncfb", "ctr"]
COVER_FILES = sorted(
    p for p in STEGHIDE_DATA.glob("*") if p.suffix.lower() in {".jpg", ".jpeg", ".bmp", ".wav", ".au"}
)


def run_oracle(exe: Path, argv: list[str], stdin: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.run([str(exe), *argv], input=stdin, capture_output=True)


def capacity_from(text: str) -> float | None:
    for line in text.splitlines():
        if "capacity:" in line:
            word = line.split("capacity:", 1)[1].strip().split()[0]
            try:
                return float(word)
            except ValueError:
                return None
    return None


def check(results: list[dict], name: str, ok: bool, detail: str = "") -> None:
    results.append({"check": name, "ok": bool(ok), "detail": detail})
    flag = "OK  " if ok else "FAIL"
    print(f"  [{flag}] {name}" + (f" -- {detail}" if detail and not ok else ""))


def section(title: str) -> None:
    print(f"\n=== {title} ===")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--steghide", type=Path, default=ORACLE_DEFAULT)
    ap.add_argument("--quick", action="store_true",
                    help="skip the full 108-case encryption matrix")
    ap.add_argument("--work", type=Path, default=WORK)
    opts = ap.parse_args()

    exe = opts.steghide
    if not exe.exists():
        print(f"reference steghide executable not found: {exe}", file=sys.stderr)
        print("pass --steghide <path> to a steghide 0.5.1 binary", file=sys.stderr)
        return 2
    work: Path = opts.work
    work.mkdir(parents=True, exist_ok=True)
    payload = work / "payload.bin"
    payload.write_bytes(PAYLOAD)
    results: list[dict] = []

    section("Reference program")
    ver = run_oracle(exe, ["--version"])
    vtxt = (ver.stdout + ver.stderr).decode("latin1")
    check(results, "oracle is steghide 0.5.1", "0.5.1" in vtxt, vtxt.strip()[:100])

    section("Cover format capacity (Python vs oracle)")
    for cover in COVER_FILES:
        py_cap = read_cover_file(str(cover)).capacity()
        r = run_oracle(exe, ["info", str(cover)], stdin=b"n\n")
        out = (r.stdout + r.stderr).decode("latin1")
        o_cap = capacity_from(out)
        ok = o_cap is not None and int(float(py_cap)) == int(o_cap)
        check(results, f"capacity {cover.name}", ok,
              f"python={py_cap} oracle={o_cap}")

    section("Oracle embed -> Python extract (all cover formats)")
    for cover in COVER_FILES:
        stego = work / f"o_{cover.name}"
        r = run_oracle(exe, ["embed", "-cf", str(cover), "-ef", str(payload),
                             "-sf", str(stego), "-p", PASSWORD, "-f", "-q"])
        if not stego.exists():
            check(results, f"oracle embed {cover.name}", False,
                  (r.stdout + r.stderr).decode("latin1").strip()[:120])
            continue
        try:
            emb = extract(read_cover_file(str(stego)), PASSWORD.encode())
            check(results, f"extract {cover.name}",
                  emb.data == PAYLOAD and emb.checksum_ok())
        except Exception as exc:  # noqa: BLE001
            check(results, f"extract {cover.name}", False, f"{type(exc).__name__}: {exc}")

    section("Python embed -> oracle extract (all cover formats)")
    for cover in COVER_FILES:
        stego = work / f"py_{cover.name}"
        try:
            args = parse_arguments(["--embed", "-cf", str(cover), "-ef", str(payload),
                                   "-sf", str(stego), "-p", PASSWORD, "-f", "-q"])
            stego.write_bytes(embed(args))
        except Exception as exc:  # noqa: BLE001
            check(results, f"embed {cover.name}", False, f"{type(exc).__name__}: {exc}")
            continue
        out_file = work / f"oracle_{cover.name}.out"
        r = run_oracle(exe, ["extract", "-sf", str(stego), "-p", PASSWORD,
                             "-xf", str(out_file), "-f", "-q"])
        ok = r.returncode == 0 and out_file.exists() and out_file.read_bytes() == PAYLOAD
        check(results, f"oracle extract {cover.name}", ok,
              (r.stdout + r.stderr).decode("latin1").strip()[:120])

    section("Encryption algorithm / mode matrix")
    if opts.quick:
        cases = [("none", "cbc")] + [(a, "cbc") for a in BLOCK_ALGOS] + \
                [(a, "stream") for a in STREAM_ALGOS]
    else:
        cases = [("none", "cbc")] + [(a, m) for a in BLOCK_ALGOS for m in BLOCK_MODES] + \
                [(a, "stream") for a in STREAM_ALGOS]
    jpeg = STEGSEEK_DATA / "sun.jpg"
    matrix_ok = 0
    matrix_fail: list[str] = []
    for algo, mode in cases:
        tag = f"{algo}_{mode}"
        o_stego = work / f"enc_o_{tag}.jpg"
        p_stego = work / f"enc_p_{tag}.jpg"
        spec = ["-e", "none"] if algo == "none" else ["-e", algo, mode]

        r = run_oracle(exe, ["embed", "-cf", str(jpeg), "-ef", str(payload),
                             "-sf", str(o_stego), "-p", PASSWORD, "-f", "-q", *spec])
        if o_stego.exists():
            try:
                e = extract(read_cover_file(str(o_stego)), PASSWORD.encode())
                ok = e.data == PAYLOAD and e.checksum_ok()
            except Exception as exc:  # noqa: BLE001
                ok, detail = False, f"{type(exc).__name__}: {exc}"
            else:
                detail = ""
        else:
            ok, detail = False, (r.stdout + r.stderr).decode("latin1").strip()[:100]
        if not ok:
            matrix_fail.append(f"oracle->python {tag}: {detail}")

        try:
            a = parse_arguments(["--embed", "-cf", str(jpeg), "-ef", str(payload),
                                 "-sf", str(p_stego), "-p", PASSWORD, "-f", "-q", *spec])
            p_stego.write_bytes(embed(a))
        except Exception as exc:  # noqa: BLE001
            matrix_fail.append(f"python embed {tag}: {type(exc).__name__}: {exc}")
        else:
            out_file = work / f"enc_{tag}.out"
            rr = run_oracle(exe, ["extract", "-sf", str(p_stego), "-p", PASSWORD,
                                  "-xf", str(out_file), "-f", "-q"])
            if rr.returncode != 0 or not out_file.exists() or out_file.read_bytes() != PAYLOAD:
                matrix_fail.append(f"python->oracle {tag}: "
                                   + (rr.stdout + rr.stderr).decode("latin1").strip()[:100])
                continue
        matrix_ok += 1

    check(results, f"encryption matrix ({len(cases)} algorithm/mode pairs, both directions)",
          not matrix_fail, "; ".join(matrix_fail[:6]))

    section("StegSeek --crack reference cases")
    crack_cases = [
        ("sun.jpg", "stegseek", b"This is a very secret file\n"),
        ("rngcollision.jpg", "iluv1josh", None),
    ]
    for name, pw, expected in crack_cases:
        src = STEGSEEK_DATA / name
        if not src.exists():
            continue
        wl = work / f"wl_{name}.txt"
        wl.write_text("\n".join([f"Blah_{i}" for i in range(100)] + [pw] +
                                [f"Foo_{i}" for i in range(100)]) + "\n")
        out = work / f"crack_{name}.out"
        proc = subprocess.run(
            [sys.executable, "-m", "stegseek.cli", "--crack", str(src), str(wl),
             "-xf", str(out), "-f", "-q"],
            capture_output=True, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")))
        ok = proc.returncode == 0 and out.exists() and (expected is None or out.read_bytes() == expected)
        check(results, f"crack {name}", ok,
              (proc.stdout + proc.stderr).decode("latin1").strip()[:140])

    section("StegSeek --seed reference case")
    # "moana5" hashes to seed 0x00000291, so a bounded search finds it quickly.
    seed_cover = STEGSEEK_DATA / "sun.jpg"
    seed_stego = work / "seed.jpg"
    r = run_oracle(exe, ["embed", "-cf", str(seed_cover), "-ef", str(payload),
                         "-sf", str(seed_stego), "-p", "moana5", "-f", "-q", "-e", "none"])
    if seed_stego.exists():
        expected_seed = passphrase_to_seed(b"moana5")
        print(f"  (expected seed 0x{expected_seed:08x})")
        out = work / "seed.out"
        proc = subprocess.run(
            [sys.executable, "-m", "stegseek.cli", "--seed", str(seed_stego),
             "-xf", str(out), "-f", "-q"],
            capture_output=True, env=dict(os.environ, PYTHONPATH=str(ROOT / "src")))
        ok = proc.returncode == 0 and out.exists() and out.read_bytes() == PAYLOAD
        check(results, "seed crack (unencrypted, recovers payload)", ok,
              (proc.stdout + proc.stderr).decode("latin1").strip()[:160])
    else:
        check(results, "seed oracle embed", False,
              (r.stdout + r.stderr).decode("latin1").strip()[:120])

    passed = sum(1 for r in results if r["ok"])
    total = len(results)
    report = {
        "oracle": str(exe),
        "oracle_version": vtxt.strip(),
        "checks": results,
        "passed": passed,
        "total": total,
        "encryption_matrix_cases": len(cases),
        "encryption_matrix_both_directions_ok": len(cases) - len(matrix_fail),
    }
    (work.parent / "validation_report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n=== SUMMARY: {passed}/{total} checks passed ===")
    if matrix_fail:
        print(f"    encryption matrix: {len(cases) - len(matrix_fail)}/{len(cases)} OK")
        for line in matrix_fail[:20]:
            print("    " + line)
    return 0 if passed == total and not matrix_fail else 1


if __name__ == "__main__":
    raise SystemExit(main())
