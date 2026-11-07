"""Shared pytest fixtures for the stegseek-py test suite."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

STEGHIDE_DATA = ROOT / "_reference/stegseek/tests/steghide/data"
STEGSEEK_DATA = ROOT / "_reference/stegseek/tests/stegseek/data"
ORACLE = ROOT / "_reference/tools/steghide-win/steghide/steghide.exe"

PAYLOAD = b"This is a test file\n"


@pytest.fixture(scope="session")
def root() -> Path:
    return ROOT


@pytest.fixture(scope="session")
def cover_files() -> list[Path]:
    return sorted(p for p in STEGHIDE_DATA.glob("*")
                  if p.suffix.lower() in {".jpg", ".jpeg", ".bmp", ".wav", ".au"})


@pytest.fixture(scope="session")
def sun_jpg() -> Path:
    return STEGSEEK_DATA / "sun.jpg"


@pytest.fixture()
def payload(tmp_path: Path) -> Path:
    p = tmp_path / "payload.bin"
    p.write_bytes(PAYLOAD)
    return p


@pytest.fixture()
def oracle():
    """Skip a test when the reference steghide binary is unavailable."""
    if not ORACLE.exists():
        pytest.skip("reference steghide.exe not available")
    return ORACLE
