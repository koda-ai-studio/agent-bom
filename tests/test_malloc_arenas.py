"""The API process caps glibc malloc arenas so freed heap is reused instead of retained per thread.

Measured on glibc 2.39, Python 3.11, small-self-hosted workflow profile
(2026-11-14): peak RSS 1,823 / 1,943 MiB (cold / warm) with glibc's default
arena count, 1,396 / 1,518 MiB with two arenas, findings identical.
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

from agent_bom.api import malloc_arenas

ROOT = Path(__file__).resolve().parents[1]


class _FakeLibc:
    def __init__(self, result: int = 1) -> None:
        self.calls: list[tuple[int, int]] = []
        self.result = result

    def mallopt(self, param: int, value: int) -> int:
        self.calls.append((param, value))
        return self.result


def test_caps_arenas_on_glibc_with_mallopt(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = _FakeLibc()
    monkeypatch.delenv("MALLOC_ARENA_MAX", raising=False)
    monkeypatch.setattr(malloc_arenas, "_glibc", lambda: libc)

    assert malloc_arenas.limit_malloc_arenas() is True
    assert libc.calls == [(malloc_arenas.M_ARENA_MAX, malloc_arenas.API_MALLOC_ARENAS)]
    assert malloc_arenas.API_MALLOC_ARENAS == 2


def test_an_operator_malloc_arena_max_is_left_to_glibc(monkeypatch: pytest.MonkeyPatch) -> None:
    libc = _FakeLibc()
    monkeypatch.setenv("MALLOC_ARENA_MAX", "8")
    monkeypatch.setattr(malloc_arenas, "_glibc", lambda: libc)

    assert malloc_arenas.limit_malloc_arenas() is False
    assert libc.calls == []


def test_non_glibc_platforms_and_a_refused_mallopt_change_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MALLOC_ARENA_MAX", raising=False)
    monkeypatch.setattr(malloc_arenas, "_glibc", lambda: None)
    assert malloc_arenas.limit_malloc_arenas() is False

    refused = _FakeLibc(result=0)
    monkeypatch.setattr(malloc_arenas, "_glibc", lambda: refused)
    assert malloc_arenas.limit_malloc_arenas() is False


def test_glibc_is_detected_only_where_it_is_the_c_library() -> None:
    expected = platform.system() == "Linux" and platform.libc_ver()[0] == "glibc"
    assert (malloc_arenas._glibc() is not None) is expected


def test_importing_the_api_server_applies_the_cap() -> None:
    probe = (
        "from agent_bom.api import malloc_arenas\n"
        "assert malloc_arenas.APPLIED is None\n"
        "import agent_bom.api.server\n"
        "print(malloc_arenas.APPLIED is not None)\n"
    )
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_")}
    env["PYTHONPATH"] = str(ROOT / "src")
    completed = subprocess.run([sys.executable, "-c", probe], env=env, capture_output=True, text=True, timeout=120, check=False)
    assert completed.returncode == 0, completed.stderr[-2000:]
    assert completed.stdout.strip().splitlines()[-1] == "True"
