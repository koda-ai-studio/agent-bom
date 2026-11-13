"""The cached update-check value is printed only when it is a newer version string."""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

from agent_bom.cli import _common as mod


@pytest.fixture
def fresh_check(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENT_BOM_OFFLINE", raising=False)
    monkeypatch.delenv("AGENT_BOM_SKIP_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(sys, "argv", ["agent-bom", "scan"])
    cache = tmp_path / "update-check.txt"
    monkeypatch.setattr(mod, "_update_check_cache_file", lambda: cache)
    monkeypatch.setattr(mod, "__version__", "1.0.0")
    monkeypatch.setattr(mod, "_update_check_done", threading.Event())
    monkeypatch.setattr(mod, "_update_check_result", None)

    def fail_fetch(*_a, **_k):
        raise AssertionError("a fresh cache must not hit PyPI")

    monkeypatch.setattr("agent_bom.http_client.fetch_json", fail_fetch)
    return cache


def _write_fresh(cache, text: str) -> None:
    cache.write_text(text, encoding="utf-8")
    now = time.time()
    os.utime(cache, (now, now))


@pytest.mark.parametrize(
    "text",
    [
        "0.114.0",
        "1.0.0",
        "[red]injected[/red]",
        "not a version\n9.9.9",
        "9.9.9; echo hi",
        "",
    ],
    ids=["older", "same", "markup", "multiline", "trailing-text", "empty"],
)
def test_foreign_or_stale_cache_prints_nothing(fresh_check, text: str) -> None:
    _write_fresh(fresh_check, text)
    mod._check_for_update_bg()
    assert mod._update_check_result is None


def test_newer_cached_version_builds_the_notice(fresh_check) -> None:
    _write_fresh(fresh_check, "2.3.4\n")
    mod._check_for_update_bg()
    assert mod._update_check_result is not None
    assert "2.3.4" in mod._update_check_result
    assert "Update available" in mod._update_check_result


def test_fetch_caches_only_the_version_string(fresh_check, monkeypatch) -> None:
    monkeypatch.setattr("agent_bom.http_client.fetch_json", lambda *a, **k: {"info": {"version": "3.0.0"}})
    mod._check_for_update_bg()
    assert fresh_check.read_text(encoding="utf-8") == "3.0.0"
    assert "3.0.0" in (mod._update_check_result or "")


def test_log_json_runs_skip_the_notice() -> None:
    assert mod._update_notice_hidden(["scan", "--log-json"])
