"""A plain ``agent-bom db update`` must refresh NVD, or NVD-only CVEs never reach the local DB."""

from __future__ import annotations

from typing import Any

from click.testing import CliRunner


def test_default_sync_sources_include_nvd() -> None:
    from agent_bom.db.sync import DEFAULT_SYNC_SOURCES

    assert "nvd" in DEFAULT_SYNC_SOURCES
    assert {"osv", "alpine", "debian", "epss", "kev"} <= set(DEFAULT_SYNC_SOURCES)


def test_cli_db_update_without_source_syncs_the_default_sources(monkeypatch) -> None:
    import agent_bom.db.sync as sync_module
    from agent_bom.cli._db import db_cmd
    from agent_bom.db.sync import DEFAULT_SYNC_SOURCES

    seen: dict[str, Any] = {}

    def fake_sync_db(*args: Any, **kwargs: Any) -> dict[str, int]:
        seen["sources"] = list(kwargs.get("sources") or [])
        return {source: 0 for source in seen["sources"]}

    monkeypatch.setattr(sync_module, "sync_db", fake_sync_db)
    result = CliRunner().invoke(db_cmd, ["update"])

    assert result.exit_code == 0, result.output
    assert seen["sources"] == list(DEFAULT_SYNC_SOURCES)
    assert "nvd" in result.output
