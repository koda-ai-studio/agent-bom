"""The standalone MCP server reads the same demo database ``serve`` writes.

``agent-bom serve --demo-estate`` points ``AGENT_BOM_DB`` at
``<demo state dir>/control-plane.db``. The MCP server pinned the demo state
directory but left the job store unset, so its tools reported zero findings and
zero paths beside a populated demo graph.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("mcp")

_ENV_KEYS = (
    "AGENT_BOM_DB",
    "AGENT_BOM_POSTGRES_URL",
    "SNOWFLAKE_ACCOUNT",
    "AGENT_BOM_GRAPH_BACKEND",
    "AGENT_BOM_DEMO_STATE_DIR",
    "AGENT_BOM_DEMO_ESTATE",
)


def _clear(monkeypatch: pytest.MonkeyPatch) -> None:
    # setenv first so monkeypatch restores keys the server writes into os.environ.
    for key in (*_ENV_KEYS, "AGENT_BOM_STATE_DIR"):
        monkeypatch.setenv(key, "")
        monkeypatch.delenv(key)


@pytest.fixture()
def demo_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    _clear(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    return tmp_path / "state" / "demo-estate"


def test_demo_mcp_server_uses_demo_control_plane_db(demo_env: Path) -> None:
    import os

    from agent_bom.mcp_server import create_mcp_server

    create_mcp_server(profile="scan")

    assert os.environ["AGENT_BOM_DB"] == str(demo_env / "control-plane.db")


def test_demo_mcp_server_keeps_explicit_db(demo_env: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    from agent_bom.mcp_server import create_mcp_server

    explicit = demo_env / "custom.db"
    monkeypatch.setenv("AGENT_BOM_DB", str(explicit))
    create_mcp_server(profile="scan")

    assert os.environ["AGENT_BOM_DB"] == str(explicit)


def test_non_demo_mcp_server_leaves_db_unset(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    from agent_bom.mcp_server import create_mcp_server

    _clear(monkeypatch)
    monkeypatch.setenv("AGENT_BOM_STATE_DIR", str(tmp_path / "state"))
    create_mcp_server(profile="scan")

    assert "AGENT_BOM_DB" not in os.environ


def test_serve_and_mcp_share_one_resolver() -> None:
    from agent_bom.cli import _server
    from agent_bom.storage.state_home import demo_estate_default_persist

    assert _server._demo_estate_default_persist is demo_estate_default_persist
