"""The MCP server emits each log record once, in agent-bom's format, with --log-json still JSON."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

pytest.importorskip("mcp")

_SRC = str(Path(__file__).resolve().parents[1] / "src")

_SCRIPT = """
import logging, sys
from agent_bom.logging_config import setup_logging
from agent_bom.mcp_server import create_mcp_server

setup_logging(level="INFO", json_output="--json" in sys.argv)
create_mcp_server()
logging.getLogger("agent_bom.probe").warning("probe-line-agent-bom")
logging.getLogger("mcp.server.probe").warning("probe-line-sdk")
"""


def _stderr(*args: str) -> str:
    env = {**os.environ, "PYTHONPATH": _SRC + os.pathsep + os.environ.get("PYTHONPATH", "")}
    env.pop("AGENT_BOM_LOG_JSON", None)
    proc = subprocess.run([sys.executable, "-c", _SCRIPT, *args], capture_output=True, text=True, env=env, timeout=120)
    assert proc.returncode == 0, proc.stderr
    return proc.stderr


def test_each_record_is_emitted_once_in_agent_bom_format() -> None:
    err = _stderr()

    assert err.count("probe-line-agent-bom") == 1, err
    assert err.count("probe-line-sdk") == 1, err
    assert "WARNING agent_bom.probe: probe-line-agent-bom" in err
    assert "WARNING mcp.server.probe: probe-line-sdk" in err


def test_log_json_survives_server_construction_and_covers_sdk_records() -> None:
    err = _stderr("--json")

    records = [json.loads(line) for line in err.splitlines() if line.strip()]
    messages = [record["msg"] for record in records]
    assert messages.count("probe-line-agent-bom") == 1, err
    assert messages.count("probe-line-sdk") == 1, err
    assert {record["logger"] for record in records if record["msg"].startswith("probe-")} == {"agent_bom.probe", "mcp.server.probe"}


def test_server_construction_leaves_the_root_logger_as_it_found_it() -> None:
    import logging

    from agent_bom.logging_config import setup_logging
    from agent_bom.mcp_server import create_mcp_server

    root = logging.getLogger()
    saved = (list(root.handlers), root.level)
    root.handlers.clear()
    root.setLevel(logging.WARNING)
    setup_logging(level="WARNING")
    try:
        create_mcp_server()
        assert root.handlers == []
        assert root.level == logging.WARNING
    finally:
        root.handlers[:] = saved[0]
        root.setLevel(saved[1])
        for name in ("agent_bom", "mcp"):
            logging.getLogger(name).handlers.clear()
            logging.getLogger(name).propagate = True
            logging.getLogger(name).setLevel(logging.NOTSET)
