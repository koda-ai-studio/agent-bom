"""The first command a new user runs must work from the base package alone."""

from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import textwrap
import tomllib
from datetime import datetime, timezone
from pathlib import Path

import pytest
from packaging.requirements import Requirement

from agent_bom.api.hub_payload_codec import decode_hub_payload
from agent_bom.cli._quickstart import _resolve_agent_bom
from scripts.check_architecture import OPTIONAL_EXTRA_MODULES

ROOT = Path(__file__).resolve().parents[1]
SCAN_ID = "11111111-1111-4111-8111-111111111111"
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
# Listed as optional for lazy-import accounting, but the base ``mcp`` dependency installs them.
ARRIVE_WITH_MCP = frozenset({"opentelemetry", "sse_starlette", "starlette", "uvicorn"})


def _names(requirements: list[str]) -> set[str]:
    return {Requirement(value).name.lower() for value in requirements}


def test_base_dependencies_carry_the_stored_payload_codec() -> None:
    assert "zstandard" in _names(PROJECT["dependencies"])
    assert "zstandard" not in _names(PROJECT["optional-dependencies"]["api"])


def test_base_dependencies_are_not_declared_as_optional_imports() -> None:
    assert _names(PROJECT["dependencies"]).isdisjoint(OPTIONAL_EXTRA_MODULES)


def test_quickstart_job_persistence_needs_no_optional_module(tmp_path: Path) -> None:
    """A finding payload crosses the compression threshold; only extras modules are hidden."""
    report = tmp_path / "report.json"
    database = tmp_path / "control-plane.db"
    finding = {
        "canonical_id": "8d132cac-70fa-5a25-9ba7-2f57916ca1de",
        "vulnerability_id": "CVE-2026-0001",
        "severity": "high",
        "package": "example@1.0.0",
        "package_name": "example",
        "package_version": "1.0.0",
        "ecosystem": "pypi",
        "title": "x" * 2048,
        "description": "y" * 2048,
        "owasp_tags": [f"LLM{number:04d}" for number in range(200)],
    }
    report.write_text(
        json.dumps(
            {
                "scan_id": SCAN_ID,
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "scan_run": {"schema_version": "1", "scan_id": SCAN_ID, "outcome": "complete", "issues": [], "scopes": []},
                "agents": [],
                "findings": [finding],
            }
        ),
        encoding="utf-8",
    )
    script = textwrap.dedent(
        """
        import sys
        from datetime import datetime, timezone
        from pathlib import Path

        hidden = frozenset(sys.argv[3].split(","))

        class HideExtras:
            def find_spec(self, name, path=None, target=None):
                if name.split(".")[0] in hidden:
                    raise ModuleNotFoundError(f"No module named {name!r}", name=name)
                return None

        sys.meta_path.insert(0, HideExtras())

        from agent_bom.cli._quickstart import _persist_completed_scan

        _persist_completed_scan(
            Path(sys.argv[1]),
            Path(sys.argv[2]),
            sys.argv[4],
            datetime.now(timezone.utc),
        )
        """
    )
    result = subprocess.run(  # noqa: S603 - fixed interpreter and test-owned script
        [sys.executable, "-c", script, str(report), str(database), ",".join(sorted(OPTIONAL_EXTRA_MODULES - ARRIVE_WITH_MCP)), SCAN_ID],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr[-1500:]
    with sqlite3.connect(database) as connection:
        stored = connection.execute("SELECT payload FROM finding_lifecycle").fetchall()
    assert stored, "the fixture must exercise the lifecycle write that compresses finding payloads"
    assert all("__abom_zstd" in row[0] for row in stored)
    assert decode_hub_payload(stored[0][0])["vulnerability_id"] == "CVE-2026-0001"


@pytest.mark.parametrize(
    ("platform", "interpreter", "script"),
    [
        ("win32", "Scripts/python.exe", "Scripts/agent-bom.exe"),
        ("linux", "bin/python", "bin/agent-bom"),
        ("darwin", "bin/python3", "bin/agent-bom"),
    ],
)
def test_console_script_resolves_beside_the_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, interpreter: str, script: str
) -> None:
    (tmp_path / interpreter).parent.mkdir(parents=True)
    (tmp_path / interpreter).touch()
    (tmp_path / script).touch()
    monkeypatch.setattr("agent_bom.cli._quickstart.sys.platform", platform)
    monkeypatch.setattr("agent_bom.cli._quickstart.sys.executable", str(tmp_path / interpreter))
    monkeypatch.setattr("agent_bom.cli._quickstart.shutil.which", lambda _name: None)

    assert _resolve_agent_bom() == str(tmp_path / script)


def test_console_script_falls_back_to_path_only_when_absent_beside_interpreter(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "Scripts").mkdir()
    (tmp_path / "Scripts" / "python.exe").touch()
    monkeypatch.setattr("agent_bom.cli._quickstart.sys.platform", "win32")
    monkeypatch.setattr("agent_bom.cli._quickstart.sys.executable", str(tmp_path / "Scripts" / "python.exe"))
    monkeypatch.setattr("agent_bom.cli._quickstart.shutil.which", lambda name: f"C:/tools/{name}.exe")

    assert _resolve_agent_bom() == "C:/tools/agent-bom.exe"
