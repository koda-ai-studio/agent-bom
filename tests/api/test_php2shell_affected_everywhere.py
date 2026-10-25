"""One PHP2Shell answer on every surface: CLI, REST, MCP and the UI fixture its component tests render.

Official php 8.3.30 is affected with patch target 8.3.36, official php 8.3.36
is not affected, and Debian's php8.2-cli before the distribution's fix is
possibly affected (distro) — never clean, never a confirmed vulnerability.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

from click.testing import CliRunner

from agent_bom.cli import main
from tests.api.test_advisory_affected_api import PHP2SHELL, REPORTS, ROUTE
from tests.api.test_mcp_affected_assets import control_plane  # noqa: F401 - fixture

FIXTURES = Path(__file__).parents[1] / "fixtures" / "php2shell"
UI_FIXTURE = Path(__file__).parents[2] / "ui" / "tests" / "fixtures" / "php2shell-affected.json"
SUMMARY = {"affected": 1, "possibly_affected": 1, "not_affected": 1, "clean_scanned": 1, "assets_examined": 3, "reports_examined": 3}


def _brief(body: dict) -> list[tuple]:
    return [(r["asset_label"], r["package"]["name"], r["installed_version"], r["fixed_version"], r["verdict"]) for r in body["rows"]]


def _verdict_reasons(body: dict) -> list:
    return [row["verdict_reason"] for row in body["rows"]]


def _cli_answer(tmp_path: Path) -> tuple[dict, str]:
    runner = CliRunner()
    assert runner.invoke(main, ["db", "advisory", "add", "--file", str(FIXTURES / "operator-advisory.json")]).exit_code == 0
    args: list[str] = []
    for index, report in enumerate(REPORTS):
        path = tmp_path / f"report-{index}.json"
        path.write_text(json.dumps(report))
        args += ["--report", str(path)]
    as_json = runner.invoke(main, ["db", "advisory", "affected", "CVE-2026-109618", *args, "--format", "json"], catch_exceptions=False)
    assert as_json.exit_code == 0, as_json.output
    table = runner.invoke(main, ["db", "advisory", "affected", "CVE-2026-109619", *args], catch_exceptions=False)
    return json.loads(as_json.output), table.output


def test_same_php2shell_answer_on_cli_rest_mcp_and_ui(control_plane, tmp_path: Path) -> None:  # noqa: F811
    from agent_bom.mcp_tools.affected_assets import affected_assets_impl

    cli, table = _cli_answer(tmp_path)
    rest = control_plane.get(ROUTE.format("CVE-2026-109618")).json()
    mcp = json.loads(asyncio.run(affected_assets_impl(advisory_id="CVE-2026-109618")))
    ui = json.loads(UI_FIXTURE.read_text())

    for body in (cli, rest, mcp, ui):
        assert _brief(body) == PHP2SHELL
        assert body["summary"] == SUMMARY
        assert _verdict_reasons(body) == [None, "distro_backport_unverified", None]
        assert body["advisory"]["fixed_versions"] == ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]
    assert mcp == rest
    assert [row["graph"] for row in cli["rows"]] == [row["graph"] for row in rest["rows"]]

    assert "affected\tphp:8.3.30-cli\tphp@8.3.30\tpatch to 8.3.36" in table
    distro = "possibly affected — verify distro advisory\tabtest/php-debian:12\tphp8.2-cli@8.2.29-1~deb12u1"
    assert f"{distro}\tpatch to verify distro advisory" in table
    assert "not affected\tphp:8.3.36-cli\tphp@8.3.36\tpatch to -" in table
    assert "safe" not in table.lower()
