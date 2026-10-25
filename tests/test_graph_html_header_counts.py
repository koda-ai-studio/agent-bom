"""Every graph-html header count equals what the canvas draws."""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from click.testing import CliRunner

from agent_bom.cli import main

_FIXTURE = Path(__file__).parent / "fixtures" / "agent_frameworks" / "langgraph_two_nodes"


def _elements(html: str) -> list[dict]:
    match = re.search(r"const els=(\[.*?\]);\nconst topRisks", html, re.S)
    assert match
    return json.loads(match.group(1))


def _header(html: str) -> dict[str, int]:
    stats = re.search(r'<div id="stats">(.*?)</div>', html, re.S)
    assert stats
    return {label: int(count) for count, label in re.findall(r"<span>(\d+) ([a-zA-Z ]+?)</span>", stats.group(1))}


def _drawn_counts(elements: list[dict]) -> dict[str, int]:
    nodes = [el["data"] for el in elements if "source" not in el["data"]]
    cves: set[str] = set()
    for node in nodes:
        if node.get("type") == "pkg_vuln":
            cves.update(str(item.get("id")) for item in json.loads(node.get("cveList") or "[]"))
        elif str(node.get("type", "")).startswith("cve"):
            cves.add(str(node.get("id")))
    return {
        "agents": sum(1 for n in nodes if n.get("type") == "agent"),
        "servers": sum(1 for n in nodes if str(n.get("type", "")).startswith("server_")),
        "vulnerable packages": sum(1 for n in nodes if n.get("type") == "pkg_vuln"),
        "CVEs": len(cves),
    }


def test_header_counts_equal_drawn_elements_for_framework_project(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    shutil.copytree(_FIXTURE, project)
    (project / "requirements.txt").write_text("langgraph==0.2.0\n", encoding="utf-8")
    out = tmp_path / "graph.html"

    result = CliRunner().invoke(main, ["scan", "-p", str(project), "--offline", "-f", "graph-html", "-o", str(out)])

    assert out.exists(), result.output
    html = out.read_text(encoding="utf-8")
    drawn = _drawn_counts(_elements(html))
    assert drawn["agents"] >= 3  # project agent plus the planner and writer framework agents
    assert _header(html) == drawn


def test_header_counts_cover_vulnerable_packages_and_collapsed_cves() -> None:
    from agent_bom.output.graph_html import drawn_header_counts

    cves = json.dumps([{"id": "CVE-2026-0001"}, {"id": "CVE-2026-0002"}])
    elements = [
        {"data": {"id": "agent:a", "type": "agent"}},
        {"data": {"id": "srv", "type": "server_vuln"}},
        {"data": {"id": "pkg:a", "type": "pkg_vuln", "cveList": cves}},
        {"data": {"id": "pkg:b", "type": "pkg_vuln", "cveList": json.dumps([{"id": "CVE-2026-0002"}])}},
        {"data": {"source": "agent:a", "target": "srv", "type": "uses"}},
    ]

    assert drawn_header_counts(elements) == {"total_agents": 1, "total_servers": 1, "total_pkgs": 2, "total_vulns": 2}
