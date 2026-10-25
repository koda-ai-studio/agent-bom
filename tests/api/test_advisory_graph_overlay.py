"""Operator-advisory matches join the scan graph: a vulnerability node and a vulnerable_to edge from the package."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi", reason="fastapi not installed")

import agent_bom.api.routes.operator_advisories  # noqa: F401 - registers the graph-input overlay
from agent_bom.api.advisory_graph_overlay import with_advisory_vulnerabilities
from agent_bom.api.operator_advisory_store import InMemoryOperatorAdvisoryStore
from agent_bom.api.stores import set_operator_advisory_store
from agent_bom.db import schema
from agent_bom.graph.types import RelationshipType

FIXTURES = Path(__file__).parents[1] / "fixtures" / "php2shell"
ADVISORY = json.loads((FIXTURES / "operator-advisory.json").read_text())
REPORTS = json.loads((FIXTURES / "affected-reports.json").read_text())


@pytest.fixture()
def declared(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setattr(schema, "DB_PATH", tmp_path / "absent" / "vulns.db")
    store = InMemoryOperatorAdvisoryStore()
    store.put("tenant-a", ADVISORY)
    set_operator_advisory_store(store)
    yield store
    set_operator_advisory_store(None)


def _packages(report: dict) -> list[dict]:
    return report["agents"][0]["mcp_servers"][0]["packages"]


def test_overlay_adds_only_confirmed_matches_and_never_mutates_the_report(declared) -> None:
    affected, debian = copy.deepcopy(REPORTS[0]), copy.deepcopy(REPORTS[2])
    overlaid = with_advisory_vulnerabilities(affected, declared.list("tenant-a"))
    assert "vulnerabilities" not in _packages(affected)[0]
    (vuln,) = _packages(overlaid)[0]["vulnerabilities"]
    assert (vuln["id"], vuln["severity"], vuln["fixed_version"], vuln["provenance"]) == (
        "CVE-2026-109618",
        "critical",
        "8.3.36",
        "operator_advisory",
    )
    assert with_advisory_vulnerabilities(debian, declared.list("tenant-a")) is debian
    assert with_advisory_vulnerabilities(affected, declared.list("tenant-b")) is affected


def test_persisted_scan_graph_carries_the_vulnerable_to_edge(declared, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.api.pipeline as pipeline
    from agent_bom.api.graph_store import SQLiteGraphStore

    store = SQLiteGraphStore(tmp_path / "graph.db")
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)
    report = copy.deepcopy(REPORTS[0])
    pipeline._persist_graph_snapshot(SimpleNamespace(job_id="scan-php-8.3.30", tenant_id="tenant-a", progress=[]), report)
    graph = store.load_graph(tenant_id="tenant-a", scan_id="scan-php-8.3.30")
    vuln = graph.nodes["vuln:CVE-2026-109618"]
    assert vuln.attributes["provenance"] == "operator_advisory"
    edges = [(e.source, e.target) for e in graph.edges if e.relationship == RelationshipType.VULNERABLE_TO]
    assert [target for source, target in edges if source.startswith("pkg:")] == ["vuln:CVE-2026-109618"]
    assert "vulnerabilities" not in _packages(report)[0]
