"""Finding-type regression matrix: every finding type reaches the security graph.

For each ``FindingType`` with an offline producer, every report row of that type
must, after the report -> graph -> SQLite store -> API round trip:

* resolve ``finding_node_id`` to an existing vulnerability/misconfiguration node;
* hang off a non-finding asset through an in-contract edge carrying evidence;
* carry the same severity on the row, the graph node and ``/v1/findings``;
* carry every compliance tag of the row on the graph node;
* keep the same ids across identical rebuilds, with no duplicate per asset+rule.

Types with no offline producer are listed explicitly and xfail with the missing
fixture named, so a coverage gap stays visible instead of silently passing.
"""

from __future__ import annotations

import copy
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from finding_matrix_scenarios import SCENARIOS, scenario_prompts

from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS
from agent_bom.finding import FindingType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.edge_evidence import evidence_problems
from agent_bom.graph.relationship_specs import relationship_spec
from agent_bom.graph.severity_floor import counts_as_finding_node
from agent_bom.graph.types import EntityType

PRODUCERS: dict[FindingType, tuple[str, ...]] = {
    FindingType.CVE: ("demo", "securityhub"),
    FindingType.CIS_FAIL: ("cloud",),
    FindingType.CIS_ERROR: ("cloud",),
    FindingType.CLOUD_BEST_PRACTICE_FAIL: ("cloud", "prowler", "securityhub"),
    FindingType.CLOUD_BEST_PRACTICE_ERROR: ("cloud", "prowler"),
    FindingType.CREDENTIAL_EXPOSURE: ("secrets", "cloud"),
    FindingType.PII_EXPOSURE: ("secrets",),
    FindingType.INJECTION: ("prompts", "poison"),
    FindingType.PROMPT_SECURITY: ("demo", "poison"),
    FindingType.SAST: ("sarif",),
    FindingType.SKILL_RISK: ("skill",),
    FindingType.BROWSER_EXT: ("browser",),
    FindingType.LICENSE: ("sbom",),
    FindingType.MCP_BLOCKLIST: ("skill", "mcp"),
    FindingType.COMBINATION: ("demo", "mcp", "poison"),
    FindingType.MALICIOUS_MODEL: ("models",),
    FindingType.MODEL_INTEGRITY: ("models",),
    FindingType.CIEM_OVER_PRIVILEGE: ("cloud",),
}
NO_OFFLINE_PRODUCER: dict[FindingType, str] = {
    FindingType.TOOL_DRIFT: "needs a runtime-proxy tool-description baseline fixture",
    FindingType.EXFILTRATION: "needs a runtime-proxy session fixture",
    FindingType.CLOAKING: "needs a runtime-proxy response fixture",
    FindingType.RATE_LIMIT: "needs a runtime-proxy rate-window fixture",
    FindingType.MALICIOUS_PACKAGE: "needs an offline malicious-package feed fixture",
    FindingType.SENSITIVE_DATA: "needs a DSPM object-sampling fixture",
}
_FINDING_ENTITIES = {EntityType.VULNERABILITY, EntityType.MISCONFIGURATION}
# Sources whose asset edge depends on evidence a scanner-only report lacks.
ASSET_EDGE_GAPS: dict[str, str] = {
    "SECRET_SCAN": "file nodes come only from the repository overlay; a secret occurrence never invents its file "
    "(tests/test_graph_secret_pii_evidence.py) and no offline fixture records repo structure yet",
}


def test_every_finding_type_is_classified() -> None:
    assert set(PRODUCERS) | set(NO_OFFLINE_PRODUCER) == set(FindingType)
    assert not set(PRODUCERS) & set(NO_OFFLINE_PRODUCER)


@pytest.fixture(scope="module")
def reports(tmp_path_factory: pytest.TempPathFactory) -> dict[str, dict[str, Any]]:
    cache: dict[str, dict[str, Any]] = {}
    work = tmp_path_factory.mktemp("finding-matrix")

    def get(name: str) -> dict[str, Any]:
        if name not in cache:
            with pytest.MonkeyPatch.context() as mp:
                cache[name] = SCENARIOS[name](work, mp)
        return cache[name]

    return _LazyReports(get)  # type: ignore[return-value]


class _LazyReports(dict):  # type: ignore[type-arg]
    def __init__(self, getter: Any) -> None:
        super().__init__()
        self._get = getter

    def __getitem__(self, name: str) -> dict[str, Any]:
        return self._get(name)


@pytest.fixture(scope="module")
def surfaces(reports: Any, tmp_path_factory: pytest.TempPathFactory) -> Any:
    cache: dict[str, dict[str, Any]] = {}
    work = tmp_path_factory.mktemp("finding-matrix-api")

    def get(name: str) -> dict[str, Any]:
        if name not in cache:
            cache[name] = _surface(name, reports[name], work)
        return cache[name]

    return get


def _tags(row: dict[str, Any]) -> set[str]:
    return {str(tag) for field in COMPLIANCE_TAG_FIELDS for tag in row.get(field) or []}


def _surface(name: str, report: dict[str, Any], work: Path) -> dict[str, Any]:
    """Graph rebuild + SQLite graph store + API rows for one scenario report."""
    from starlette.testclient import TestClient

    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import JobStatus
    from agent_bom.api.server import ScanJob, ScanRequest, app, set_job_store
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.api.stores import _get_store, set_graph_store

    scan_id = str(report.get("scan_id") or f"matrix-{name}")
    graph = build_unified_graph_from_report(copy.deepcopy(report), scan_id=scan_id, tenant_id="default")
    rebuilt = build_unified_graph_from_report(copy.deepcopy(report), scan_id=scan_id, tenant_id="default")
    now = datetime.now(timezone.utc).isoformat()
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
        mp.delenv("AGENT_BOM_API_KEY", raising=False)
        mp.delenv("AGENT_BOM_API_KEYS", raising=False)
        set_job_store(InMemoryJobStore())
        job = ScanJob(
            job_id=scan_id,
            tenant_id="default",
            request=ScanRequest(),
            status=JobStatus.DONE,
            created_at=now,
            completed_at=now,
            result=report,
        )
        _get_store().put(job)
        store = SQLiteGraphStore(str(work / f"{name}.db"))
        store.save_graph(graph)
        set_graph_store(store)
        try:
            client = TestClient(app)
            findings = client.get(f"/v1/findings?scan_id={scan_id}&limit=500")
            stats = client.get(f"/v1/graph?scan_id={scan_id}&limit=5")
        finally:
            set_graph_store(None)  # type: ignore[arg-type]
    assert findings.status_code == 200, findings.text
    assert stats.status_code == 200, stats.text
    body = findings.json()
    api_rows = {row["id"]: row for row in body.get("findings") or body.get("items") or []}
    return {
        "graph": graph,
        "rebuilt": rebuilt,
        "api": api_rows,
        "stats": stats.json()["stats"].get("severity_counts") or {},
    }


def _params() -> list[Any]:
    params = []
    for finding_type in FindingType:
        if finding_type in NO_OFFLINE_PRODUCER:
            mark = pytest.mark.xfail(reason=f"no offline producer: {NO_OFFLINE_PRODUCER[finding_type]}", strict=True)
            params.append(pytest.param(finding_type, None, marks=mark, id=f"{finding_type.value}-none"))
            continue
        for scenario in PRODUCERS[finding_type]:
            params.append(pytest.param(finding_type, scenario, id=f"{finding_type.value}-{scenario}"))
    return params


@pytest.mark.parametrize(("finding_type", "scenario"), _params())
def test_finding_type_reaches_graph(finding_type: FindingType, scenario: str | None, reports: Any, surfaces: Any) -> None:
    if scenario is None:
        pytest.fail(f"{finding_type.value} has no offline producer")
    report = reports[scenario]
    rows = [row for row in report["findings"] if row.get("finding_type") == finding_type.value]
    assert rows, f"{scenario} produced no {finding_type.value} findings"
    surface = surfaces(scenario)
    graph, api = surface["graph"], surface["api"]
    problems: list[str] = []
    gaps: set[str] = set()
    for row in rows:
        label = f"{row['id']} {row.get('title', '')[:60]!r}"
        node_id = row.get("finding_node_id")
        node = graph.nodes.get(node_id) if node_id else None
        if node is None:
            problems.append(f"{label}: finding_node_id {node_id!r} does not resolve")
            continue
        if node.entity_type not in _FINDING_ENTITIES:
            problems.append(f"{label}: node {node_id} is {node.entity_type}")
        assets = [
            edge
            for edge in graph.edges
            if node_id in (edge.source, edge.target)
            and graph.nodes.get(edge.target if edge.source == node_id else edge.source) is not None
            and graph.nodes[edge.target if edge.source == node_id else edge.source].entity_type not in _FINDING_ENTITIES
        ]
        if not assets and row.get("source") in ASSET_EDGE_GAPS:
            gaps.add(ASSET_EDGE_GAPS[row["source"]])
        elif not assets:
            problems.append(f"{label}: node {node_id} has no asset edge")
        for edge in assets:
            spec = relationship_spec(edge.relationship)
            src, tgt = graph.nodes[edge.source].entity_type, graph.nodes[edge.target].entity_type
            if spec is None or not spec.allows(src, tgt):
                problems.append(f"{label}: edge {edge.relationship} {src}->{tgt} outside the contract")
            elif evidence_problems(edge.evidence, spec.required_evidence):
                problems.append(f"{label}: edge {edge.relationship} lacks evidence {edge.evidence}")
        if str(node.severity).lower() != str(row["severity"]).lower():
            problems.append(f"{label}: severity row={row['severity']} node={node.severity}")
        api_row = api.get(row["id"])
        if api_row is None:
            problems.append(f"{label}: missing from /v1/findings")
        elif str(api_row["severity"]).lower() != str(row["severity"]).lower():
            problems.append(f"{label}: severity row={row['severity']} api={api_row['severity']}")
        missing_tags = _tags(row) - set(node.compliance_tags or [])
        if missing_tags:
            problems.append(f"{label}: node lacks compliance tags {sorted(missing_tags)[:6]}")
    assert not problems, "\n".join(problems)
    if gaps:
        pytest.xfail("; ".join(sorted(gaps)))


@pytest.mark.parametrize("scenario", sorted(SCENARIOS))
def test_scenario_graph_parity(scenario: str, reports: Any, surfaces: Any) -> None:
    report = reports[scenario]
    surface = surfaces(scenario)
    graph, rebuilt = surface["graph"], surface["rebuilt"]
    findings = report["findings"]
    report_sev = Counter(str(row["severity"]).lower() for row in findings)
    finding_nodes = [node for node in graph.nodes.values() if counts_as_finding_node(node) and node.severity]
    assert Counter(str(n.severity).lower() for n in finding_nodes) == report_sev
    assert Counter({k.lower(): v for k, v in surface["stats"].items() if v}) == report_sev
    referenced = {row.get("finding_node_id") for row in findings}
    assert sorted(n.id for n in finding_nodes if n.id not in referenced) == []
    assert set(graph.nodes) == set(rebuilt.nodes)
    assert {(e.source, e.target, str(e.relationship)) for e in graph.edges} == {
        (e.source, e.target, str(e.relationship)) for e in rebuilt.edges
    }
    keys = Counter(
        (
            row["finding_type"],
            (row.get("asset") or {}).get("canonical_id") or (row.get("asset") or {}).get("identifier"),
            row.get("vulnerability_id") or (row.get("evidence") or {}).get("rule_id") or row.get("title"),
            (row.get("evidence") or {}).get("line_number") or (row.get("evidence") or {}).get("line"),
        )
        for row in findings
    )
    assert [key for key, count in keys.items() if count > 1] == []
    assert len({row["id"] for row in findings}) == len(findings)


def test_prompt_finding_ids_do_not_depend_on_path_form(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    relative = scenario_prompts(tmp_path, monkeypatch, relative=True)
    absolute = scenario_prompts(tmp_path, monkeypatch)
    assert sorted(r["id"] for r in relative["findings"]) == sorted(r["id"] for r in absolute["findings"])


def test_reports_do_not_leak_host_paths(reports: Any) -> None:
    home = str(Path.home())
    for name in ("skill", "browser", "prompts", "models"):
        text = str(reports[name]["findings"])
        assert "/private/" not in text and "/tmp/" not in text and home not in text, name


def test_one_over_privilege_finding_per_identity(reports: Any) -> None:
    rows = [row for row in reports["cloud"]["findings"] if row["finding_type"] == "CIEM_OVER_PRIVILEGE"]
    assert rows
    per_identity = Counter(row.get("node_id") for row in rows)
    assert [node for node, count in per_identity.items() if count > 1] == []
    identity_rows = [row for row in reports["cloud"]["findings"] if (row.get("evidence") or {}).get("identity_id")]
    assert {row["source"] for row in identity_rows} == {"GRAPH_ANALYSIS"}


def test_enforcement_findings_keep_distinct_ids(reports: Any) -> None:
    rows = [row for row in reports["poison"]["findings"] if (row.get("evidence") or {}).get("detector") == "mcp_enforcement"]
    assert len(rows) == len({row["id"] for row in rows}) >= 4
    combos = [row for row in rows if row["evidence"].get("category") == "dangerous_combo"]
    assert combos and all(row["asset"]["asset_type"] == "mcp_server" for row in combos)


def test_legacy_browser_extension_rows_rehydrate_to_enums() -> None:
    from agent_bom.domain.finding_rehydrate import finding_from_dict
    from agent_bom.finding import FindingSource

    legacy = {
        "id": "legacy-ext",
        "finding_type": "BROWSER_EXTENSION_RISK",
        "source": "BROWSER_EXTENSION_SCAN",
        "asset": {"name": "ext", "asset_type": "browser_extension", "identifier": "abc"},
        "severity": "high",
        "title": "ext browser extension risk",
    }
    finding = finding_from_dict(legacy)
    assert finding is not None
    assert (finding.finding_type, finding.source) == (FindingType.BROWSER_EXT, FindingSource.BROWSER_EXT)
