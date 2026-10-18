"""MCP graph tools answer agents with the same evidence REST and the UI show.

Two persisted fixtures are exercised: the ``scan --demo`` estate (derived
paths, completed scan job, compliance evidence) and the showcase enterprise
estate (thousands of persisted paths). Every MCP answer is compared with the
REST route the dashboard reads, not with a hand-written expectation.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.graph_contract("warn")

_ROOT = Path(__file__).resolve().parents[1]
_SHOWCASE_SEED = """
from agent_bom.storage.state_home import activate_demo_state_dir
activate_demo_state_dir()
from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
summary = maybe_bootstrap_demo_estate(tenant_id="default")
assert summary.get("graph_seeded"), summary
"""


def _env(workdir: Path, **extra: str) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AGENT_BOM_") or key in {"AGENT_BOM_OFFLINE", "AGENT_BOM_SKIP_UPDATE_CHECK"}
    }
    env.update(
        AGENT_BOM_DB=str(workdir / "cp.db"),
        AGENT_BOM_GRAPH_DB=str(workdir / "graph.db"),
        AGENT_BOM_OFFLINE="1",
        AGENT_BOM_STATE_DIR=str(workdir),
        **extra,
    )
    return env


@pytest.fixture(scope="module")
def demo_dir(tmp_path_factory) -> Path:
    workdir = tmp_path_factory.mktemp("mcp-demo")
    report = workdir / "report.json"
    subprocess.run(
        [sys.executable, "-m", "agent_bom", "scan", "--demo", "--offline", "--context-graph", "-f", "json", "-q", "-o", str(report)],
        env=_env(workdir),
        cwd=workdir,
        capture_output=True,
        timeout=300,
        check=False,
    )
    assert report.is_file() and (workdir / "graph.db").is_file()
    return workdir


@pytest.fixture(scope="module")
def showcase_dir(tmp_path_factory) -> Path:
    workdir = tmp_path_factory.mktemp("mcp-showcase")
    env = _env(workdir, AGENT_BOM_DEMO_ESTATE="1", AGENT_BOM_DEMO_STATE_DIR=str(workdir), AGENT_BOM_DEMO_STORY_PREWARM="0")
    result = subprocess.run([sys.executable, "-c", _SHOWCASE_SEED], env=env, cwd=workdir, capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr[-2000:]
    return workdir


class _Estate:
    def __init__(self, name: str, client: Any, store: Any) -> None:
        self.name = name
        self.client = client
        self.store = store

    def rest(self, path: str, **params: Any) -> dict[str, Any]:
        response = self.client.get(path, params=params)
        assert response.status_code == 200, response.text[:500]
        return response.json()

    def mcp(self, impl: Any, **kwargs: Any) -> dict[str, Any]:
        return json.loads(self.mcp_raw(impl, **kwargs))

    def mcp_raw(self, impl: Any, **kwargs: Any) -> str:
        if "_get_graph_store" in inspect.signature(impl).parameters:
            kwargs.setdefault("_get_graph_store", lambda: self.store)
        kwargs.setdefault("_truncate_response", lambda value: value)
        return asyncio.run(impl(**kwargs))


@pytest.fixture()
def _api_env(monkeypatch: pytest.MonkeyPatch) -> pytest.MonkeyPatch:
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_KEYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_TENANT_ID", raising=False)
    return monkeypatch


def _open_estate(name: str, workdir: Path, with_jobs: bool) -> Iterator[_Estate]:
    from starlette.testclient import TestClient

    from agent_bom.api import stores as api_stores
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.server import app

    store = SQLiteGraphStore(str(workdir / "graph.db"))
    previous_graph = getattr(api_stores, "_graph_store", None)
    previous_jobs = getattr(api_stores, "_store", None)
    api_stores.set_graph_store(store)
    from datetime import datetime, timezone

    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.store import InMemoryJobStore

    job_store = InMemoryJobStore()
    if with_jobs:
        report = json.loads((workdir / "report.json").read_text())
        now = datetime.now(timezone.utc).isoformat()
        job_store.put(
            ScanJob(
                job_id=report["scan_id"],
                tenant_id="default",
                request=ScanRequest(),
                triggered_by="test",
                status=JobStatus.DONE,
                created_at=now,
                started_at=now,
                completed_at=now,
                result=report,
            )
        )
    api_stores.set_job_store(job_store)
    try:
        yield _Estate(name, TestClient(app), store)
    finally:
        api_stores.set_graph_store(previous_graph)  # type: ignore[arg-type]
        api_stores.set_job_store(previous_jobs)


@pytest.fixture()
def demo(demo_dir: Path, _api_env) -> Iterator[_Estate]:
    yield from _open_estate("demo", demo_dir, with_jobs=True)


@pytest.fixture()
def showcase(showcase_dir: Path, _api_env) -> Iterator[_Estate]:
    yield from _open_estate("showcase", showcase_dir, with_jobs=False)


@pytest.fixture(params=["demo", "showcase"])
def estate(request) -> _Estate:
    return request.getfixturevalue(request.param)


def _rest_queue(estate: _Estate, *, offset: int = 0, limit: int = 1000, **filters: Any) -> dict[str, Any]:
    return estate.rest("/v1/graph/attack-paths", offset=offset, limit=limit, **filters)


def _rest_ids(payload: dict[str, Any]) -> list[str]:
    return [row["exposure_path"]["id"] for row in payload["attack_paths"]]


# ── P0-1: one ranking for MCP and the dashboard queue ────────────────────────


def test_exposure_paths_rank_like_the_dashboard_queue(estate: _Estate) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    rest = _rest_queue(estate, limit=25)
    mcp = estate.mcp(exposure_paths_impl, limit=25)
    assert [path["id"] for path in mcp["paths"]] == _rest_ids(rest)
    assert mcp["total"] == rest["pagination"]["total"]
    assert mcp["ranking"]["method"] == rest["count_metadata"]["ranking"]["method"]
    assert mcp["ranking"]["order"] == rest["count_metadata"]["ranking"]["order"]
    for path, row in zip(mcp["paths"], rest["attack_paths"], strict=True):
        assert (path["evidenceTier"], path["isKev"], path["severity"]) == (row["evidence_tier"], row["is_kev"], row["severity"])
        assert path["rank"] == row["exposure_path"]["rank"]


def test_demo_kev_path_is_first_and_says_why(demo: _Estate) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    first = demo.mcp(exposure_paths_impl, limit=1)["paths"][0]
    assert "CVE-2023-4863" in first["id"]
    assert first["isKev"] is True
    assert first["evidenceTier"] == 3
    assert first["rank"] == 1


def test_cursor_walk_returns_every_dashboard_path_once_in_order(demo: _Estate) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    seen: list[str] = []
    cursor = None
    last: dict[str, Any] = {}
    while True:
        last = demo.mcp(exposure_paths_impl, limit=10, cursor=cursor)
        seen.extend(path["id"] for path in last["paths"])
        cursor = last["pagination"]["next_cursor"]
        if not cursor:
            break
    assert seen == _rest_ids(_rest_queue(demo))
    assert len(seen) == len(set(seen)) == last["total"]
    # The final page leaves nothing behind it.
    assert last["pagination"]["has_more"] is False
    assert last["completeness"]["truncated"] is False


def test_showcase_pages_follow_dashboard_offsets(showcase: _Estate) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    first = showcase.mcp(exposure_paths_impl, limit=100)
    assert first["count"] == 100
    second = showcase.mcp(exposure_paths_impl, limit=100, cursor=first["pagination"]["next_cursor"])
    rest = _rest_queue(showcase, offset=100, limit=100, snapshot_generation=first["snapshot_generation"])
    assert [path["id"] for path in second["paths"]] == _rest_ids(rest)
    assert second["paths"][0]["rank"] == 101


def test_server_side_filters_match_rest(estate: _Estate) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    rest = _rest_queue(estate, limit=50, min_severity="critical")
    mcp = estate.mcp(exposure_paths_impl, limit=50, min_severity="critical")
    assert [path["id"] for path in mcp["paths"]] == _rest_ids(rest)
    assert mcp["total"] == rest["pagination"]["total"]

    kev = estate.mcp(exposure_paths_impl, limit=50, kev=True)
    assert all(path["isKev"] for path in kev["paths"])
    assert kev["total"] == sum(row["is_kev"] for row in _rest_queue(estate)["attack_paths"])

    target = mcp["paths"][0]["target"]["id"] if mcp["paths"] else _rest_queue(estate, limit=1)["attack_paths"][0]["target"]
    by_target = estate.mcp(exposure_paths_impl, limit=50, target_id=target)
    assert by_target["paths"] and all(path["target"]["id"] == target for path in by_target["paths"])


# ── P1-5: bounded, summary-first payloads ────────────────────────────────────


def test_default_exposure_answer_fits_the_agent_budget(estate: _Estate) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    raw = estate.mcp_raw(exposure_paths_impl)
    payload = json.loads(raw)
    assert payload["view"] == "summary"
    assert len(raw) <= 16_000
    assert "nodes" not in payload and "edges" not in payload
    sizes = [len(json.dumps(path, separators=(",", ":"))) for path in payload["paths"]]
    # Path ids embed every hop id, so a long misconfiguration id costs ~380 bytes
    # across ``id``, ``target`` and ``via``; critical misconfiguration paths now
    # rank by their own score instead of tying at a capped value.
    assert sum(sizes) / len(sizes) <= 1_300 and max(sizes) <= 1_300
    for path in payload["paths"]:
        assert {"id", "rank", "riskScore", "severity", "isKev", "evidenceTier", "source", "target", "findings"} <= set(path)
        assert payload["risk_scale"]["riskScore"].startswith("0-100")


def test_summary_view_returns_the_requested_page(showcase: _Estate) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    raw = showcase.mcp_raw(exposure_paths_impl, limit=100)
    payload = json.loads(raw)
    assert payload["count"] == 100
    # Container-to-CVE paths name the image digest in three hop ids.
    assert max(len(json.dumps(path, separators=(",", ":"))) for path in payload["paths"]) <= 1_400
    assert len(raw) <= 140_000


# ── P1-6: every hop resolves to a recorded edge ──────────────────────────────


def test_every_hop_resolves_to_an_edge(estate: _Estate) -> None:
    from agent_bom.mcp_tools.graph import exposure_paths_impl

    payload = estate.mcp(exposure_paths_impl, limit=20, view="full")
    edge_ids = {edge["id"] for edge in payload["edges"]}
    assert payload["paths"]
    for path in payload["paths"]:
        assert len(path["relationships"]) == len(path["nodeIds"]) - 1, path["id"]
        assert set(path["edgeIds"]) <= edge_ids
        for relationship, (source, target) in zip(path["relationships"], zip(path["nodeIds"], path["nodeIds"][1:]), strict=True):
            assert {relationship["source"], relationship["target"]} == {source, target}


# ── P0-3: deploy gate searches the whole stored path set ────────────────────


def test_should_i_deploy_finds_a_candidate_ranked_beyond_the_first_page(showcase: _Estate) -> None:
    from agent_bom.mcp_tools.graph import deploy_decision_impl

    generation = _rest_queue(showcase, limit=1)["snapshot_generation"]
    queue = _rest_queue(showcase, offset=600, limit=1, snapshot_generation=generation)
    deep = queue["attack_paths"][0]
    first_page_targets = {row["target"] for row in _rest_queue(showcase, limit=100)["attack_paths"]}
    candidate = deep["target"]
    assert candidate not in first_page_targets
    payload = showcase.mcp(deploy_decision_impl, candidate=candidate)
    assert payload["matchedPathCount"] >= 1
    assert payload["searchedPaths"] == payload["total"] == queue["pagination"]["total"]
    assert any(path["target"]["id"] == candidate for path in payload["matchedPaths"])


def test_should_i_deploy_is_compact(demo: _Estate) -> None:
    from agent_bom.mcp_tools.graph import deploy_decision_impl

    raw = demo.mcp_raw(deploy_decision_impl, candidate="CVE-2023-4863")
    assert "\n" not in raw
    payload = json.loads(raw)
    assert payload["matchedPathCount"] >= 1
    assert payload["searchedPaths"] == payload["total"]


# ── P0-2: blast radius carries the graph's exposure ─────────────────────────


def _blast(demo: _Estate, cve: str, **overrides: Any) -> dict[str, Any]:
    from agent_bom.mcp_server import _persisted_finding_evidence, _validate_cve_id
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    async def no_local_scan(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("persisted evidence must not fall back to a local scan")

    return demo.mcp(
        blast_radius_impl,
        cve_id=cve,
        _validate_cve_id=_validate_cve_id,
        _run_scan_pipeline=no_local_scan,
        _get_persisted_evidence=_persisted_finding_evidence,
        **overrides,
    )


@pytest.mark.parametrize("cve", ["CVE-2023-4863", "CVE-2020-14343"])
def test_blast_radius_projects_credentials_tools_and_reach_from_graph_paths(demo: _Estate, cve: str) -> None:
    payload = _blast(demo, cve)
    paths = [row for row in _rest_queue(demo)["attack_paths"] if f"vuln:{cve}" in row["hops"]]
    assert paths, "fixture must carry graph paths for this advisory"
    expected_credentials = sorted({credential for row in paths for credential in row["credential_exposure"]})
    expected_tools = sorted({tool for row in paths for tool in row["tool_exposure"]})
    rows = payload["blast_radii"]
    assert sorted({c for row in rows for c in row["exposed_credentials"] or []}) == expected_credentials
    assert sorted({t for row in rows for t in row["exposed_tools"] or []}) == expected_tools
    assert all(row["graph_reachable"] is True for row in rows)
    assert all(row["graph"]["matched_paths"] >= 1 for row in rows)
    assert all(row["graph"]["source"] == "graph_attack_paths" for row in rows)


def test_blast_radius_never_reports_unknown_as_empty(demo: _Estate) -> None:
    class _NoGraph:
        def snapshot_identity(self, **_kwargs: Any) -> Any:
            raise NotImplementedError

    rows = _blast(demo, "CVE-2023-4863", _get_graph_store=lambda: _NoGraph())["blast_radii"]
    assert rows
    for row in rows:
        assert row["exposed_credentials"] is None
        assert row["exposed_tools"] is None
        assert row["graph"]["status"] == "unavailable"


# ── P0-4: compliance answers from persisted tenant evidence ─────────────────


def test_compliance_reads_persisted_tenant_evidence_like_rest(demo: _Estate) -> None:
    from agent_bom.mcp_tools.compliance_persisted import compliance_tool_impl

    async def no_local_scan(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("persisted tenant compliance must not run a laptop scan")

    payload = demo.mcp(compliance_tool_impl, _run_scan_pipeline=no_local_scan)
    rest = demo.rest("/v1/compliance/summary")
    assert payload["source"] == "persisted_tenant_compliance"
    assert payload["scope"]["tenant_id"] == "default"
    assert payload["summary"] == rest
    assert payload["summary"]["total_controls"] == rest["total_controls"]


def test_compliance_control_drill_matches_findings_route(demo: _Estate) -> None:
    from agent_bom.mcp_tools.compliance_persisted import compliance_tool_impl

    framework = demo.rest("/v1/compliance/summary")
    rest_framework = demo.rest("/v1/compliance/owasp-llm")
    failing = [control for control in rest_framework["controls"] if control.get("findings") or control.get("status") in {"fail", "warning"}]
    assert failing, framework
    control = failing[0]["control_id"] if "control_id" in failing[0] else failing[0]["code"]

    async def no_local_scan(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("no laptop scan")

    payload = demo.mcp(compliance_tool_impl, framework="owasp-llm", control=control, limit=500, _run_scan_pipeline=no_local_scan)
    rest_rows = demo.rest("/v1/findings", framework="owasp-llm", control=control, limit=500)
    assert payload["framework"] == rest_framework
    assert payload["driving_findings"]["ids"] == [row["id"] for row in rest_rows["findings"]]
    assert payload["driving_findings"]["total"] == rest_rows["total"]


def test_compliance_local_scan_is_explicit_and_labelled(demo: _Estate) -> None:
    from agent_bom.mcp_tools.compliance_persisted import compliance_tool_impl

    calls: list[Any] = []

    async def local_scan(*args: Any, **_kwargs: Any) -> Any:
        calls.append(args)
        return [], [], [], []

    payload = demo.mcp(compliance_tool_impl, source="local_scan", _run_scan_pipeline=local_scan)
    assert calls
    assert payload["source"] == "local_scan"
    assert payload["scope"]["tenant_id"] is None


# ── P1-7: what can reach X ───────────────────────────────────────────────────


def test_graph_reach_matches_rest_impact(estate: _Estate) -> None:
    from agent_bom.mcp_tools.graph_reach import graph_reach_impl

    node = _rest_queue(estate, limit=1)["attack_paths"][0]["target"]
    rest = estate.rest("/v1/graph/impact", node=node, max_depth=4)
    seen: list[str] = []
    cursor = None
    while True:
        page = estate.mcp(graph_reach_impl, node_id=node, direction="in", max_depth=4, limit=25, cursor=cursor)
        seen.extend(item["id"] for item in page["items"])
        cursor = page["pagination"]["next_cursor"]
        if not cursor:
            break
    assert seen == rest["affected_nodes"]
    assert page["total"] == rest["affected_count"]
    assert page["affected_by_type"] == rest["affected_by_type"]
    assert page["completeness"] == rest["completeness"]
    assert page["interpretation"] == rest["interpretation"]


def test_graph_reach_filters_entity_types(demo: _Estate) -> None:
    from agent_bom.mcp_tools.graph_reach import graph_reach_impl

    node = _rest_queue(demo, limit=1)["attack_paths"][0]["target"]
    page = demo.mcp(graph_reach_impl, node_id=node, entity_types=["agent"], limit=100)
    assert page["items"] and all(item["entityType"] == "agent" for item in page["items"])
    assert page["total"] == page["affected_by_type"]["agent"]
    out = demo.mcp(graph_reach_impl, node_id=page["items"][0]["id"], direction="out", max_depth=4)
    assert node in {item["id"] for item in out["items"]}


# ── P1-9: findings tools reuse the findings route ────────────────────────────


def test_findings_query_matches_rest(demo: _Estate) -> None:
    from agent_bom.mcp_tools.findings import findings_query_impl

    rest = demo.rest("/v1/findings", severity="critical", limit=10)
    payload = demo.mcp(findings_query_impl, severity="critical", limit=10)
    assert [row["id"] for row in payload["findings"]] == [row["id"] for row in rest["findings"]]
    assert payload["total"] == rest["total"]
    assert payload["risk_scale"] == {"risk_score": "0-10", "effective_reach_score": "0-100"}
    assert len(json.dumps(payload)) < len(json.dumps(rest))
    page_two = demo.mcp(findings_query_impl, severity="critical", limit=10, cursor=payload["next_cursor"])
    rest_two = demo.rest("/v1/findings", severity="critical", limit=10, cursor=rest["next_cursor"])
    assert [row["id"] for row in page_two["findings"]] == [row["id"] for row in rest_two["findings"]]


def test_finding_detail_joins_graph_paths(demo: _Estate) -> None:
    from agent_bom.mcp_tools.findings import finding_detail_impl

    row = demo.rest("/v1/findings", q="CVE-2023-4863", limit=1)["findings"][0]
    payload = demo.mcp(finding_detail_impl, finding_id=row["id"])
    assert payload["finding"]["id"] == row["id"]
    assert payload["graph"]["matched_paths"] >= 1
    assert payload["graph"]["reachers"]
    assert any("CVE-2023-4863" in path["id"] for path in payload["graph"]["paths"])
    assert "triage" in payload


# ── graph_diff: bounded snapshot diff for agents and the dashboard ──────────

_LEGACY_DIFF_BYTES_FLOOR = 5_000_000


def test_showcase_graph_diff_payloads_are_bounded(showcase: _Estate) -> None:
    from agent_bom.graph.diff_view import FULL_BYTE_CAP
    from agent_bom.mcp_tools.graph_diff import graph_diff_impl

    legacy = showcase.store.diff_snapshots("showcase-baseline", "showcase", tenant_id="default")
    legacy_bytes = len(json.dumps(legacy, separators=(",", ":"), default=str))
    assert legacy_bytes >= _LEGACY_DIFF_BYTES_FLOOR, "the unbounded diff this view replaces"

    summary_response = showcase.client.get("/v1/graph/diff")
    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert (summary["old"], summary["new"]) == ("showcase-baseline", "showcase")
    assert len(summary_response.content) <= 16_000
    totals = summary["summary"]["totals"]
    assert totals["nodes"]["added"] == len(legacy["nodes_added"])
    assert totals["edges"]["added"] == len(legacy["edges_added"])
    assert summary["summary"]["total_changes"] == sum(len(legacy[key]) for key in _DIFF_LIST_KEYS)

    raw = showcase.mcp_raw(graph_diff_impl)
    assert len(raw) <= 16_000

    detail = showcase.client.get("/v1/graph/diff", params={"view": "detail", "limit": 200})
    assert len(detail.content) <= 80_000 and len(detail.json()["items"]) == 200

    full = showcase.client.get("/v1/graph/diff", params={"view": "full"})
    body = full.json()
    assert len(full.content) <= FULL_BYTE_CAP + 50_000
    assert body["truncated"] is True and body["complete"] is False
    assert body["total_changes"] == summary["summary"]["total_changes"] > body["returned_changes"]
    assert len(body["change_kind_index"]["nodes"]) == len(body["nodes_added"]) + len(body["nodes_removed"]) + len(body["nodes_changed"])


_DIFF_LIST_KEYS = ("nodes_added", "nodes_removed", "nodes_changed", "edges_added", "edges_removed", "edges_changed")


def test_graph_diff_mcp_matches_rest(showcase: _Estate) -> None:
    from agent_bom.mcp_tools.graph_diff import graph_diff_impl

    rest = showcase.rest("/v1/graph/diff")
    mcp = showcase.mcp(graph_diff_impl)
    assert mcp["summary"] == rest["summary"] and (mcp["old"], mcp["new"]) == (rest["old"], rest["new"])

    filters = {"change": "added", "entity_type": "vulnerability"}
    seen_mcp: list[str] = []
    seen_rest: list[str] = []
    mcp_cursor = rest_cursor = None
    for _ in range(4):
        page = showcase.mcp(graph_diff_impl, view="detail", limit=50, cursor=mcp_cursor, **filters)
        rest_params: dict[str, Any] = {"view": "detail", "limit": 50, **filters}
        if rest_cursor:
            rest_params["cursor"] = rest_cursor
        rest_page = showcase.rest("/v1/graph/diff", **rest_params)
        assert page["total"] == rest_page["total"] == rest["summary"]["nodes_by_entity_type"]["vulnerability"]["added"]
        assert page["items"] == rest_page["items"]
        seen_mcp.extend(row["id"] for row in page["items"])
        seen_rest.extend(row["id"] for row in rest_page["items"])
        mcp_cursor, rest_cursor = page["pagination"]["next_cursor"], rest_page["pagination"]["next_cursor"]
        assert mcp_cursor == rest_cursor
    assert seen_mcp == seen_rest and len(seen_mcp) == len(set(seen_mcp)) == 200
    assert all(
        row["change"] == "added" and row["entity_type"] == "vulnerability"
        for row in showcase.mcp(graph_diff_impl, view="detail", limit=200, **filters)["items"]
    )


def test_graph_diff_tool_errors_match_rest(demo: _Estate) -> None:
    from agent_bom.mcp_tools.graph_diff import graph_diff_impl

    assert demo.client.get("/v1/graph/diff").status_code == 404
    assert demo.mcp(graph_diff_impl)["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE"
    assert demo.mcp(graph_diff_impl, view="full")["error"]["details"] == {"argument": "view"}
    assert demo.mcp(graph_diff_impl, limit=201)["error"]["details"] == {"argument": "limit"}
    assert demo.mcp(graph_diff_impl, from_scan_id="missing-a", to_scan_id="missing-b")["error"]["code"] == "AGENTBOM_MCP_NOT_FOUND_RESOURCE"


def test_new_graph_modules_import_without_fastapi() -> None:
    code = (
        "import sys; sys.modules['fastapi'] = None; "
        "import agent_bom.mcp_tools.graph, agent_bom.mcp_tools.graph_reach, agent_bom.mcp_tools.finding_graph, "
        "agent_bom.graph.attack_path_queue, agent_bom.mcp_tools.deploy_gate, "
        "agent_bom.mcp_tools.findings, agent_bom.mcp_tools.compliance_persisted, agent_bom.mcp_tools.graph_registration, "
        "agent_bom.mcp_tools.graph_diff, agent_bom.graph.diff_view"
    )
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, cwd=_ROOT)
    assert result.returncode == 0, result.stderr


def test_new_tools_are_registered_in_graph_profile() -> None:
    from agent_bom.mcp_tools.profiles import PROFILES

    for name in ("graph_reach", "graph_diff", "findings_query", "finding_detail", "should_i_deploy"):
        assert name in PROFILES["graph"].tools
        assert name in PROFILES["guided"].tools


def test_summary_omits_only_a_label_repeated_by_its_endpoints():
    from agent_bom.mcp_tools.exposure_queue import summary_path

    path = {
        "id": "exact-path-id",
        "label": "Finding via Agent",
        "source": {"id": "agent:1", "label": "Agent"},
        "target": {"id": "finding:1", "label": "Finding"},
        "nodeIds": ["agent:1", "finding:1"],
    }
    result = summary_path(path)
    assert "label" not in result
    assert result["id"] == path["id"]
    assert result["source"]["label"] == "Agent" and result["target"]["label"] == "Finding"
    assert path["label"] == "Finding via Agent"
    path["label"] = "Distinct recorded context"
    assert summary_path(path)["label"] == path["label"]
