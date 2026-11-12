"""Push lifecycle behaviour the workflow measurements found, on a small estate and fresh SQLite stores.

Each test guards one behaviour the measurements found: a CLI rescan replaces
rather than grows the graph, an identical push after retention stores again, a
resolved finding keeps its package and scans, a late older report cannot bring
back a package a newer scan removed, and agent ids do not depend on the
inventory file path.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from scripts.generate_graph_benchmark_estate import generate_estate
from scripts.perf.workflow_budget import PUSH_HEADERS, _expire_retained_jobs, _Http, _push, _run_cli_scan, mocked_upstream, stored_findings
from scripts.perf.workflow_equivalence import mutate_inventory
from scripts.perf.workflow_lifecycle import RESOLVED_IDENTITY_FIELDS, findings_view, graph_refresh, open_keys, resolved_rows
from scripts.perf.workflow_profiles import MockUpstream, cli_push_body, inventory_from_estate, vulnerable_versions
from tests.test_workflow_resource_budget import workflow_control_plane  # noqa: F401  (fixture)

pytestmark = pytest.mark.graph_performance

AGENTS = 4


def _estate() -> tuple[dict, dict]:
    report, _summary = generate_estate(agents=AGENTS, seed=2145, vulnerable_package_rate=0.3)
    return report, inventory_from_estate(report)


def _scan_sync(report: dict, inventory: dict, path: Path) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(inventory), encoding="utf-8")
    output = path.with_suffix(".report.json")
    with mocked_upstream(MockUpstream(vulnerable=vulnerable_versions(report))):
        _run_cli_scan(path, output)  # exits 1 when it reports findings, as the CLI does
    return output.read_bytes()


async def _scan(report: dict, inventory: dict, path: Path) -> bytes:
    """The CLI runs its own event loop, so it scans in a worker thread."""
    return await asyncio.to_thread(_scan_sync, report, inventory, path)


def _client() -> httpx.AsyncClient:
    from agent_bom.api.server import app

    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://workflow", timeout=300)


async def _graph_page(http: _Http) -> tuple[int, int]:
    for _ in range(240):
        response, _ = await http.call("GET", "/v1/graph?limit=100")
        if response.status_code == 200:
            return len(response.content), int(response.json()["stats"]["total_nodes"])
        await asyncio.sleep(0.25)
    raise AssertionError(f"graph never became readable: {response.status_code}")


@pytest.mark.asyncio
async def test_rescans_pushed_by_one_cli_source_replace_rather_than_grow_the_graph(workflow_control_plane, tmp_path) -> None:  # noqa: F811
    """Two scans of one estate from different paths, pushed with the CLI's source and scope.

    Without them the two reports are independent evidence and the current graph is their
    union: measured at 12 agents, the limit=100 page grew 1.98 -> 3.45 MB.
    """
    report, inventory = _estate()
    first = await _scan(report, inventory, tmp_path / "a" / "inventory.json")
    second = await _scan(report, inventory, tmp_path / "b" / "inventory.json")
    async with _client() as client:
        http = _Http(client)
        await _push(http, cli_push_body(first), 300)
        before_bytes, before_nodes = await _graph_page(http)
        await _push(http, cli_push_body(second), 300)
        await asyncio.sleep(1)
        after_bytes, after_nodes = await _graph_page(http)
    assert after_nodes == before_nodes
    # Timestamps and scan ids in the payload differ by a few bytes; growth was +74%.
    assert abs(after_bytes - before_bytes) <= before_bytes // 100, (before_bytes, after_bytes)


@pytest.mark.asyncio
async def test_identical_push_after_retention_is_admitted_again(workflow_control_plane, tmp_path) -> None:  # noqa: F811
    """The content key outlives the job it answered for; once retention removed the job, the same push stores again."""
    report, inventory = _estate()
    body = cli_push_body(await _scan(report, inventory, tmp_path / "inventory.json"))
    async with _client() as client:
        http = _Http(client)
        first = await _push(http, body, 300)
        stored = await stored_findings(http, first["job_id"])
        assert (await _expire_retained_jobs(http))["jobs_after"] == 0
        response, _ = await http.call("POST", "/v1/results/push", content=body, headers=PUSH_HEADERS)
        assert response.status_code in {201, 202}, response.text[:300]
        again = await _push(http, body, 300)
        assert again["status"] == "stored"
        assert await stored_findings(http, again["job_id"]) == stored


@pytest.mark.asyncio
async def test_resolved_finding_keeps_its_package_identity(workflow_control_plane, tmp_path) -> None:  # noqa: F811
    report, inventory = _estate()
    mutated, change = mutate_inventory(report, inventory)
    path = tmp_path / "inventory.json"
    original = cli_push_body(await _scan(report, inventory, path))
    updated = cli_push_body(await _scan(report, mutated, path))
    async with _client() as client:
        http = _Http(client)
        first = await _push(http, original, 300)
        second = await _push(http, updated, 300)
        rows = await resolved_rows(http, change["deleted"][0])
    assert rows and all(row.get("resolution_reason") == "no_longer_detected" for row in rows)
    missing = sorted({field for row in rows for field in RESOLVED_IDENTITY_FIELDS if not row.get(field)})
    assert missing == [], missing
    _, name, version = change["deleted"]
    assert {(row["package"].removesuffix(f"@{version}"), row["package_version"]) for row in rows} == {(name, version)}
    assert {row["scan_id"] for row in rows} == {first["job_id"]}
    assert {row["resolved_by_scan_id"] for row in rows} == {second["job_id"]}


@pytest.mark.asyncio
async def test_a_late_older_report_does_not_bring_back_a_removed_package(workflow_control_plane, tmp_path) -> None:  # noqa: F811
    """Ordering follows each report's own time: a newer scan's removal survives an older report delivered after it."""
    report, inventory = _estate()
    mutated, change = mutate_inventory(report, inventory)
    path = tmp_path / "inventory.json"
    older = await _scan(report, inventory, path)
    await asyncio.sleep(1.1)  # keep the two report times clearly apart
    newer = await _scan(report, mutated, path)
    _, name, version = change["deleted"]
    async with _client() as client:
        http = _Http(client)
        await _push(http, cli_push_body(older), 300)
        assert (await graph_refresh(http, name, version, deadline=0))[0] >= 1
        await _push(http, cli_push_body(newer), 300)
        assert (await graph_refresh(http, name, version))[0] == 0
        await _push(http, cli_push_body(older), 300, idempotency_key="late-older-report")
        await asyncio.sleep(2)
        assert (await graph_refresh(http, name, version))[0] == 0
        assert tuple(change["deleted"]) not in open_keys(await findings_view(http))


@pytest.mark.asyncio
async def test_agent_ids_do_not_depend_on_the_inventory_path(workflow_control_plane, tmp_path) -> None:  # noqa: F811
    """Unscoped pushes of one estate scanned from two paths describe the same agents, so the graph does not grow."""
    report, inventory = _estate()
    first = await _scan(report, inventory, tmp_path / "a" / "inventory.json")
    second = await _scan(report, inventory, tmp_path / "b" / "inventory.json")

    def agent_ids(body: bytes) -> set[str]:
        return {str(agent.get("canonical_id")) for agent in json.loads(body).get("agents") or []}

    assert agent_ids(first) == agent_ids(second) and len(agent_ids(first)) == AGENTS
    async with _client() as client:
        http = _Http(client)
        await _push(http, first, 300)
        _, before_nodes = await _graph_page(http)
        await _push(http, second, 300)
        await asyncio.sleep(1)
        _, after_nodes = await _graph_page(http)
    assert after_nodes == before_nodes
