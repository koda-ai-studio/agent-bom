"""Push lifecycle behaviour the workflow measurements found, on a small estate and fresh SQLite stores.

Strict xfails are confirmed product gaps (not fixed here); each flips to a failure
once the behaviour is fixed, so the marker must then be removed. The passing test
guards the behaviour the CLI push path relies on.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from scripts.generate_graph_benchmark_estate import generate_estate
from scripts.perf.workflow_budget import PUSH_HEADERS, _expire_retained_jobs, _Http, _push, _run_cli_scan, mocked_upstream
from scripts.perf.workflow_equivalence import mutate_inventory
from scripts.perf.workflow_lifecycle import RESOLVED_IDENTITY_FIELDS, resolved_rows
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
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="the content idempotency key outlives the retained job: an identical re-push gets 409 for 24 h",
)
async def test_identical_push_after_retention_is_admitted_again(workflow_control_plane, tmp_path) -> None:  # noqa: F811
    report, inventory = _estate()
    body = cli_push_body(await _scan(report, inventory, tmp_path / "inventory.json"))
    async with _client() as client:
        http = _Http(client)
        await _push(http, body, 300)
        assert (await _expire_retained_jobs(http))["jobs_after"] == 0
        response, _ = await http.call("POST", "/v1/results/push", content=body, headers=PUSH_HEADERS)
        assert response.status_code in {201, 202}, response.text[:300]


@pytest.mark.asyncio
@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="a finding resolved by a later push is served without package, package_version, ecosystem and scan_id",
)
async def test_resolved_finding_keeps_its_package_identity(workflow_control_plane, tmp_path) -> None:  # noqa: F811
    report, inventory = _estate()
    mutated, change = mutate_inventory(report, inventory)
    path = tmp_path / "inventory.json"
    original = cli_push_body(await _scan(report, inventory, path))
    updated = cli_push_body(await _scan(report, mutated, path))
    async with _client() as client:
        http = _Http(client)
        await _push(http, original, 300)
        await _push(http, updated, 300)
        rows = await resolved_rows(http, change["deleted"][0])
    assert rows and all(row.get("resolution_reason") == "no_longer_detected" for row in rows)
    missing = sorted({field for row in rows for field in RESOLVED_IDENTITY_FIELDS if not row.get(field)})
    assert missing == [], missing
