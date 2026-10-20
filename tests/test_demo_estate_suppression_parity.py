"""An approved exception suppresses one occurrence on every surface in the same read; revoke restores it.

REST findings, posture counts, the overview, the graph roll-up, MCP
``blast_radius`` and the attack-path queue all read the one suppression
source (the tenant's exception store, through the findings projection). A path
whose every finding occurrence is suppressed is not an open path: it stays in
the queue as evidence, marked suppressed, and is counted apart from the open
paths.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from tests.test_demo_estate_bootstrap import VIEWER, demo_estate_client  # noqa: F401

_TENANT = "default"
_PYYAML = ("CVE-2020-14343", "pyyaml@5.3", "shell-runner-server")
_REQUESTS_CVE = "CVE-2023-32681"


@pytest.fixture()
def exception_store():
    from agent_bom.api import stores as api_stores
    from agent_bom.api.exception_store import InMemoryExceptionStore

    original = api_stores._exception_store
    store = InMemoryExceptionStore()
    api_stores.set_exception_store(store)
    try:
        yield store
    finally:
        api_stores.set_exception_store(original)


def _approve(store, vuln_id: str, package: str, server: str):
    from agent_bom.api.exception_store import ExceptionStatus, VulnException
    from agent_bom.api.suppression_approval import APPROVAL_VERSION

    now = datetime.now(timezone.utc)
    exc = VulnException(
        vuln_id=vuln_id,
        package_name=package,
        server_name=server,
        reason="accepted risk",
        requested_by="analyst",
        approved_by="reviewer",
        decided_by="reviewer",
        status=ExceptionStatus.APPROVED,
        approved_at=(now - timedelta(seconds=5)).isoformat(),
        expires_at=(now + timedelta(days=60)).isoformat(),
        approval_version=APPROVAL_VERSION,
        tenant_id=_TENANT,
    )
    store.put(exc, tenant_id=_TENANT)
    return exc


def _revoke(store, exc) -> None:
    from dataclasses import replace

    from agent_bom.api.exception_store import ExceptionStatus

    store.put(replace(exc, status=ExceptionStatus.REVOKED, revoked_at=datetime.now(timezone.utc).isoformat()), tenant_id=_TENANT)


def _get(client: TestClient, path: str, **params: object) -> dict:
    response = client.get(path, headers=VIEWER, params=params)
    assert response.status_code == 200, (path, response.text[:400])
    return response.json()


def _mcp_blast(cve_id: str) -> dict:
    from agent_bom.api import stores as api_stores
    from agent_bom.api.scan_finding_read import persisted_finding_evidence
    from agent_bom.mcp_tools.analysis import blast_radius_impl

    async def no_local_scan():  # pragma: no cover - the persisted estate must answer
        raise AssertionError("blast_radius fell back to a local scan")

    raw = asyncio.run(
        blast_radius_impl(
            cve_id=cve_id,
            tenant_id=_TENANT,
            _validate_cve_id=lambda value: value,
            _run_scan_pipeline=no_local_scan,
            _truncate_response=lambda text: text,
            _get_persisted_evidence=persisted_finding_evidence,
            _get_graph_store=api_stores._get_graph_store,
        )
    )
    return json.loads(raw)


def _open_rest_rows(client: TestClient, cve_id: str) -> list[dict]:
    page = _get(client, "/v1/findings", limit=1000, q=cve_id)
    return [row for row in page["findings"] if (row.get("cve_id") or row.get("vulnerability_id")) == cve_id]


def _counts(client: TestClient) -> dict[str, int]:
    counts = _get(client, "/v1/posture/counts")
    overview = _get(client, "/v1/overview")
    summary = _get(client, "/v1/graph/rollup", limit=500)["summary"]
    return {
        "findings": _get(client, "/v1/findings", limit=1)["total"],
        "posture": counts["total"],
        "overview": overview["finding_counts"]["total"],
        "rollup": summary["finding_occurrence_count"],
        "findings_issues": _get(client, "/v1/findings", limit=1, group_occurrences="true")["total"],
        "posture_issues": counts["issues"]["total"],
        "overview_issues": overview["issue_counts"]["total"],
        "rollup_issues": summary["issue_count"],
    }


def _assert_one_number(counts: dict[str, int]) -> None:
    occurrences = {counts[key] for key in ("findings", "posture", "overview", "rollup")}
    issues = {counts[key] for key in ("findings_issues", "posture_issues", "overview_issues", "rollup_issues")}
    assert len(occurrences) == 1, counts
    assert len(issues) == 1, counts


def _paths_targeting(client: TestClient, finding_ids: set[str]) -> list[dict]:
    paths: list[dict] = []
    params: dict[str, object] = {"limit": 1000}
    while True:
        page = _get(client, "/v1/graph/attack-paths", **params)
        paths.extend(path for path in page["attack_paths"] if set(path.get("finding_ids") or []) & finding_ids)
        if not page["pagination"].get("next_cursor"):
            return paths
        params = {"limit": 1000, "cursor": page["pagination"]["next_cursor"]}


def test_exception_reaches_every_surface_and_revoke_restores(demo_estate_client: TestClient, exception_store) -> None:  # noqa: F811
    client = demo_estate_client
    before = _counts(client)
    _assert_one_number(before)

    exc = _approve(exception_store, *_PYYAML)
    suppressed_ids = {
        row["id"]
        for row in _get(client, "/v1/findings", limit=1000, q=_PYYAML[0], status="all")["findings"]
        if row.get("suppressed") is True
    }
    assert len(suppressed_ids) == 1, suppressed_ids

    after = _counts(client)
    _assert_one_number(after)
    assert after["findings"] == before["findings"] - 1

    paths = _paths_targeting(client, suppressed_ids)
    assert paths, "precondition: the suppressed occurrence has attack paths"
    for path in paths:
        open_ids = set(path.get("finding_ids") or []) - suppressed_ids
        assert path.get("suppressed") is (not open_ids), path.get("finding_ids")
    queue = _get(client, "/v1/graph/attack-paths", limit=1)["count_metadata"]
    assert queue["suppressed_paths"] == sum(1 for path in paths if path["suppressed"]) > 0
    assert queue["open_paths"] == queue["total"] - queue["suppressed_paths"]
    assert queue["suppression_complete"] is True

    _revoke(exception_store, exc)
    assert _counts(client) == before
    assert not any(path.get("suppressed") for path in _paths_targeting(client, suppressed_ids))
    restored = _get(client, "/v1/graph/attack-paths", limit=1)["count_metadata"]
    assert restored["suppressed_paths"] == 0
    assert restored["open_paths"] == restored["total"]


def test_mcp_blast_radius_reports_only_open_occurrences(demo_estate_client: TestClient, exception_store) -> None:  # noqa: F811
    client = demo_estate_client
    before = _mcp_blast(_REQUESTS_CVE)
    open_before = _open_rest_rows(client, _REQUESTS_CVE)
    assert before["count"] == len(open_before) > 1

    package = str(open_before[0].get("package") or "")
    exc = _approve(exception_store, _REQUESTS_CVE, package, "*")
    suppressed = len([row for row in open_before if row.get("package") == package])

    after = _mcp_blast(_REQUESTS_CVE)
    open_after = _open_rest_rows(client, _REQUESTS_CVE)
    assert len(open_after) == len(open_before) - suppressed
    assert after["count"] == len(open_after)
    assert after["suppressed_count"] == suppressed
    assert {row["finding_id"] for row in after["blast_radii"]} == {row["id"] for row in open_after}

    _revoke(exception_store, exc)
    assert _mcp_blast(_REQUESTS_CVE)["count"] == len(open_before)


def test_mcp_blast_radius_holders_are_per_occurrence(demo_estate_client: TestClient) -> None:  # noqa: F811
    client = demo_estate_client
    rest = {row["id"]: row for row in _open_rest_rows(client, _REQUESTS_CVE)}
    mcp = _mcp_blast(_REQUESTS_CVE)
    assert mcp["blast_radii"]
    for row in mcp["blast_radii"]:
        expected = rest[row["finding_id"]]
        assert sorted(row["affected_servers"]) == sorted(expected.get("affected_servers") or []), row["finding_id"]
        assert sorted(row["affected_agents"]) == sorted(expected.get("affected_agents") or []), row["finding_id"]
        scale = row["risk_scale"]
        assert 0 <= float(row["risk_score"]) <= 10, row["risk_score"]
        assert scale["risk_score"] == "0-10"
        if row.get("effective_reach_score") is not None:
            assert scale["effective_reach_score"] == "0-100"


_IMDS_INSTANCE = "cloud_resource:aws:aws_instance:210987654321/us-east-1/i-0de00000000000000"


def test_rollup_entities_count_their_own_occurrences(demo_estate_client: TestClient) -> None:  # noqa: F811
    client = demo_estate_client
    view = _get(client, "/v1/graph/rollup", limit=500)
    summary, entries = view["summary"], {entry["id"]: entry for entry in view["top_level"]}
    occurrences = _get(client, "/v1/findings", limit=1)["total"]
    assert summary["finding_occurrence_count"] == occurrences

    cursor = entries["agent:cursor"]["aggregate"]
    assert cursor["finding_occurrence_count"] == cursor["issue_count"] == 5, cursor
    # Every occurrence lands in some top-level entry; shared servers are reported, not hidden.
    metadata = view["aggregate_count_metadata"]
    assert metadata["distinct_finding_occurrences"] == occurrences
    assert sum(entry["aggregate"]["finding_occurrence_count"] for entry in entries.values()) == metadata["finding_occurrence_memberships"]
    orgs = [entry["aggregate"]["finding_occurrence_count"] for entry in entries.values() if entry["entity_type"] == "org"]
    assert sum(orgs) <= occurrences

    assert not [nid for nid in entries if nid.startswith("misconfig:cloud_security:demo-compute-imds-")]
    from agent_bom.api import stores as api_stores

    graph = api_stores._get_graph_store().load_graph(tenant_id=_TENANT, scan_id="")
    parent = next(
        edge.source for edge in graph.edges if edge.target == _IMDS_INSTANCE and str(edge.relationship.value) in {"contains", "owns"}
    )
    drilled = _get(client, "/v1/graph/rollup", node=parent, limit=500)
    instance = next(child for child in drilled["children"] if child["id"] == _IMDS_INSTANCE)
    held = [node for node in graph.nodes.values() if _IMDS_INSTANCE in ((node.attributes or {}).get("finding_ids_by_asset") or {})]
    assert instance["aggregate"]["issue_count"] == len(held) == 2, [node.id for node in held]


def test_overview_headline_reads_one_labelled_basis(demo_estate_client: TestClient) -> None:  # noqa: F811
    overview = _get(demo_estate_client, "/v1/overview")
    headline, issues = overview["headline"], overview["issue_counts"]
    assert headline["basis"] == "issue_groups"
    assert (headline["critical"], headline["high"], headline["kev"]) == (issues["critical"], issues["high"], issues["kev"])
    assert headline["critical_high"] == issues["critical"] + issues["high"]


def test_mcp_context_graph_says_how_much_of_the_current_estate_it_covers(demo_estate_client: TestClient) -> None:  # noqa: F811
    from agent_bom.mcp_tools.analysis import context_graph_impl

    async def no_local_scan(*_args):  # pragma: no cover - the persisted estate must answer
        raise AssertionError("context_graph fell back to a local scan")

    payload = json.loads(
        asyncio.run(context_graph_impl(tenant_id=_TENANT, _run_scan_pipeline=no_local_scan, _truncate_response=lambda text: text))
    )
    estate_agents = _get(demo_estate_client, "/v1/posture/counts")["agents"]["total"]
    coverage = payload["estate_coverage"]
    assert coverage["current_estate_agents"] == estate_agents
    assert coverage["agents_in_view"] == payload["stats"]["agent_count"] == sum(node["kind"] == "agent" for node in payload["nodes"])
    assert coverage["agents_in_view"] < estate_agents
    assert coverage["covers_current_estate"] is False
    assert payload["completeness"]["complete"] is False
    assert payload["completeness"]["total"] == estate_agents
