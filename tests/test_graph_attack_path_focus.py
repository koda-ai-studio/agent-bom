"""A finding's investigation link must open its path wherever it ranks in the queue."""

from __future__ import annotations

from agent_bom.graph.container import AttackPath, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.path_evidence import annotate_attack_path_evidence
from agent_bom.graph.types import EntityType, RelationshipType
from tests.test_graph_tenant_scope_and_bounds import api  # noqa: F401


def _queue_graph(tenant: str, count: int = 30) -> UnifiedGraph:
    graph = UnifiedGraph(tenant_id=tenant, scan_id="focus-scan", created_at="2026-10-18T00:00:00Z")
    source = "principal:reader"
    graph.add_node(UnifiedNode(id=source, entity_type=EntityType.SERVICE_ACCOUNT, label="reader"))
    paths = []
    for index in range(count):
        target = f"data:store-{index}"
        graph.add_node(UnifiedNode(id=target, entity_type=EntityType.DATA_STORE, label=target))
        graph.add_edge(UnifiedEdge(source=source, target=target, relationship=RelationshipType.CAN_ACCESS))
        path = AttackPath(source=source, target=target, hops=[source, target], edges=["can_access"], composite_risk=90.0 - index)
        if index == count - 1:
            path.finding_ids = ["finding-last"]
        paths.append(annotate_attack_path_evidence(path, graph))
    graph.attack_paths = paths
    return graph


def test_node_focus_returns_a_path_beyond_the_first_page(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_queue_graph("tenant-a"))
    unfocused = client.get("/v1/graph/attack-paths", params={"scan_id": "focus-scan", "limit": 10}, headers=headers["tenant-a"]).json()
    assert "data:store-29" not in {path["target"] for path in unfocused["attack_paths"]}

    response = client.get(
        "/v1/graph/attack-paths",
        params={"scan_id": "focus-scan", "limit": 10, "node_id": "data:store-29"},
        headers=headers["tenant-a"],
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert [path["target"] for path in body["attack_paths"]] == ["data:store-29"]
    assert body["pagination"]["total"] == 1
    assert body["pagination"]["has_more"] is False
    assert body["focus"] == {"node_id": "data:store-29", "finding_id": None, "resolved_from": None, "covers_all_matches": True}


def test_finding_focus_matches_the_occurrence_and_misses_are_empty_not_errors(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_queue_graph("tenant-a"))
    params = {"scan_id": "focus-scan", "limit": 10}
    found = client.get("/v1/graph/attack-paths", params=params | {"finding_id": "finding-last"}, headers=headers["tenant-a"]).json()
    assert [path["target"] for path in found["attack_paths"]] == ["data:store-29"]
    both = client.get(
        "/v1/graph/attack-paths", params=params | {"finding_id": "finding-last", "node_id": "data:store-3"}, headers=headers["tenant-a"]
    )
    assert both.status_code == 200, both.text
    assert both.json()["attack_paths"] == []
    assert both.json()["pagination"]["total"] == 0


def test_focused_cursor_is_bound_to_its_focus(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_queue_graph("tenant-a"))
    params = {"scan_id": "focus-scan", "limit": 1, "node_id": "principal:reader"}
    first = client.get("/v1/graph/attack-paths", params=params, headers=headers["tenant-a"]).json()
    assert first["pagination"]["total"] == 30
    cursor = first["pagination"]["next_cursor"]
    assert cursor
    second = client.get("/v1/graph/attack-paths", params=params | {"cursor": cursor}, headers=headers["tenant-a"])
    assert second.status_code == 200, second.text
    assert second.json()["attack_paths"][0]["target"] != first["attack_paths"][0]["target"]
    other_focus = {"scan_id": "focus-scan", "limit": 1, "node_id": "data:store-1", "cursor": cursor}
    assert client.get("/v1/graph/attack-paths", params=other_focus, headers=headers["tenant-a"]).status_code == 400


def test_focus_never_reads_another_tenant(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_queue_graph("tenant-a"))
    response = client.get(
        "/v1/graph/attack-paths", params={"scan_id": "focus-scan", "node_id": "data:store-29"}, headers=headers["tenant-b"]
    )
    body = response.json()
    assert body.get("attack_paths", []) == []
    assert body.get("nodes", []) == []
    assert "principal:reader" not in response.text


def _advisory_graph(tenant: str) -> UnifiedGraph:
    """Paths record the advisory id, not the finding store's occurrence UUID."""
    graph = UnifiedGraph(tenant_id=tenant, scan_id="advisory-scan", created_at="2026-10-18T00:00:00Z")
    hops = ["agent:svc", "server:orch", "pkg:pypi:langchain@0.0.150", "vuln:CVE-2023-36258"]
    for node_id, kind in zip(hops, [EntityType.AGENT, EntityType.SERVER, EntityType.PACKAGE, EntityType.VULNERABILITY]):
        graph.add_node(UnifiedNode(id=node_id, entity_type=kind, label=node_id))
    graph.add_node(UnifiedNode(id="pkg:pypi:other@1", entity_type=EntityType.PACKAGE, label="other"))
    graph.add_node(UnifiedNode(id="agent:other", entity_type=EntityType.AGENT, label="other"))
    path = AttackPath(source=hops[0], target=hops[-1], hops=hops, edges=["uses", "depends_on", "affects"], composite_risk=80.0)
    path.vuln_ids = ["CVE-2023-36258"]
    path.finding_ids = ["CVE-2023-36258"]
    other = AttackPath(
        source="agent:other",
        target="vuln:CVE-2023-36258",
        hops=["agent:other", "pkg:pypi:other@1", "vuln:CVE-2023-36258"],
        edges=["depends_on", "affects"],
        composite_risk=70.0,
    )
    other.vuln_ids = ["CVE-2023-36258"]
    graph.attack_paths = [annotate_attack_path_evidence(path, graph), annotate_attack_path_evidence(other, graph)]
    return graph


def test_occurrence_resolves_through_its_node_and_advisory_when_paths_lack_the_uuid(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_advisory_graph("tenant-a"))
    params = {
        "scan_id": "advisory-scan",
        "limit": 10,
        "node_id": "pkg:pypi:langchain@0.0.150",
        "finding_id": "8d96119f-27b7-596e-9e73-a540b6863817",
    }
    strict = client.get("/v1/graph/attack-paths", params=params, headers=headers["tenant-a"]).json()
    assert strict["attack_paths"] == []

    resolved = client.get("/v1/graph/attack-paths", params=params | {"advisory_id": "CVE-2023-36258"}, headers=headers["tenant-a"]).json()
    assert [path["source"] for path in resolved["attack_paths"]] == ["agent:svc"]
    assert resolved["focus"]["matched_by"] == "node_advisory"
    assert resolved["focus"]["advisory_id"] == "CVE-2023-36258"


def test_advisory_never_widens_focus_without_the_occurrence_node(api):  # noqa: F811
    client, store, headers = api
    store.save_graph(_advisory_graph("tenant-a"))
    params = {"scan_id": "advisory-scan", "limit": 10, "finding_id": "8d96119f", "advisory_id": "CVE-2023-36258"}
    body = client.get("/v1/graph/attack-paths", params=params, headers=headers["tenant-a"]).json()
    assert body["attack_paths"] == []
    other_tenant = client.get(
        "/v1/graph/attack-paths", params=params | {"node_id": "pkg:pypi:langchain@0.0.150"}, headers=headers["tenant-b"]
    ).json()
    assert other_tenant.get("attack_paths", []) == []


def _control_snapshot(monkeypatch, rows, *, partial=False):
    seen: list[dict] = []

    def fake_snapshot(request, **kwargs):
        seen.append(kwargs)
        projection = kwargs.get("row_projection") or (lambda row: row)
        return {"findings": [projection(row) for row in rows], "completeness": {"status": "partial" if partial else "complete"}}

    monkeypatch.setattr("agent_bom.api.routes.scan.current_findings_snapshot", fake_snapshot)
    return seen


def test_control_focus_returns_the_paths_of_its_mapped_occurrences(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    store.save_graph(_advisory_graph("tenant-a"))
    seen = _control_snapshot(
        monkeypatch,
        [{"finding_id": "8d96119f", "cve_id": "CVE-2023-36258", "node_id": "pkg:pypi:langchain@0.0.150"}],
    )
    body = client.get(
        "/v1/graph/attack-paths",
        params={"scan_id": "advisory-scan", "limit": 10, "framework": "cis", "control": "CIS-02.6"},
        headers=headers["tenant-a"],
    ).json()
    # Only the occurrence's own node path; the other asset carrying the same advisory is not this control's evidence.
    assert [path["source"] for path in body["attack_paths"]] == ["agent:svc"]
    assert body["focus"]["control"] == "CIS-02.6"
    assert body["focus"]["framework"] == "cis"
    assert body["focus"]["control_findings"] == 1
    assert body["focus"]["covers_all_matches"] is True
    assert seen[0]["framework"] == "cis" and seen[0]["control"] == "CIS-02.6"
    assert seen[0]["scan_id"] == "advisory-scan"


def test_control_focus_is_honest_about_a_bounded_finding_set(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    store.save_graph(_advisory_graph("tenant-a"))
    _control_snapshot(monkeypatch, [], partial=True)
    body = client.get(
        "/v1/graph/attack-paths",
        params={"scan_id": "advisory-scan", "framework": "cis", "control": "CIS-02.6"},
        headers=headers["tenant-a"],
    ).json()
    assert body["attack_paths"] == []
    assert body["focus"]["covers_all_matches"] is False


def test_control_focus_requires_both_framework_and_control(api, monkeypatch):  # noqa: F811
    client, store, headers = api
    store.save_graph(_advisory_graph("tenant-a"))
    _control_snapshot(monkeypatch, [])
    response = client.get("/v1/graph/attack-paths", params={"scan_id": "advisory-scan", "control": "CIS-02.6"}, headers=headers["tenant-a"])
    assert response.status_code == 400
