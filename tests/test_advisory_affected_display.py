"""Affected-asset rows name the image, agent and host the graph already holds, and say what they count."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.api import advisory_affected_read
from agent_bom.api.advisory_affected_display import (
    AFFECTED_COUNT_BASIS,
    AFFECTED_COUNT_BASIS_NOTE,
    attach_asset_display,
)
from agent_bom.graph import RelationshipType, UnifiedEdge, UnifiedNode
from agent_bom.graph.types import EntityType

IMAGE = "cloud_resource:aws:registry:image:claims-engine-00@sha256:bda9"
WORKLOAD = "kubernetes:workload:eks-7777-14/claims-engine/claims-engine-00"
PKG = "pkg:pypi:pyyaml@5.3:image:bda9"
SERVER = "server:cfg-1:cursor:abc"
AGENT = "agent:cfg-1:cursor"
POD = "kubernetes:pod:eks-1/tools/shell-runner-0"


class FakeStore:
    def __init__(self, nodes: dict[str, UnifiedNode], edges: list[UnifiedEdge]) -> None:
        self.nodes, self.edges, self.calls = nodes, edges, []

    def nodes_by_ids(self, *, tenant_id: str = "", scan_id: str = "", node_ids: set[str]) -> list[UnifiedNode]:
        self.calls.append(("nodes", tenant_id, frozenset(node_ids)))
        return [self.nodes[i] for i in node_ids if i in self.nodes]

    def edges_for_node_ids(self, *, tenant_id: str = "", scan_id: str = "", node_ids: set[str], **kw: Any) -> list[UnifiedEdge]:
        self.calls.append(("edges", tenant_id, frozenset(node_ids)))
        wanted = kw.get("relationships")
        return [e for e in self.edges if e.source in node_ids and (not wanted or e.relationship.value in wanted)]


def _node(node_id: str, kind: EntityType, label: str, **attrs: Any) -> UnifiedNode:
    return UnifiedNode(id=node_id, entity_type=kind, label=label, attributes=attrs)


def _store() -> FakeStore:
    nodes = {
        PKG: _node(PKG, EntityType.PACKAGE, "pyyaml@5.3", tags={"container_image": IMAGE, "workload": WORKLOAD}),
        IMAGE: _node(IMAGE, EntityType.CONTAINER, "claims-engine-00:2026.08.28", resource_type="container_image"),
        WORKLOAD: _node(WORKLOAD, EntityType.CLOUD_RESOURCE, "claims-engine-00"),
        SERVER: _node(SERVER, EntityType.SERVER, "shell-runner-server"),
        AGENT: _node(AGENT, EntityType.AGENT, "Cursor"),
        POD: _node(POD, EntityType.CLOUD_RESOURCE, "shell-runner-0"),
    }
    edges = [UnifiedEdge(source=SERVER, target=POD, relationship=RelationshipType.HOSTED_ON)]
    return FakeStore(nodes, edges)


def _image_row() -> dict[str, Any]:
    return {
        "asset": {"agent": "", "server": "", "asset_type": "package", "node_id": PKG},
        "asset_label": "pyyaml@5.3",
        "asset_type": "package",
        "asset_node_id": PKG,
        "graph": {"package_node_id": PKG, "server_node_id": None, "agent_node_id": None},
    }


def _server_row() -> dict[str, Any]:
    return {
        "asset": {"agent": "cursor", "server": "shell-runner-server"},
        "asset_label": "shell-runner-server",
        "asset_type": "mcp_server",
        "asset_node_id": SERVER,
        "graph": {"package_node_id": "pkg:pypi:pyyaml@5.3", "server_node_id": SERVER, "agent_node_id": AGENT},
    }


def test_image_occurrence_is_named_by_its_image_and_workload() -> None:
    rows = [_image_row()]
    attach_asset_display(rows, tenant_id="t1", store=_store())
    assert rows[0]["asset_display"] == {
        "name": "claims-engine-00:2026.08.28",
        "kind": "container_image",
        "agent": "",
        "host": "claims-engine-00",
    }


def test_server_occurrence_is_named_with_its_agent_and_host() -> None:
    rows = [_server_row()]
    store = _store()
    attach_asset_display(rows, tenant_id="t1", store=store)
    assert rows[0]["asset_display"] == {"name": "shell-runner-server", "kind": "mcp_server", "agent": "Cursor", "host": "shell-runner-0"}
    assert all(call[1] == "t1" for call in store.calls), "every graph read is tenant-scoped"


def test_two_graph_round_trips_for_any_number_of_rows() -> None:
    rows = [_image_row() for _ in range(50)] + [_server_row(), _server_row()]
    store = _store()
    attach_asset_display(rows, tenant_id="t1", store=store)
    assert [kind for kind, *_ in store.calls] == ["nodes", "edges", "nodes"]


def test_missing_graph_nodes_fall_back_to_the_recorded_label_without_raising() -> None:
    rows = [_image_row(), _server_row()]
    attach_asset_display(rows, tenant_id="t1", store=FakeStore({}, []))
    assert rows[0]["asset_display"] == {"name": "pyyaml@5.3", "kind": "package", "agent": "", "host": ""}
    assert rows[1]["asset_display"] == {"name": "shell-runner-server", "kind": "mcp_server", "agent": "cursor", "host": ""}


def test_a_failing_graph_store_never_blocks_the_answer() -> None:
    class Broken:
        def nodes_by_ids(self, **_: Any) -> list[UnifiedNode]:
            raise RuntimeError("graph store offline")

        def edges_for_node_ids(self, **_: Any) -> list[UnifiedEdge]:
            raise RuntimeError("graph store offline")

    rows = [_image_row()]
    attach_asset_display(rows, tenant_id="t1", store=Broken())
    assert rows[0]["asset_display"]["name"] == "pyyaml@5.3"


def test_tenant_answer_carries_display_count_basis_and_is_cached_per_generation(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import read_cache

    read_cache.clear_read_cache()
    computed = {"n": 0}

    def fake_answer(tenant_id: str, advisory_id: str) -> dict[str, Any] | None:
        computed["n"] += 1
        return {"advisory": {"id": advisory_id}, "summary": {"affected": 1}, "rows": [_image_row()], "generation": "g"}

    monkeypatch.setattr(advisory_affected_read, "_uncached_affected_answer", fake_answer)
    monkeypatch.setattr(advisory_affected_read, "_get_graph_store", lambda: _store())
    generation = {"value": "jobs=1"}
    monkeypatch.setattr(advisory_affected_read, "_affected_generation", lambda tenant_id: generation["value"])

    first = advisory_affected_read.tenant_affected_answer("t1", "cve-2020-14343")
    second = advisory_affected_read.tenant_affected_answer("t1", "CVE-2020-14343")
    assert computed["n"] == 1, "same tenant, advisory and generation: one computation"
    assert first is not None and second is not None
    assert first["summary"]["count_basis"] == AFFECTED_COUNT_BASIS
    assert first["summary"]["count_basis_note"] == AFFECTED_COUNT_BASIS_NOTE
    assert first["rows"][0]["asset_display"]["name"] == "claims-engine-00:2026.08.28"

    generation["value"] = "jobs=2"
    advisory_affected_read.tenant_affected_answer("t1", "CVE-2020-14343")
    assert computed["n"] == 2, "a new evidence generation recomputes"
    advisory_affected_read.tenant_affected_answer("t2", "CVE-2020-14343")
    assert computed["n"] == 3, "another tenant never shares the cached body"
    read_cache.clear_read_cache()
