"""Semantic repository changes require complete same-repository/ref snapshots."""

import pytest

from agent_bom.graph import EntityType, RelationshipType, UnifiedEdge, UnifiedNode
from tests.api.test_graph_estate_changes import TENANT, client, record
from tests.api.test_graph_estate_changes import estate as estate_fixture

estate = estate_fixture
SCOPE = "a" * 64


def seed_repository(estate, month, definitions, *, status="complete", ref="refs/heads/main"):
    scan_id = record(estate, month, "repo", [])
    job = estate[0].get(scan_id, tenant_id=TENANT)
    job.result["project_inventory"] = {
        "repository_context": {
            "version": 1,
            "scope_id": SCOPE,
            "ref": ref,
            "ref_status": "recorded",
            "revision": str(month) * 40,
            "status": status,
            "coverage": {"npm_yarn": "package_manifests"},
        }
    }
    estate[0].put(job)
    graph = estate[1].load_graph(tenant_id=TENANT, scan_id=scan_id)
    for node_id, kind, subtype in definitions:
        graph.add_node(
            UnifiedNode(
                id=node_id, entity_type=kind, label=node_id, attributes={"subtype": subtype, "repository_scope": SCOPE, "path": node_id}
            )
        )
    estate[1].save_graph(graph)
    return scan_id


def test_semantic_repository_diff_and_new_finding_files(estate):
    old = seed_repository(estate, 7, [("old-package", EntityType.CODE_MODULE, "workspace_package")])
    new = seed_repository(
        estate,
        8,
        [
            ("orders", EntityType.CODE_MODULE, "dbt_model"),
            ("deploy", EntityType.CI_JOB, "gitlab_job"),
            ("main.py", EntityType.SOURCE_FILE, ""),
            ("finding", EntityType.MISCONFIGURATION, ""),
        ],
    )
    graph = estate[1].load_graph(tenant_id=TENANT, scan_id=new)
    graph.add_edge(UnifiedEdge(source="finding", target="main.py", relationship=RelationshipType.AFFECTS))
    estate[1].save_graph(graph)
    with client() as http:
        source = http.get("/v1/graph/changes").json()["sources"][0]
    result = source.get("repository_changes")
    assert result is not None, "Typed repository changes are missing"
    assert result["status"] == "complete"
    assert result["counts"]["workspace_packages"] == {"added": 0, "removed": 1}
    assert result["counts"]["dbt_models"]["added"] == result["counts"]["pipelines"]["added"] == 1
    assert result["files_with_new_findings"]["count"] == 1
    assert result["old_scan_id"] == old and result["new_scan_id"] == new
    assert result["rows"][0]["scan_id"] in {old, new}


@pytest.mark.parametrize("status,ref", [("partial", "refs/heads/main"), ("complete", "refs/heads/other"), ("complete", "unrecorded")])
def test_incomplete_or_different_ref_never_reports_semantic_removal(estate, status, ref):
    seed_repository(estate, 7, [("old-package", EntityType.CODE_MODULE, "workspace_package")])
    seed_repository(estate, 8, [], status=status, ref=ref)
    with client() as http:
        result = http.get("/v1/graph/changes").json()["sources"][0].get("repository_changes")
    assert result is not None and result["status"] == "unavailable"
    assert result.get("counts") is None


def test_first_repository_observation_is_not_an_addition(estate):
    seed_repository(estate, 7, [("package", EntityType.CODE_MODULE, "workspace_package")])
    with client() as http:
        result = http.get("/v1/graph/changes").json()
    assert not result["sources"] and result["new_sources"][0]["reason"] == "first_observation"


def test_semantic_rows_are_bounded_while_counts_remain_exact(estate):
    seed_repository(estate, 7, [])
    seed_repository(estate, 8, [(f"package-{i}", EntityType.CODE_MODULE, "workspace_package") for i in range(35)])
    with client() as http:
        result = http.get("/v1/graph/changes").json()["sources"][0]["repository_changes"]
    assert result["counts"]["workspace_packages"]["added"] == 35
    assert len(result["rows"]) == 30 and result["rows_truncated"]


def test_replaced_snapshot_generation_discards_repository_summary(estate, monkeypatch):
    from agent_bom.api.repository_changes import repository_basis, repository_change_summary

    old = seed_repository(estate, 7, [])
    new = seed_repository(estate, 8, [("main.py", EntityType.SOURCE_FILE, ""), ("finding", EntityType.MISCONFIGURATION, "")])
    store = estate[1]
    graph = store.load_graph(tenant_id=TENANT, scan_id=new)
    graph.add_edge(UnifiedEdge(source="finding", target="main.py", relationship=RelationshipType.AFFECTS))
    store.save_graph(graph)
    read = store.nodes_by_ids

    def replace_during_read(**kwargs):
        nodes = list(read(**kwargs))
        store.save_graph(graph)
        return nodes

    monkeypatch.setattr(store, "nodes_by_ids", replace_during_read)
    result = repository_change_summary(
        store,
        TENANT,
        old,
        new,
        repository_basis(estate[0].get(old, tenant_id=TENANT).result),
        repository_basis(estate[0].get(new, tenant_id=TENANT).result),
        {"status": "comparable"},
    )
    assert result == {"status": "unavailable", "reason": "snapshot_generation_changed"}
