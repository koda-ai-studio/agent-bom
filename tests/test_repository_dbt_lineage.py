"""Local dbt lineage remains bounded, source-attributed and account-safe."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.parsers import summarize_project_inventory


def put(root: Path, path: str, data: str | dict) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(data) if isinstance(data, dict) else data)


def manifest() -> dict:
    def node(key, kind, name, path, parents=()):
        return {
            "unique_id": key,
            "resource_type": kind,
            "name": name,
            "original_file_path": path,
            "relation_name": f'"Analytics"."Public"."{name}"',
            "depends_on": {"nodes": list(parents)},
            "raw_code": "do not retain compiled or source SQL",
            "meta": {"token": "test-placeholder-value"},
        }

    return {
        "metadata": {
            "dbt_schema_version": "https://schemas.getdbt.com/dbt/manifest/v12.json",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "adapter_type": "snowflake",
        },
        "nodes": {
            "model.shop.orders": node("model.shop.orders", "model", "Orders", "models/orders.sql", ["source.shop.raw"]),
            "seed.shop.countries": node("seed.shop.countries", "seed", "Countries", "seeds/countries.csv"),
        },
        "sources": {"source.shop.raw": node("source.shop.raw", "source", "Raw", "models/schema.yml")},
        "exposures": {
            "exposure.shop.dashboard": node("exposure.shop.dashboard", "exposure", "Dashboard", "models/schema.yml", ["model.shop.orders"])
        },
    }


def collect(root: Path, value: dict) -> dict:
    put(root, "dbt_project.yml", "name: shop\nprofile: shop\n")
    put(root, "target/manifest.json", value)
    return summarize_project_inventory(root, {})["repository_context"]["dbt"]


def test_local_manifest_keeps_lineage_and_provenance_without_sql_or_secret_values(tmp_path):
    put(
        tmp_path,
        "profiles.yml",
        "shop:\n  target: dev\n  outputs:\n    dev:\n      type: snowflake\n"
        "      account: account-one\n      password: never-copy-this-placeholder\n",
    )
    result = collect(tmp_path, manifest())
    assert result["status"] == "complete"
    assert result["freshness"] == "current" and result["snowflake_account"] == "account-one"
    assert {n["kind"] for n in result["nodes"]} == {"model", "source", "seed", "exposure"}
    assert {(e["source"], e["target"]) for e in result["edges"]} == {
        ("model.shop.orders", "source.shop.raw"),
        ("exposure.shop.dashboard", "model.shop.orders"),
    }
    assert result["artifact"] == "target/manifest.json" and len(result["digest"]) == 64
    assert "never-copy" not in json.dumps(result) and "raw_code" not in json.dumps(result) and "test-placeholder" not in json.dumps(result)


def test_manifest_unknown_version_stale_missing_cycle_and_paths_are_explicit(tmp_path):
    data = manifest()
    data["metadata"]["dbt_schema_version"] = "https://schemas.getdbt.com/dbt/manifest/v999.json"
    unsupported = collect(tmp_path, data)
    assert unsupported["status"] == "unavailable" and unsupported["nodes"] == []
    data = manifest()
    data["metadata"]["generated_at"] = "2010-01-01T00:00:00Z"
    data["nodes"]["model.shop.orders"]["depends_on"]["nodes"] += ["model.missing"]
    data["sources"]["source.shop.raw"]["depends_on"]["nodes"] = ["model.shop.orders"]
    data["nodes"]["seed.shop.countries"]["original_file_path"] = "../outside.csv"
    result = collect(tmp_path, data)
    assert result["status"] == "partial" and result["freshness"] == "stale"
    assert {r["reason"] for r in result["unresolved"]} >= {"missing_parent", "cycle", "invalid_source_path"}
    assert not any(e["target"] == "model.missing" for e in result["edges"])
    assert not any((n.get("path") or "").startswith("..") for n in result["nodes"])


def test_dynamic_account_does_not_resolve_environment_or_read_home(tmp_path, monkeypatch):
    put(
        tmp_path,
        "profiles.yml",
        "shop:\n  target: dev\n  outputs:\n    dev:\n      type: snowflake\n      account: \"{{ env_var('ACCOUNT') }}\"\n",
    )
    monkeypatch.setenv("ACCOUNT", "must-not-be-used")
    result = collect(tmp_path, manifest())
    assert result["snowflake_account"] is None
    assert any(r["reason"] == "account_unresolved" for r in result["unresolved"])
    assert "must-not-be-used" not in json.dumps(result)


def test_dbt_graph_keeps_quoted_names_and_matches_only_current_tenant_account(tmp_path):
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.types import RelationshipType

    put(tmp_path, "profiles.yml", "shop:\n  target: dev\n  outputs:\n    dev:\n      type: snowflake\n      account: account-one\n")
    collect(tmp_path, manifest())
    report = {
        "project_inventory": summarize_project_inventory(tmp_path, {}),
        "agents": [],
        "snowflake_object_graph": {
            "status": "ok",
            "account": "account-one",
            "objects": [
                {"fqn": "Analytics.Public.Orders", "database": "Analytics", "schema": "Public", "object_type": "TABLE"},
                {"fqn": "ANALYTICS.PUBLIC.ORDERS", "database": "ANALYTICS", "schema": "PUBLIC", "object_type": "TABLE"},
            ],
        },
        "iac_findings": {
            "findings": [
                {
                    "rule_id": "DBT-SEC-011",
                    "category": "dbt",
                    "title": "Raw variable",
                    "file_path": "models/orders.sql",
                    "line_number": 1,
                    "severity": "high",
                }
            ]
        },
    }
    graph = build_unified_graph_from_report(report, tenant_id="tenant-one")
    model = next(n for n in graph.nodes.values() if n.attributes.get("dbt_unique_id") == "model.shop.orders")
    matches = [e for e in graph.edges if e.source == model.id and e.relationship == RelationshipType.CORRELATES_WITH]
    assert len(matches) == 1
    target = graph.nodes[matches[0].target]
    assert target.attributes["fqn"] == "Analytics.Public.Orders"
    assert matches[0].traversable is False
    assert any(e.target == model.id and e.relationship == RelationshipType.BELONGS_TO for e in graph.edges)
    assert model.attributes["connector_match_status"] == "matched"
    report["snowflake_object_graph"]["account"] = "account-two"
    wrong = build_unified_graph_from_report(report, tenant_id="tenant-one")
    assert not any(e.relationship == RelationshipType.CORRELATES_WITH for e in wrong.edges)
    assert not any(e.relationship == RelationshipType.CORRELATES_WITH for e in build_unified_graph_from_report(report).edges)


def test_connector_tuple_collision_and_foreign_tenant_are_not_matches(tmp_path):
    from agent_bom.graph.builder_overlays import _apply_repo_structure_overlay
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType, RelationshipType

    put(tmp_path, "profiles.yml", "shop:\n  target: dev\n  outputs:\n    dev:\n      type: snowflake\n      account: account-one\n")
    value = manifest()
    value["nodes"]["model.shop.orders"]["relation_name"] = '"A.B"."C"."D"'
    collect(tmp_path, value)
    graph = UnifiedGraph(scan_id="s", tenant_id="one")
    for key, db, schema, tenant in [("wrong-parts", "A", "B.C", "one"), ("wrong-tenant", "A.B", "C", "two")]:
        graph.add_node(
            UnifiedNode(
                id=key,
                entity_type=EntityType.DATA_STORE,
                label=key,
                attributes={
                    "cloud_provider": "snowflake",
                    "account_id": "account-one",
                    "fqn": "A.B.C.D",
                    "database": db,
                    "schema": schema,
                    "tenant_id": tenant,
                },
            )
        )
    _apply_repo_structure_overlay(graph, {"project_inventory": summarize_project_inventory(tmp_path, {})})
    assert any(n.attributes.get("dbt_unique_id") == "model.shop.orders" for n in graph.nodes.values())
    assert not any(e.relationship == RelationshipType.CORRELATES_WITH for e in graph.edges)


def test_manifest_limits_and_malformed_rows_do_not_become_clean_or_raise(tmp_path, monkeypatch):
    from agent_bom.parsers.repository import dbt

    data = manifest()
    monkeypatch.setattr(dbt, "MAX_NODES", 2)
    bounded = collect(tmp_path, data)
    assert len(bounded["nodes"]) == 2 and bounded["status"] == "partial"
    assert bounded["unresolved_counts"]["node_limit"] == 1
    monkeypatch.setattr(dbt, "MAX_NODES", 2000)
    data["nodes"]["model.shop.orders"]["resource_type"] = {"poison": "value"}
    poisoned = collect(tmp_path, data)
    assert poisoned["status"] == "partial"
    data = manifest()
    data["sources"] = []
    invalid = collect(tmp_path, data)
    assert invalid["status"] == "partial"


def test_ambiguous_or_stale_connector_and_shared_yaml_findings_do_not_fan_out(tmp_path):
    from agent_bom.graph.builder_overlays import _apply_repo_structure_overlay
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType, RelationshipType

    put(tmp_path, "profiles.yml", "shop:\n  target: dev\n  outputs:\n    dev:\n      type: snowflake\n      account: account-one\n")
    collect(tmp_path, manifest())
    graph = UnifiedGraph(scan_id="s", tenant_id="one")
    for key in ["same-object-one", "same-object-two"]:
        graph.add_node(
            UnifiedNode(
                id=key,
                entity_type=EntityType.DATA_STORE,
                label=key,
                attributes={
                    "cloud_provider": "snowflake",
                    "account_id": "account-one",
                    "fqn": "Analytics.Public.Orders",
                    "database": "Analytics",
                    "schema": "Public",
                },
            )
        )
    graph.add_node(
        UnifiedNode(
            id="yaml-finding",
            entity_type=EntityType.MISCONFIGURATION,
            label="finding",
            attributes={"category": "dbt", "file_path": "models/schema.yml"},
        )
    )
    inv = summarize_project_inventory(tmp_path, {})
    _apply_repo_structure_overlay(graph, {"project_inventory": inv})
    assert not any(e.relationship == RelationshipType.CORRELATES_WITH for e in graph.edges)
    assert not any(e.source == "yaml-finding" and e.relationship == RelationshipType.BELONGS_TO for e in graph.edges)
    assert graph.nodes["yaml-finding"].attributes["dbt_link_status"] == "ambiguous_source_file"
    model = next(n for n in graph.nodes.values() if n.attributes.get("dbt_unique_id") == "model.shop.orders")
    assert model.attributes["connector_match_status"] == "ambiguous"
    graph2 = UnifiedGraph(scan_id="s", tenant_id="one")
    graph2.add_node(graph.nodes["same-object-one"])
    inv["repository_context"]["dbt"]["freshness"] = "stale"
    _apply_repo_structure_overlay(graph2, {"project_inventory": inv})
    assert not any(e.relationship == RelationshipType.CORRELATES_WITH for e in graph2.edges)


def test_qualified_identifiers_preserve_boundaries_escapes_and_spaces():
    from agent_bom.graph.dbt_identity import qualified_parts

    assert qualified_parts('"A.B"."C"."D"') != qualified_parts('"A"."B.C"."D"')
    assert qualified_parts('"A"."B"." D "') == ("A", "B", " D ")
    assert qualified_parts('db.public."O""rders"') == ("DB", "PUBLIC", 'O"rders')
    assert qualified_parts('"A"."B"."unclosed') is None
    assert qualified_parts("db.public.orders; DROP") is None


def assert_repository_store_parity(tmp_path, backend="sqlite"):
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.dbt_overlay import apply_dbt_overlay
    from agent_bom.graph.pipeline_overlay import apply_pipeline_overlay
    from agent_bom.graph.sdk_overlay import apply_sdk_overlay
    from agent_bom.graph.store_backed import open_store_backed_unified_graph
    from agent_bom.graph.workspace_overlay import apply_workspace_overlay

    collect(tmp_path, manifest())
    put(tmp_path, "package.json", {"name": "first-party", "version": "1.0.0"})
    put(tmp_path, ".gitlab-ci.yml", "build:\n  script: echo safe\ndeploy:\n  needs: [build]\n  script: echo safe\n")
    put(tmp_path, "app/main.py", "from agents import Agent\nassistant = Agent(name='demo')\n")
    report = {"project_inventory": summarize_project_inventory(tmp_path, {})}
    now = datetime.now(timezone.utc)
    expected = UnifiedGraph(tenant_id="repository-parity")
    with open_store_backed_unified_graph(tenant_id="repository-parity", backend=backend, capacity=2, page_size=2) as actual:
        for graph in (expected, actual):
            for _ in range(2):
                apply_pipeline_overlay(graph, report, now)
                apply_sdk_overlay(graph, report, now)
                apply_workspace_overlay(graph, report, now)
                apply_dbt_overlay(graph, report, now)
        assert {n.id: n.to_dict() for n in actual.nodes.values()} == {n.id: n.to_dict() for n in expected.nodes.values()}

        def key(e):
            return e.source, e.target, e.relationship.value

        assert {key(e): e.to_dict() for e in actual.edges} == {key(e): e.to_dict() for e in expected.edges}


def test_repository_overlays_preserve_mutations_with_two_node_cache(tmp_path):
    assert_repository_store_parity(tmp_path)


def test_invalid_parent_is_partial_evidence(tmp_path):
    data = manifest()
    data["nodes"]["model.shop.orders"]["depends_on"]["nodes"].append({"bad": "parent"})
    result = collect(tmp_path, data)
    assert result["status"] == "partial"
    assert result["unresolved_counts"]["invalid_parent"] == 1
