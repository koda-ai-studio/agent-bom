"""Repository workspace identities are local, bounded and distinct from dependencies."""

from __future__ import annotations

import json
from pathlib import Path

from agent_bom.parsers import summarize_project_inventory


def put(root: Path, path: str, value: str | dict) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value) if isinstance(value, dict) else value)


def context(root: Path) -> dict:
    return summarize_project_inventory(root, {})["repository_context"]


def test_workspace_members_have_scoped_stable_first_party_ids_and_owners(tmp_path):
    put(tmp_path, "package.json", {"name": "root", "workspaces": ["apps/*"]})
    put(tmp_path, "apps/api/package.json", {"name": "@example/api", "dependencies": {"openai": "^1", "@example/lib": "workspace:*"}})
    put(tmp_path, "pnpm-workspace.yaml", "packages:\n  - libs/*\n  - '!libs/excluded'\n")
    put(tmp_path, "libs/core/package.json", {"name": "@example/lib"})
    put(tmp_path, "libs/excluded/package.json", {"name": "excluded"})
    put(tmp_path, "orphan/package.json", {"name": "not-a-member"})
    put(tmp_path, ".github/CODEOWNERS", "* @default\n/apps/api/ @api\n")
    first = context(tmp_path)
    packages = {p["name"]: p for p in first["workspace_packages"]}
    assert set(packages) == {"root", "@example/api", "@example/lib"}
    api = packages["@example/api"]
    assert api["path"] == "apps/api" and api["first_party"] is True
    assert api["owners"] == ["@api"] and api["owner_source"] == ".github/CODEOWNERS"
    assert api["declared_dependencies"] == ["@example/lib", "openai"]
    assert "^1" not in json.dumps(api)
    assert first["status"] == "complete"
    assert first == context(tmp_path)
    other = tmp_path / "other"
    put(other, "package.json", {"name": "root"})
    assert context(other)["scope_id"] != first["scope_id"]
    assert context(other)["workspace_packages"][0]["id"] != packages["root"]["id"]


def test_uv_cargo_go_workspaces_and_exclusions(tmp_path):
    put(tmp_path, "pyproject.toml", '[tool.uv.workspace]\nmembers=["python/*"]\nexclude=["python/no"]\n')
    put(tmp_path, "python/yes/pyproject.toml", '[project]\nname="Local.Python"\ndependencies=["openai>=1"]\n')
    put(tmp_path, "python/no/pyproject.toml", '[project]\nname="excluded"\n')
    put(tmp_path, "Cargo.toml", '[workspace]\nmembers=["crates/*"]\nexclude=["crates/no"]\n')
    put(tmp_path, "crates/yes/Cargo.toml", '[package]\nname="engine"\n[dependencies]\nserde="1"\n')
    put(tmp_path, "crates/no/Cargo.toml", '[package]\nname="excluded"\n')
    put(tmp_path, "go.work", "go 1.22\nuse (\n ./go/one\n)\nuse ./go/two\n")
    for name in ["one", "two"]:
        put(tmp_path, f"go/{name}/go.mod", f"module example.test/{name}\ngo 1.22\nrequire example.test/dep v1.0.0\n")
    packages = context(tmp_path)["workspace_packages"]
    assert {(p["ecosystem"], p["name"]) for p in packages} == {
        ("pypi", "local-python"),
        ("cargo", "engine"),
        ("go", "example.test/one"),
        ("go", "example.test/two"),
    }
    assert next(p for p in packages if p["ecosystem"] == "pypi")["declared_dependencies"] == ["openai"]


def test_workspace_rejects_escapes_symlinks_and_invalid_metadata(tmp_path):
    root = tmp_path / "repo"
    put(root, "package.json", {"workspaces": ["../outside", "link", "bad"]})
    put(tmp_path, "outside/package.json", {"name": "outside"})
    (root / "link").symlink_to(tmp_path / "outside", target_is_directory=True)
    put(root, "bad/package.json", "{")
    result = context(root)
    assert result["workspace_packages"] == []
    assert result["status"] == "partial"
    assert {r["reason"] for r in result["unresolved"]} >= {"invalid_workspace_path", "invalid_or_unreadable_artifact"}
    assert str(tmp_path) not in json.dumps(result)


def test_workspace_records_nx_turbo_gap_and_does_not_execute_config(tmp_path):
    put(tmp_path, "package.json", {"name": "root"})
    put(tmp_path, "nx.json", {})
    put(tmp_path, "turbo.json", {})
    result = context(tmp_path)
    assert result["coverage"]["nx"] == "package_manifests_only"
    assert result["coverage"]["turbo"] == "package_manifests_only"


def test_graph_workspace_membership_is_scoped_and_has_no_third_party_fanout(tmp_path):
    from agent_bom.graph.builder import build_unified_graph_from_report
    from agent_bom.graph.types import EntityType, RelationshipType

    put(tmp_path, "package.json", {"name": "root", "workspaces": ["apps/*"]})
    put(tmp_path, "apps/api/package.json", {"name": "api", "dependencies": {"openai": "1"}})
    put(tmp_path, "apps/web/package.json", {"name": "web", "dependencies": {"api": "workspace:*"}})
    inventory = summarize_project_inventory(tmp_path, {tmp_path: [], tmp_path / "apps/api": [], tmp_path / "apps/web": []})
    report = {"scan_id": "local", "agents": [], "project_inventory": inventory}
    graph = build_unified_graph_from_report(report)
    members = {n.label: n for n in graph.nodes.values() if n.attributes.get("subtype") == "workspace_package"}
    assert set(members) == {"root", "api", "web"}
    assert all(n.entity_type == EntityType.CODE_MODULE for n in members.values())
    assert all(n.attributes["repository_scope"] == inventory["repository_context"]["scope_id"] for n in members.values())
    assert any(
        e.source == members["web"].id and e.target == members["api"].id and e.relationship == RelationshipType.DEPENDS_ON
        for e in graph.edges
    )
    assert not any(n.label == "openai" for n in graph.nodes.values())  # declaration is not a resolved third-party inventory package
    assert not any(n.id == "directory:." for n in graph.nodes.values())
    assert all(n.attributes.get("repository_scope") for n in graph.nodes.values() if n.entity_type == EntityType.DIRECTORY)
    assert len(graph.edges) == len({e.id for e in graph.edges})
    other = tmp_path / "copy"
    put(other, "package.json", {"name": "root"})
    second = build_unified_graph_from_report(
        {"scan_id": "other", "agents": [], "project_inventory": summarize_project_inventory(other, {other: []})}
    )
    assert not (set(graph.nodes) & set(second.nodes))


def test_repository_reader_limits_bytes_members_and_enumeration(tmp_path, monkeypatch):
    from agent_bom.parsers.repository import artifacts, workspaces

    put(tmp_path, "package.json", {"name": "root", "workspaces": ["apps/**"]})
    for i in range(5):
        put(tmp_path, f"apps/p{i}/package.json", {"name": f"p{i}"})
    monkeypatch.setattr(workspaces, "MAX_PACKAGES", 2)
    capped = context(tmp_path)
    assert len(capped["workspace_packages"]) == 2 and capped["status"] == "partial"
    assert any(r["reason"] == "workspace_package_limit" for r in capped["unresolved"])
    monkeypatch.setattr(artifacts, "MAX_ENTRIES", 3)
    assert any(r["reason"] == "entry_limit" for r in context(tmp_path)["unresolved"])
    reader = artifacts.RepositoryReader(tmp_path)
    assert reader.read("package.json", max_bytes=4) is None
    assert reader.unresolved[0]["reason"] == "invalid_or_unreadable_artifact"
    assert reader.read("../outside") is None


def test_workspace_graph_reuses_exact_dependencies_and_file_findings(tmp_path):
    from datetime import datetime, timezone

    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.edge import UnifiedEdge
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.repo_structure_overlay import apply_repo_structure_overlay
    from agent_bom.graph.types import EntityType, RelationshipType
    from agent_bom.graph.workspace_overlay import apply_workspace_overlay

    put(tmp_path, "package.json", {"workspaces": ["apps/*"]})
    for name in ["a", "b"]:
        put(tmp_path, f"apps/{name}/package.json", {"name": name, "dependencies": {"openai": "1"} if name == "a" else {}})
    inv = summarize_project_inventory(tmp_path, {tmp_path / "apps/a": [], tmp_path / "apps/b": []})
    report = {"project_inventory": inv}
    now = datetime(2026, 11, 1, tzinfo=timezone.utc)
    graph = UnifiedGraph(scan_id="repo", tenant_id="one")
    graph.add_node(
        UnifiedNode(id="finding", entity_type=EntityType.MISCONFIGURATION, label="finding", attributes={"file_path": "apps/a/main.py"})
    )
    apply_repo_structure_overlay(graph, report, now)
    manifest = next(n for n in graph.nodes.values() if n.attributes.get("path") == "apps/a/package.json")
    graph.add_node(
        UnifiedNode(id="third-party", entity_type=EntityType.PACKAGE, label="openai@1", attributes={"name": "openai", "ecosystem": "npm"})
    )
    graph.add_edge(
        UnifiedEdge(
            source=manifest.id,
            target="third-party",
            relationship=RelationshipType.DEPENDS_ON,
            evidence={"tier": "static_scan", "source": "fixture"},
        )
    )
    apply_workspace_overlay(graph, report, now)
    workspaces = {n.label: n.id for n in graph.nodes.values() if n.attributes.get("subtype") == "workspace_package"}
    assert any(e.source == workspaces["a"] and e.target == "third-party" for e in graph.edges)
    assert not any(e.source == workspaces["b"] and e.target == "third-party" for e in graph.edges)
    assert any(e.source == "finding" and e.target == workspaces["a"] for e in graph.edges)
    assert not any(e.source == "finding" and e.target == workspaces["b"] for e in graph.edges)
    original = (set(graph.nodes), {e.id for e in graph.edges})
    apply_workspace_overlay(graph, report, now)
    assert original == (set(graph.nodes), {e.id for e in graph.edges})
    from agent_bom.graph.rollup import rollup_view

    rolled = rollup_view(graph)
    assert len(rolled["top_level"]) < len(graph.nodes)


def test_same_name_dependency_does_not_prove_workspace_resolution(tmp_path):
    from agent_bom.graph.builder import build_unified_graph_from_report

    put(tmp_path, "package.json", {"workspaces": ["packages/*"]})
    put(tmp_path, "packages/local/package.json", {"name": "shared"})
    put(tmp_path, "packages/consumer/package.json", {"name": "consumer", "dependencies": {"shared": "^2.0.0"}})
    graph = build_unified_graph_from_report({"agents": [], "project_inventory": summarize_project_inventory(tmp_path, {})})
    members = {n.label: n.id for n in graph.nodes.values() if n.attributes.get("subtype") == "workspace_package"}
    assert not any(e.source == members["consumer"] and e.target == members["shared"] for e in graph.edges)


def test_local_path_dependencies_are_exact_and_do_not_escape(tmp_path):
    from agent_bom.graph.builder import build_unified_graph_from_report

    put(tmp_path, "Cargo.toml", '[workspace]\nmembers=["crates/*"]\n')
    put(tmp_path, "crates/a/Cargo.toml", '[package]\nname="a"\n[dependencies]\nb={path="../b"}\noutside={path="../../../outside"}\n')
    put(tmp_path, "crates/b/Cargo.toml", '[package]\nname="b"\n')
    inventory = summarize_project_inventory(tmp_path, {})
    records = {r["name"]: r for r in inventory["repository_context"]["workspace_packages"]}
    assert records["a"]["local_dependency_paths"] == {"b": "crates/b"}
    graph = build_unified_graph_from_report({"agents": [], "project_inventory": inventory})
    assert any(e.source == records["a"]["id"] and e.target == records["b"]["id"] for e in graph.edges)


def test_truncated_declarations_remain_explicitly_partial(tmp_path):
    put(tmp_path, "package.json", {"name": "root", "dependencies": {f"dep{i}": "1" for i in range(1001)}})
    result = context(tmp_path)
    assert len(result["workspace_packages"][0]["declared_dependencies"]) == 1000
    assert result["status"] == "partial"
    assert any(row["reason"] == "declaration_limit" for row in result["unresolved"])


def test_go_dependency_workspace_cannot_follow_outside_or_symlink_members(tmp_path):
    from agent_bom.parsers import parse_go_workspace

    root = tmp_path / "repo"
    put(root, "go.work", "go 1.22\nuse (\n ../outside\n ./linked\n)\n")
    put(tmp_path, "outside/go.mod", "module example.test/outside\ngo 1.22\nrequire example.test/should-not-read v1.2.3\n")
    (root / "linked").symlink_to(tmp_path / "outside", target_is_directory=True)
    assert parse_go_workspace(root) == []
