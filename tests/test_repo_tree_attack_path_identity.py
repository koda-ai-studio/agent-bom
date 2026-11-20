"""A manifest is one path identity: the repository file tree draws it, the inventory tree carries its attack paths."""

from __future__ import annotations

from collections import Counter
from typing import Any

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.path_derivation import _derived_attack_paths
from agent_bom.graph.types import RelationshipType


def _pkg(name: str, version: str, cve: str) -> dict[str, Any]:
    return {
        "name": name,
        "version": version,
        "ecosystem": "pypi",
        "is_direct": True,
        "vulnerabilities": [{"id": cve, "severity": "high", "cvss_score": 7.5}],
    }


def _directory(path: str) -> dict[str, Any]:
    files = ["requirements.txt"]
    return {"path": path, "package_count": 1, "direct_packages": 1, "manifest_files": files, "declaration_files": files}


def _report() -> dict[str, Any]:
    return {
        "agents": [
            {
                "name": "project:demo",
                "agent_type": "custom",
                "type": "custom",
                "source": "project",
                "config_path": "<path:demo>",
                "mcp_servers": [
                    {"name": "demo", "command": "project", "surface": "other", "packages": [_pkg("pyyaml", "5.3", "CVE-2020-14343")]},
                    {"name": "svc", "command": "project", "surface": "other", "packages": [_pkg("urllib3", "1.24.1", "CVE-2019-11324")]},
                ],
            }
        ],
        "project_inventory": {
            "root": "<path:demo>",
            "repository_context": {"version": 1, "scope_id": "a" * 64, "identity_basis": "local_root", "status": "complete"},
            "directories": [_directory("."), _directory("svc")],
        },
        "scan_sources": ["agent_discovery"],
    }


def test_each_vulnerable_occurrence_yields_one_path_not_one_per_tree() -> None:
    graph = build_unified_graph_from_report(_report())
    repo_files = [nid for nid in graph.nodes if nid.startswith("repo:config_file:")]
    assert len(repo_files) == 2, "the file tree is still drawn"
    drawn = [e for e in graph.edges if e.source in repo_files and e.relationship == RelationshipType.DEPENDS_ON]
    assert {e.target for e in drawn} == {"pkg:pypi:pyyaml@5.3", "pkg:pypi:urllib3@1.24.1"}

    paths = [p for p in _derived_attack_paths(graph) if p.target.startswith("vuln:")]
    per_finding = Counter(p.target for p in paths)
    assert per_finding == {"vuln:CVE-2020-14343": 1, "vuln:CVE-2019-11324": 1}
    assert not [p.source for p in paths if p.source.startswith("repo:")]
