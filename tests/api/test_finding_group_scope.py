"""A grouped issue row names every agent and server its occurrences affect, not only its representative's."""

from __future__ import annotations

from agent_bom.api.finding_grouping import _group_occurrence_rows


def _row(finding_id: str, agents: list[str] | None, servers: list[str] | None, node: str) -> dict:
    return {
        "id": finding_id,
        "finding_id": finding_id,
        "cve_id": "CVE-2023-4863",
        "vulnerability_id": "CVE-2023-4863",
        "package": "pillow@9.0.0",
        "severity": "high",
        "node_id": node,
        "affected_agents": agents,
        "affected_servers": servers,
    }


def test_group_unions_agents_and_servers_across_occurrences():
    rows = [
        _row("image-1", None, [], "pkg:pypi:pillow@9.0.0:image:a"),
        _row("agent-1", ["data-pipeline"], ["etl-server"], "pkg:pypi:pillow@9.0.0"),
        _row("agent-2", ["data-pipeline", "cursor"], ["etl-server"], "pkg:pypi:pillow@9.0.0"),
    ]
    groups = _group_occurrence_rows(rows)
    assert len(groups) == 1
    group = groups[0]
    assert group["finding_id"] == "image-1"
    assert group["affected_agents"] == ["data-pipeline", "cursor"]
    assert group["affected_servers"] == ["etl-server"]
    assert group["occurrence_count"] == 3


def test_group_without_any_agent_stays_empty():
    groups = _group_occurrence_rows([_row("image-1", None, None, "pkg:a"), _row("image-2", [], [], "pkg:b")])
    assert groups[0]["affected_agents"] == []
    assert groups[0]["affected_servers"] == []
