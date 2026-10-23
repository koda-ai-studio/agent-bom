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


def test_group_reports_every_package_version_its_occurrences_carry():
    container = {**_row("image-1", None, [], "pkg:npm:ws@8.17.0:image:a"), "package": "ws@8.17.0", "cve_id": "CVE-2024-37890"}
    server = {
        **_row("agent-1", ["cursor"], ["filesystem-server"], "pkg:npm:ws@8.5.0"),
        "package": "ws@8.5.0",
        "package_version": "8.5.0",
        "cve_id": "CVE-2024-37890",
    }
    groups = _group_occurrence_rows([container, {**container, "finding_id": "image-2", "id": "image-2"}, server])
    assert len(groups) == 1
    assert groups[0]["package_versions"] == ["8.17.0", "8.5.0"]
    assert groups[0]["affected_agents"] == ["cursor"]


def test_group_keeps_versions_when_a_worse_occurrence_becomes_representative():
    low = {**_row("a", None, None, "pkg:a"), "package": "pillow@9.0.0", "severity": "low"}
    high = {**_row("b", None, None, "pkg:b"), "package": "pillow@9.1.0", "severity": "critical"}
    groups = _group_occurrence_rows([low, high])
    assert groups[0]["severity"] == "critical"
    assert groups[0]["package_versions"] == ["9.0.0", "9.1.0"]


def test_serialized_group_exposes_package_versions():
    from agent_bom.api.finding_list_helpers import _serialize_finding_group

    rows = [{**_row("a", None, None, "pkg:a"), "package": "ws@8.17.0"}, {**_row("b", ["cursor"], None, "pkg:b"), "package": "ws@8.5.0"}]
    public = _serialize_finding_group(_group_occurrence_rows(rows)[0])
    assert public["package_versions"] == ["8.17.0", "8.5.0"]
    assert public["package_version_count"] == 2


def test_mixed_version_group_title_names_every_version_not_one():
    """52 occurrences across 8.17.0 and 8.5.0 must not be titled after the one 8.5.0 row."""
    from agent_bom.api.finding_list_helpers import _serialize_finding_group

    image_rows = [
        {**_row(f"image-{i}", None, None, f"pkg:npm:ws@8.17.0:image:{i}"), "package": "ws@8.17.0", "cve_id": "CVE-2024-37890"}
        for i in range(51)
    ]
    server = {
        **_row("agent-1", ["cursor"], ["filesystem-server"], "pkg:npm:ws@8.5.0"),
        "package": "ws@8.5.0",
        "package_version": "8.5.0",
        "cve_id": "CVE-2024-37890",
        "severity": "critical",
        "title": "CVE-2024-37890: ws@8.5.0",
    }
    public = _serialize_finding_group(_group_occurrence_rows([*image_rows, server])[0])

    assert public["occurrence_count"] == 52
    assert public["package_version_count"] == 2
    assert public["title"] == "CVE-2024-37890: ws · 2 versions"
    assert "8.5.0" not in public["title"]


def test_single_version_group_title_keeps_its_version():
    from agent_bom.api.finding_list_helpers import _serialize_finding_group

    rows = [{**_row(f"a{i}", None, None, f"pkg:a{i}"), "package": "ws@8.17.0", "title": "CVE-2024-37890: ws@8.17.0"} for i in range(3)]
    public = _serialize_finding_group(_group_occurrence_rows(rows)[0])
    assert public["title"] == "CVE-2024-37890: ws@8.17.0"
