"""Every surface's count for one metric comes from one source on the demo estate.

The overview, the nav badges, the findings page (in every sort order), posture,
the graph roll-up and remediation are read against one seeded estate. Where two
surfaces report the same metric in the same unit and scope, the numbers must be
equal. Where they differ in unit (issues vs occurrences) or scope (this host vs
the estate), each response must say which one it carries.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests._demo_estate_fixtures import VIEWER

_BANDS = ("critical", "high", "medium", "low")
_FINDINGS_SORTS = ("effective_reach", "severity", "cvss")


def _get(client: TestClient, path: str, **params: object) -> dict:
    response = client.get(path, headers=VIEWER, params=params)
    assert response.status_code == 200, (path, response.text)
    return response.json()


def _grouped_findings(client: TestClient, sort: str) -> dict:
    return _get(client, "/v1/findings", group_occurrences="true", include_facets="true", limit=1, sort=sort)


def _bands(counts: dict) -> dict[str, int]:
    return {band: int(counts.get(band) or 0) for band in _BANDS}


def _surfaces(client: TestClient) -> dict[str, dict]:
    return {
        "counts": _get(client, "/v1/posture/counts"),
        "overview": _get(client, "/v1/overview"),
        "posture": _get(client, "/v1/posture"),
        "rollup": _get(client, "/v1/graph/rollup"),
        "remediation": _get(client, "/v1/findings/remediation"),
        "agents": _get(client, "/v1/agents"),
        "snapshots": {"rows": _get(client, "/v1/graph/snapshots")},
        "graph": _get(client, "/v1/graph", limit=1),
        **{f"findings:{sort}": _grouped_findings(client, sort) for sort in _FINDINGS_SORTS},
    }


def _check_issue_severity_is_one_number_on_every_surface(surfaces: dict[str, dict]) -> None:
    issues = surfaces["counts"]["issues"]
    assert issues["basis"] == "issue_groups"
    expected = _bands(issues)
    assert sum(expected.values()) > 0
    assert _bands(surfaces["overview"]["issue_counts"]) == expected
    assert _bands(surfaces["rollup"]["summary"]["issue_severity_counts"]) == expected
    for sort in _FINDINGS_SORTS:
        page = surfaces[f"findings:{sort}"]
        assert page["total"] == issues["total"], sort
        assert _bands(page["facets"]["severity"]) == expected, f"findings sorted by {sort} disagree with the overview"


def _check_occurrence_counts_are_labelled_as_a_different_unit(surfaces: dict[str, dict]) -> None:
    overview = surfaces["overview"]
    issues, occurrences = overview["issue_counts"], overview["finding_counts"]
    assert overview["posture"]["severity_basis"] == "issue_groups"
    assert occurrences["total"] >= issues["total"]
    assert surfaces["rollup"]["summary"]["severity_basis"] == "issue_groups"
    assert surfaces["rollup"]["summary"]["finding_occurrence_count"] == occurrences["total"]
    for lane in overview["coverage"]:
        assert sum(lane["severity"].values()) == lane["count"], lane["domain"]


def _check_kev_uses_the_issue_unit_beside_the_issue_tiles(surfaces: dict[str, dict], client: TestClient) -> None:
    kev_issues = surfaces["counts"]["issues"]["kev"]
    assert surfaces["overview"]["issue_counts"]["kev"] == kev_issues
    filtered = _get(client, "/v1/findings", group_occurrences="true", kev="true", limit=1)
    assert filtered["total"] == kev_issues
    assert surfaces["overview"]["finding_counts"]["kev"] >= kev_issues
    summary = surfaces["overview"]["posture"]["summary"]
    if kev_issues:
        assert f"{kev_issues:,} KEV" in summary
    assert surfaces["posture"]["summary"] == summary


def _check_open_cve_findings_agree_between_overview_and_posture(surfaces: dict[str, dict]) -> None:
    domain = surfaces["overview"]["domains"]["vuln"]
    dimensions = surfaces["posture"]["dimensions_basis"]
    assert domain["count_exact"] is True
    assert domain["metric"] == dimensions["vulnerability_findings"]
    details = surfaces["posture"]["dimensions"]["vulnerability_posture"]["details"]
    assert details.startswith(f"{dimensions['vulnerability_findings']} vulnerability occurrences")


def _check_vuln_card_equals_its_drill_down(surfaces: dict[str, dict], client: TestClient) -> None:
    """The overview Vuln / SCA card and the findings page it links to count one set."""
    from urllib.parse import parse_qsl, urlsplit

    domain = surfaces["overview"]["domains"]["vuln"]
    link = urlsplit(domain["href"])
    assert link.path == "/findings"
    params = dict(parse_qsl(link.query))
    api_params = {("finding_class" if key == "issue" else key): value for key, value in params.items()}
    linked = _get(client, "/v1/findings", limit=1, include_facets="true", **api_params)
    assert domain["metric"] > 0
    assert linked["total"] == domain["metric"], (domain["href"], linked["total"], domain["metric"])
    assert _bands(linked["facets"]["severity"]) == _bands(domain["detail"]["severity"])
    by_domain = _get(client, "/v1/findings", limit=1, include_facets="true", domain="vuln")
    assert by_domain["total"] == domain["metric"], ("domain=vuln", by_domain["total"], domain["metric"])
    domain_facet = linked["facets"].get("domain") or linked["facets"].get("security_domain") or {}
    if domain_facet:
        assert domain_facet.get("vuln") == domain["metric"], domain_facet


def _check_remediation_reads_the_findings_window(surfaces: dict[str, dict]) -> None:
    findings_window = surfaces["findings:severity"]["window"]
    remediation_window = surfaces["remediation"]["window"]
    assert remediation_window["days"] == findings_window["days"]
    assert remediation_window["label"] == findings_window["label"]


def _check_graph_snapshot_severity_names_its_unit(surfaces: dict[str, dict]) -> None:
    """Snapshot severity counts finding nodes: a third unit, labelled, and equal to the graph's own tally.

    One node holds every occurrence of an advisory or benchmark check, so the
    node count is neither the issue count (an advisory on two packages is two
    issues) nor the occurrence count; it must never be passed off as either.
    """
    issues, occurrences = surfaces["overview"]["issue_counts"], surfaces["overview"]["finding_counts"]
    rows = [row for row in surfaces["snapshots"]["rows"] if isinstance(row, dict) and row.get("risk_summary")]
    assert rows
    latest = rows[0]
    assert latest["severity_basis"] == "graph_nodes"
    assert latest["risk_summary"] == surfaces["graph"]["stats"]["severity_counts"]
    node_total = sum(latest["risk_summary"].values())
    assert node_total <= issues["total"] <= occurrences["total"], (node_total, issues["total"], occurrences["total"])


def _check_agent_counts_carry_their_scope(surfaces: dict[str, dict]) -> None:
    host = surfaces["agents"]
    estate = surfaces["counts"]["agents"]
    assert host["scope"] in {"local_discovery", "scanned_estate"}
    assert host["count"] == len(host["agents"])
    assert estate["basis"] == "graph_agents"
    assert estate["total"] >= 1


def _check_unique_credentials_match_the_posture_dimension_on_the_same_inventory(surfaces: dict[str, dict]) -> None:
    from agent_bom.constants import is_credential_key

    host = surfaces["agents"]
    names: set[str] = set()
    for agent in host["agents"]:
        for server in agent.get("mcp_servers") or []:
            names.update(key for key in (server.get("env") or {}) if is_credential_key(key))
            names.update(server.get("credential_env_vars") or [])
    details = surfaces["posture"]["dimensions"]["credential_hygiene"]["details"]
    assert details.startswith(f"{len(names)} unique credentials"), (sorted(names), details)


def test_every_surface_reads_one_count_source(demo_estate_client: TestClient) -> None:
    """One bootstrap, every check: the seed is the expensive part."""
    surfaces = _surfaces(demo_estate_client)
    _check_issue_severity_is_one_number_on_every_surface(surfaces)
    _check_occurrence_counts_are_labelled_as_a_different_unit(surfaces)
    _check_kev_uses_the_issue_unit_beside_the_issue_tiles(surfaces, demo_estate_client)
    _check_open_cve_findings_agree_between_overview_and_posture(surfaces)
    _check_vuln_card_equals_its_drill_down(surfaces, demo_estate_client)
    _check_remediation_reads_the_findings_window(surfaces)
    _check_graph_snapshot_severity_names_its_unit(surfaces)
    _check_agent_counts_carry_their_scope(surfaces)
    _check_unique_credentials_match_the_posture_dimension_on_the_same_inventory(surfaces)
