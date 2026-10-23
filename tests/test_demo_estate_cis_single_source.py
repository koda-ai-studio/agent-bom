"""The demo's CIS panel, scorecard and graph read one set of CIS results.

The demo job used to carry a separately curated CIS table with older AWS
numbering (2.1.1 meant S3 encryption, shown as passing) and no Snowflake, while
the graph held the estate's current failures (2.1.1 is the public access block).
Both now derive from the estate findings the graph projects.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from starlette.testclient import TestClient

from tests.test_demo_estate_bootstrap import VIEWER, demo_estate_client  # noqa: F401 - pytest fixture

_CIS_SECTIONS = {
    "cis_benchmark": "aws",
    "azure_cis_benchmark": "azure",
    "gcp_cis_benchmark": "gcp",
    "snowflake_cis_benchmark": "snowflake",
}


def _row(provider: str, check_id: str, status: str, resource_id: str, **extra: Any) -> dict[str, Any]:
    return {
        "id": f"{provider}-{check_id}-{resource_id}",
        "finding_type": "CIS_ERROR" if status == "ERROR" else "CIS_FAIL",
        "source": "CLOUD_CIS",
        "severity": "unknown" if status == "ERROR" else "high",
        "title": f"{'Unevaluated' if status == 'ERROR' else 'Failed'} CIS {check_id} — Control {check_id}",
        "remediation": {"fix": {"console": "Console path", "cli": None, "docs": "https://example.invalid"}, "priority": 4},
        "evidence": {
            "provider": provider,
            "check_id": check_id,
            "status": status,
            "cis_section": "2 - Storage",
            "control_title": f"Control {check_id}",
            "resource_id": resource_id,
            "benchmark": "CIS",
        },
        **extra,
    }


def test_benchmark_blobs_are_derived_from_the_estate_cis_findings() -> None:
    from agent_bom.demo_estate.estate_cis_benchmarks import estate_cis_benchmarks

    rows = [
        _row("aws", "2.1.1", "FAIL", "aws:bucket:a"),
        _row("aws", "2.1.1", "FAIL", "aws:bucket:b"),
        _row("aws", "2.1.1", "ERROR", "aws:bucket:c"),
        _row("snowflake", "3.1", "ERROR", "snowflake:table:t"),
        # Not CIS: vendor best practice and non-posture rows never enter a CIS benchmark.
        {**_row("aws", "9.9", "FAIL", "aws:x"), "source": "CLOUD_SECURITY", "finding_type": "CLOUD_BEST_PRACTICE_FAIL"},
        {"id": "cve", "finding_type": "CVE", "source": "SBOM", "evidence": {}},
    ]

    blobs = estate_cis_benchmarks(rows)

    assert set(blobs) == {"cis_benchmark", "snowflake_cis_benchmark"}
    aws = blobs["cis_benchmark"]
    assert aws["benchmark_version"] == "3.0"
    (check,) = aws["checks"]
    assert check["check_id"] == "2.1.1"
    assert check["title"] == "Control 2.1.1"
    assert check["status"] == "fail"
    assert check["resource_ids"] == ["aws:bucket:a", "aws:bucket:b"]
    assert check["unevaluated_resource_ids"] == ["aws:bucket:c"]
    assert check["remediation"]["fix_console"] == "Console path"
    assert (aws["passed"], aws["failed"], aws["total"]) == (0, 1, 1)
    snowflake = blobs["snowflake_cis_benchmark"]
    assert snowflake["benchmark_version"] == "1.0"
    assert [(c["check_id"], c["status"], c["resource_ids"]) for c in snowflake["checks"]] == [("3.1", "error", [])]
    # No recorded passing result was supplied, so nothing is reported as passing.
    assert all(c["status"] != "pass" for blob in blobs.values() for c in blob["checks"])


def test_recorded_passes_join_the_blob_and_never_mask_a_failure() -> None:
    from agent_bom.demo_estate.estate_cis_benchmarks import estate_cis_benchmarks, recorded_cis_passes

    passing = {"check_id": "1.4", "title": "No root account access keys", "status": "pass", "resource_ids": []}
    masked = {**passing, "check_id": "2.1.1"}
    blobs = estate_cis_benchmarks([_row("aws", "2.1.1", "FAIL", "aws:bucket:a")], [("aws", passing), ("aws", masked)])

    aws = blobs["cis_benchmark"]
    assert [(c["check_id"], c["status"]) for c in aws["checks"]] == [("1.4", "pass"), ("2.1.1", "fail")]
    assert (aws["passed"], aws["failed"], aws["total"], aws["pass_rate"]) == (1, 1, 2, 50.0)
    assert recorded_cis_passes(blobs) == [("aws", passing)]


def _scanner_definition(provider: str, check_id: str) -> tuple[str, str, str] | None:
    """``(title, severity, section literal or constant)`` from the shipped scanner source."""
    import re
    from pathlib import Path

    import agent_bom.cloud as cloud_pkg

    root = Path(cloud_pkg.__file__).parent
    paths = [root / f"{provider}_cis_benchmark.py", *sorted((root / f"{provider}_cis").glob("*.py"))]
    source = "\n".join(path.read_text(encoding="utf-8") for path in paths if path.exists())
    constants = dict(re.findall(r'^(_[A-Z_]+)\s*=\s*"([^"]+)"', source, re.M))
    for match in re.finditer(rf'check_id="{re.escape(check_id)}",', source):
        window = source[match.end() : match.end() + 700]
        title, severity = re.search(r'title="([^"]+)"', window), re.search(r'severity="([a-z]+)"', window)
        section = re.search(r'cis_section=([A-Za-z_"][^,\n)]*)', window)
        if title and severity and section:
            raw = section.group(1).strip()
            return title.group(1), severity.group(1), constants.get(raw, raw.strip('"'))
    return None


def test_every_recorded_pass_is_a_shipped_scanner_control_that_never_fails_in_the_estate() -> None:
    from agent_bom.demo_estate.estate_cis_catalog import _CATALOG, _PASSING

    drifted = [
        f"{check.provider} {check.check_id}"
        for check in _PASSING
        if _scanner_definition(check.provider, check.check_id) != (check.title, check.severity, check.cis_section)
    ]
    assert drifted == [], f"recorded passes must copy the scanner's id, title, severity and section: {drifted}"
    failing = {(check.provider, check.check_id) for check in _CATALOG}
    assert [(c.provider, c.check_id) for c in _PASSING if (c.provider, c.check_id) in failing] == []


def test_every_cloud_records_a_believable_derived_pass_rate() -> None:
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.estate_cis_catalog import _PASSING, estate_cis_passes

    passes = estate_cis_passes(build_demo_estate(tenant_id="default"))
    # Every recorded pass rests on estate evidence, and none was dropped for lack of it.
    assert len(passes) == len(_PASSING)
    assert all(check["evaluated_count"] > 0 and check["resource_ids"] == [] for _, check in passes)


def test_the_curated_cis_table_is_gone() -> None:
    import importlib.util

    assert importlib.util.find_spec("agent_bom.demo_estate.showcase_cis") is None


def _graph_cis_failures(client: TestClient) -> dict[tuple[str, str], set[str]]:
    page = client.get("/v1/graph", headers=VIEWER, params={"entity_types": "misconfiguration", "limit": 5000}).json()
    # Every misconfiguration node is on the page (edge endpoints ride along beside them).
    assert sum(1 for node in page["nodes"] if node["entity_type"] == "misconfiguration") == page["stats"]["total_nodes"]
    failures: dict[tuple[str, str], set[str]] = defaultdict(set)
    for node in page["nodes"]:
        section, _, check_id = node["id"].removeprefix("misconfig:").partition(":")
        if section in _CIS_SECTIONS and check_id:
            failures[(_CIS_SECTIONS[section], check_id)] |= set(node["attributes"].get("finding_ids_by_asset") or {})
    return failures


def _panel(client: TestClient) -> list[dict[str, Any]]:
    body = client.get("/v1/cis/checks", headers=VIEWER, params={"limit": 500}).json()
    assert body["count"] == len(body["checks"])
    return body["checks"]


def test_panel_scorecard_job_and_graph_agree_on_cis_snowflake_included(demo_estate_client: TestClient) -> None:  # noqa: F811
    """One demo boot: every CIS surface must state the graph's CIS failures."""
    graph = _graph_cis_failures(demo_estate_client)
    checks = _panel(demo_estate_client)
    _assert_panel_matches_graph(checks, graph)
    _assert_resources_open_in_graph_and_findings(demo_estate_client, checks)
    _assert_scorecard_counts_the_panel(demo_estate_client, checks)
    _assert_demo_job_matches_graph(demo_estate_client, graph)


def _assert_panel_matches_graph(checks: list[dict[str, Any]], graph: dict[tuple[str, str], set[str]]) -> None:
    failing = {(row["cloud"], row["check_id"]): set(row["resource_ids"]) for row in checks if row["status"] == "fail"}

    assert len(graph) == 28 and {cloud for cloud, _ in graph} == {"aws", "azure", "gcp", "snowflake"}
    assert failing == graph, "the panel's failing checks and resources must be the graph's CIS failure nodes"
    by_id = {(row["cloud"], row["check_id"]): row for row in checks}
    public_access_block = by_id[("aws", "2.1.1")]
    assert "public access block" in public_access_block["title"].lower()
    assert public_access_block["graph_node_id"] == "misconfig:cis_benchmark:2.1.1"
    assert {row["status"] for row in checks} <= {"pass", "fail", "error", "not_evaluated"}
    passes = [row for row in checks if row["status"] == "pass"]
    # Recorded passes never claim a failing resource and are never in the graph's failures.
    assert passes and all(row["resource_ids"] == [] and (row["cloud"], row["check_id"]) not in graph for row in passes)
    for cloud in ("aws", "azure", "gcp", "snowflake"):
        rows = [row for row in checks if row["cloud"] == cloud]
        evaluated = [row for row in rows if row["status"] in {"pass", "fail", "error"}]
        rate = sum(1 for row in evaluated if row["status"] == "pass") / len(evaluated)
        assert 0.6 <= rate <= 0.8, (cloud, rate)


def _assert_resources_open_in_graph_and_findings(client: TestClient, checks: list[dict[str, Any]]) -> None:
    row = next(row for row in checks if (row["cloud"], row["check_id"]) == ("snowflake", "3.1"))
    resource = row["resource_ids"][0]

    search = client.get("/v1/graph/search", headers=VIEWER, params={"q": resource, "limit": 20}).json()
    assert resource in {node["id"] for node in search["results"]}, "a resource id is a graph node id"
    (finding_id,) = row["resource_finding_ids"][resource]
    findings = client.get("/v1/findings", headers=VIEWER, params={"q": finding_id, "limit": 5}).json()
    assert [f["id"] for f in findings["findings"]] == [finding_id]
    assert findings["findings"][0]["finding_node_id"] == row["graph_node_id"]


def _assert_scorecard_counts_the_panel(client: TestClient, checks: list[dict[str, Any]]) -> None:
    benchmark = [row for row in checks if row["cloud"] != "databricks"]
    line = client.get("/v1/compliance", headers=VIEWER).json()["cis_foundations_benchmark"]
    summary = line["summary"]

    def count(status: str) -> int:
        return sum(1 for row in benchmark if row["status"] == status)

    assert summary["fail"] == count("fail") == 28
    assert summary["pass"] == count("pass") > 0
    assert summary["error"] == count("error")
    assert summary["not_evaluated"] == count("not_evaluated")
    assert summary["evaluated"] == summary["pass"] + summary["fail"] + summary["error"]
    assert line["status"] == "fail"
    assert summary["score"] == round(summary["pass"] / summary["evaluated"] * 100, 1)
    assert line["providers"]["snowflake"]["fail"] == 4


def _assert_demo_job_matches_graph(client: TestClient, graph: dict[tuple[str, str], set[str]]) -> None:
    from agent_bom.demo_estate.showcase_constants import SHOWCASE_SCAN_ID

    jobs = client.get("/v1/jobs", headers=VIEWER, params={"include_details": "true"}).json()["jobs"]
    results = [client.get(f"/v1/scan/{job['job_id']}", headers=VIEWER).json().get("result") or {} for job in jobs]
    (result,) = [result for result in results if result.get("scan_id") == SHOWCASE_SCAN_ID]
    stored: dict[tuple[str, str], list[str]] = {}
    for section, cloud in _CIS_SECTIONS.items():
        for check in (result.get(section) or {}).get("checks") or []:
            if check["status"] == "fail":
                stored[(cloud, check["check_id"])] = list(check["resource_ids"])
    assert set(stored) == set(graph)
    for key, ids in graph.items():
        # Persistence redaction may mask an id in the stored blob; it never adds,
        # drops or renames one, which is why the panel reads resources from the graph.
        assert len(stored[key]) == len(ids), key
        assert set(stored[key]) - {"***REDACTED***"} <= ids, key
