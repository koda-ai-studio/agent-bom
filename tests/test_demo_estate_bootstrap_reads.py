"""Read-only contracts over one seeded demo estate per module.

Every test here only reads, so the module shares one seed (see
tests/_demo_estate_fixtures.py). Tests that write, reseed or patch belong in
test_demo_estate_bootstrap.py on the per-test seed.
"""

from __future__ import annotations

from collections import Counter

import pytest
from fastapi import HTTPException
from starlette.testclient import TestClient

from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_SCAN_ID
from tests._demo_estate_fixtures import VIEWER, demo_graph_get


def _demo_report(client: TestClient) -> dict:
    jobs = client.get("/v1/jobs", headers=VIEWER, params={"include_details": "true"}).json().get("jobs") or []
    assert jobs, "expected at least one demo job after bootstrap"
    detail = client.get(f"/v1/scan/{jobs[0]['job_id']}", headers=VIEWER).json()
    return detail.get("result") or {}


def test_demo_estate_bootstrap_seeds_jobs_and_graph(shared_demo_estate_client: TestClient) -> None:
    jobs_payload = shared_demo_estate_client.get(
        "/v1/jobs",
        headers=VIEWER,
        params={"include_details": "true"},
    ).json()
    jobs = jobs_payload.get("jobs") or []
    assert jobs, "expected at least one demo job after bootstrap"
    job_id = jobs[0]["job_id"]
    detail = shared_demo_estate_client.get(f"/v1/scan/{job_id}", headers=VIEWER).json()
    sources = (detail.get("result") or {}).get("scan_sources", [])
    assert any("demo" in str(src).lower() for src in sources)

    graph = shared_demo_estate_client.get("/v1/graph", headers=VIEWER)
    assert graph.status_code == 200, graph.text
    payload = graph.json()
    node_count = len(payload.get("nodes") or [])
    assert node_count > 0


def test_demo_estate_change_pair_reports_the_trend_issue_basis(shared_demo_estate_client: TestClient) -> None:
    """The SOC diff names the posture-basis issue counts the trend plots for the same two scans."""
    trends = shared_demo_estate_client.get("/v1/trends", headers=VIEWER, params={"limit": 30}).json()["data_points"]
    by_scan = {point["scan_id"]: point["issues"] for point in trends}
    changes = shared_demo_estate_client.get("/v1/graph/changes", headers=VIEWER).json()
    source = changes["sources"][0]
    assert (source["old"]["scan_id"], source["new"]["scan_id"]) == (SHOWCASE_BASELINE_SCAN_ID, "showcase")
    issues = source["issue_change"]
    assert issues["basis"] == "issue_groups"
    for side in ("old", "new"):
        expected = by_scan[source[side]["scan_id"]]
        assert {key: issues[side][key] for key in ("critical", "high")} == {key: expected[key] for key in ("critical", "high")}
    assert issues["new"]["critical"] != issues["old"]["critical"] or issues["new"]["high"] != issues["old"]["high"]


def test_demo_estate_story_api_exposes_normalized_evidence_only(
    shared_demo_estate_client: TestClient,
) -> None:
    response = shared_demo_estate_client.get("/v1/demo-estate/story", headers=VIEWER)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["schema_version"] == "enterprise_demo_story.v1"
    assert payload["synthetic"] is True
    assert payload["fictional"] is True
    assert payload["graph_snapshot_id"] == "showcase"
    focused_graph = shared_demo_estate_client.get(
        "/v1/graph",
        headers=VIEWER,
        params={"scan": payload["graph_snapshot_id"], "limit": 1},
    )
    assert focused_graph.status_code == 200, focused_graph.text
    focused_payload = focused_graph.json()
    assert focused_payload["scan_id"] == payload["graph_snapshot_id"]
    assert focused_payload["stats"]["total_nodes"] > 0
    assert focused_payload["stats"]["total_edges"] > 0
    assert payload["primary_correlation"]["outcome"] == "blocked"
    assert payload["summary"]["evidence_sources"] == 9
    assert "raw_payload" not in response.text


def test_demo_estate_status_exposes_the_default_graph_owner(
    shared_demo_estate_client: TestClient,
) -> None:
    response = shared_demo_estate_client.get("/v1/demo-estate/status", headers=VIEWER)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert isinstance(payload.pop("story_ready"), bool)
    assert payload == {
        "schema_version": "demo_estate_status.v1",
        "showcase_snapshot_id": "showcase",
        "showcase_available": True,
        "graph_owner_scan_id": "showcase",
        "graph_alignment": "aligned",
        "reason": None,
    }


def test_demo_estate_graph_is_a_rich_multi_agent_estate(shared_demo_estate_client: TestClient) -> None:
    # Reads the whole snapshot rather than the default page. Since the
    # enterprise estate is projected into this snapshot it holds ~2,900 nodes,
    # and the default page is 500 ordered by severity — which the estate's 439
    # posture findings now fill. The agents/servers/packages asserted here are
    # unrated inventory, so a default-page read would be testing the pager, not
    # the estate. ``test_demo_estate_default_graph_page_declares_its_truncation``
    # covers the bounded read.
    payload = _graph_with_all_nodes(shared_demo_estate_client)
    nodes = payload.get("nodes") or []
    by_type = Counter(n.get("entity_type") for n in nodes)

    # Several AI agents, many MCP servers, real packages + CVEs, credentials.
    assert by_type["agent"] >= 5, by_type
    assert by_type["server"] >= 10, by_type
    assert by_type["package"] >= 10, by_type
    assert by_type["vulnerability"] >= 10, by_type
    assert by_type["credential"] >= 5, by_type
    assert by_type["tool"] >= 15, by_type

    labels = {n.get("label") for n in nodes}
    # Realistic, distinct agents render.
    assert {"Cursor", "LangChain Service", "Support Copilot", "Data Pipeline"} <= labels

    # Configuration errors must not masquerade as CVEs or invented packages.
    assert "CVE-2024-S3ACL" not in labels
    assert not any("reqeusts" in (label or "") for label in labels)
    public_bucket = next(n for n in nodes if n.get("id") == "misconfig:showcase:pii-public")
    assert public_bucket["entity_type"] == "misconfiguration"
    assert public_bucket["severity"] == "high"

    # KEV vulnerability lights up.
    kev = [n for n in nodes if n.get("attributes", {}).get("is_kev")]
    assert any("CVE-2023-4863" in (n.get("label") or "") for n in kev), "expected a KEV CVE node"


def test_demo_estate_headline_blast_radius_chain(shared_demo_estate_client: TestClient) -> None:
    """agent -> MCP server -> vulnerable package -> critical CVE -> reachable
    credential + reachable run_shell tool -> potential RCE renders in the graph.

    Whole snapshot, not the default page: the hand-built chain is *extended* by
    the projected enterprise estate, never replaced, but its unrated inventory
    nodes no longer land in a 500-row severity-ranked page.
    """
    payload = _graph_with_all_nodes(shared_demo_estate_client)
    node_ids = {n.get("id") for n in payload.get("nodes") or []}
    # Node pages carry bounded incident evidence. Read the chain's source
    # relationships explicitly; limit=2 also exercises cursor continuation.
    edges = _outgoing_graph_edges(
        shared_demo_estate_client,
        payload,
        {"agent:cursor", "server:shell-runner-server", "pkg:pypi:pyyaml@5.3", "vuln:CVE-2020-14343"},
        limit=2,
    )
    edge_pairs = {(e.get("source"), e.get("target")) for e in edges}

    # Chain nodes exist.
    for nid in (
        "agent:cursor",
        "server:shell-runner-server",
        "pkg:pypi:pyyaml@5.3",
        "vuln:CVE-2020-14343",
        "cred:aws-secret",
        "tool:shell-runner-server:run_shell",
    ):
        assert nid in node_ids, f"missing chain node {nid}"

    assert ("agent:cursor", "server:shell-runner-server") in edge_pairs
    assert ("server:shell-runner-server", "pkg:pypi:pyyaml@5.3") in edge_pairs
    assert ("pkg:pypi:pyyaml@5.3", "vuln:CVE-2020-14343") in edge_pairs
    assert ("server:shell-runner-server", "cred:aws-secret") in edge_pairs
    # The critical CVE reaches both the credential and the run_shell tool (RCE).
    assert ("vuln:CVE-2020-14343", "cred:aws-secret") in edge_pairs
    assert ("vuln:CVE-2020-14343", "tool:shell-runner-server:run_shell") in edge_pairs


def test_demo_estate_findings_include_critical_and_kev(shared_demo_estate_client: TestClient) -> None:
    result = _demo_report(shared_demo_estate_client)
    summary = result.get("summary") or {}
    assert summary.get("total_agents") == 5
    assert summary.get("total_mcp_servers") == 10
    assert (summary.get("critical_findings") or 0) >= 2, summary

    findings = result.get("findings") or []
    assert len(findings) >= 12, f"expected a dense findings list, got {len(findings)}"

    # KEV differentiator surfaces in the blast radius (Pillow/libwebp).
    blast = result.get("blast_radius") or []
    kev = [b for b in blast if b.get("is_kev") or b.get("cisa_kev")]
    assert any(b.get("vulnerability_id") == "CVE-2023-4863" for b in kev), "expected KEV CVE in blast radius"


def test_demo_estate_hero_findings_carry_the_persisted_graph_path(shared_demo_estate_client: TestClient) -> None:
    """The scan and graph surfaces must tell the same hero-path story."""
    result = _demo_report(shared_demo_estate_client)
    blast = result.get("blast_radius") or []
    hero = [
        row
        for row in blast
        if row.get("vulnerability_id") == "CVE-2020-14343" and row.get("package_name") == "pyyaml" and row.get("package_version") == "5.3"
    ]

    on_path = [row for row in hero if (row.get("asset") or {}).get("asset_type") == "mcp_server"]
    assert len(hero) > len(on_path) >= 1, "the bundled inventory did not include both the hero server and estate-scoped pyyaml exposures"
    # An estate occurrence is another asset, not a hop on the hand-built path.
    assert all(row.get("graph_reachable") is not True for row in hero if row not in on_path)
    for row in on_path:
        assert row.get("graph_reachable") is True
        assert row.get("graph_min_hop_distance") == 3
        assert "agent:cursor" in (row.get("graph_reachable_from_agents") or [])
        assert "cursor" in (row.get("affected_agents") or [])
        assert "shell-runner-server" in (row.get("affected_servers") or [])
        assert (row.get("risk_score") or 0) > 0

    listing = shared_demo_estate_client.get(
        "/v1/findings",
        headers=VIEWER,
        params={"limit": 1000},
    ).json()
    public_hero = [row for row in listing.get("findings") or [] if (row.get("vulnerability_id") or row.get("cve_id")) == "CVE-2020-14343"]
    assert public_hero, "the persisted hero path did not reach the public findings route"
    graph_hero = [row for row in public_hero if row.get("graph_reachable") is True]
    assert graph_hero, [(row.get("id"), row.get("graph_reachable"), row.get("source"), row.get("asset")) for row in public_hero]
    assert all(
        row.get("package") == "pyyaml"
        or (row.get("asset") or {}).get("name") == "pyyaml"
        or (row.get("evidence") or {}).get("package_name") == "pyyaml"
        for row in graph_hero
    )
    agent_path_rows = [row for row in graph_hero if "agent:cursor" in (row.get("graph_reachable_from") or [])]
    assert agent_path_rows, "the original agent path must remain visible"
    assert all("cursor" in (row.get("affected_agents") or []) for row in agent_path_rows)
    assert all("shell-runner-server" in (row.get("affected_servers") or []) for row in agent_path_rows)
    # Workload paths now establish structural reach too. They must carry their
    # own source evidence without borrowing the hero agent/server context.
    workload_rows = [row for row in graph_hero if row not in agent_path_rows]
    assert workload_rows
    assert all(row.get("graph_reachable_from") for row in workload_rows)
    assert all(not row.get("affected_agents") and not row.get("affected_servers") for row in workload_rows)


def test_demo_estate_graph_evidence_covers_every_hand_built_path(shared_demo_estate_client: TestClient) -> None:
    """Every hand-built path is evidenced on its finding, and no other row borrows one."""
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_PACKAGES

    blast = _demo_report(shared_demo_estate_client).get("blast_radius") or []
    evidenced = [row for row in blast if row.get("graph_reachable") is True]
    paths = {f"{row.get('package_name')}@{row.get('package_version')}".lower() for row in evidenced}

    assert paths == set(SHOWCASE_PACKAGES), sorted(paths ^ set(SHOWCASE_PACKAGES))
    assert all((row.get("asset") or {}).get("asset_type") == "mcp_server" for row in evidenced)


def test_demo_estate_posture_findings_resolve_to_inventoried_assets(
    shared_demo_estate_client: TestClient,
) -> None:
    """The estate's posture findings reach the public findings list, chain intact.

    Asserted on ``/v1/findings`` rather than the raw scan result on purpose:
    that route is the canonical list every consumer reads, and it applies
    ``safe_finding_response_payload`` — default-deny tier-A redaction. A chain
    that only holds before redaction is a chain no user ever sees, so the join
    keys the demo relies on must be ones the evidence policy already classifies
    as safe.
    """
    from agent_bom.demo_estate.enterprise_composition import build_demo_estate
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    inventoried = {asset.asset_id for asset in build_demo_estate(tenant_id=SHOWCASE_TENANT).assets}

    listing = shared_demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1000, "domain": "cspm"}).json()
    rows = [row for row in listing["findings"] if (row.get("evidence") or {}).get("resource_id", "") in inventoried]
    assert len(rows) >= 400, f"only {len(rows)} estate posture findings reached the findings list"

    for row in rows:
        evidence = row.get("evidence") or {}
        assert evidence["resource_id"] in inventoried, evidence["resource_id"]
        assert evidence.get("principal_id") or evidence.get("actor_id"), (
            f"{row.get('id')} lost its identity edge through redaction: {sorted(evidence)}"
        )
        # Every posture finding must say which check saw it — that is the join
        # key the rest of the product reads. A control id is required *exactly
        # when* the finding claims a framework: not every posture rule has a
        # CIS twin ("resource declared without an ownership tag" has none), and
        # a rule with no control must say so rather than borrow one. Requiring
        # a control on every row is what forced the IaC lane to assert CIS and
        # NIST coverage it could not support.
        assert evidence.get("check_id"), f"{row.get('id')} has no check identity: {sorted(evidence)}"
        claims_cis = any(str(tag).upper().startswith("CIS") for tag in (row.get("compliance_tags") or row.get("compliance") or []))
        if claims_cis:
            assert evidence.get("control_id"), f"{row.get('id')} claims CIS with no control_id behind it"
        assert evidence.get("resource_name") and evidence.get("resource_type")
        assert row.get("provider"), sorted(row)
        assert row.get("severity"), sorted(row)
    assert any((row.get("evidence") or {}).get("correlation_id") for row in rows), "no posture finding kept its correlated attack path"
    assert len({(row.get("evidence") or {}).get("resource_id") for row in rows}) > 200, (
        "the estate's findings all land on a handful of assets"
    )


def test_demo_estate_finding_counts_reconcile_across_tile_list_and_facet(
    shared_demo_estate_client: TestClient,
) -> None:
    """One estate, one total — whatever surface is asked.

    The tile, the list header, and the severity facet histogram are three
    different code paths over the same evidence. Adding hundreds of posture
    findings is exactly the change that makes them drift apart, so pin them
    together on the seeded estate rather than trusting that they agree.
    """
    listing = shared_demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1, "include_facets": "true"}).json()
    total = listing["total"]
    assert total > 400, total

    severity_facet = (listing.get("facets") or {}).get("severity") or {}
    assert severity_facet, f"the findings list returned no severity facet: {list(listing.get('facets') or {})}"
    severity_total = sum(int(v) for v in severity_facet.values())
    facet_completeness = (listing.get("facet_metadata") or {}).get("completeness") or {}
    if facet_completeness.get("status") == "complete":
        assert severity_total == total, f"severity facet sums to {severity_total} but the list reports {total}"
    else:
        assert listing.get("facets_approximate") is True, listing
        assert severity_total <= total, (severity_total, total)
        assert any("lower bounds, not totals" in warning for warning in listing.get("warnings") or []), listing

    counts = shared_demo_estate_client.get("/v1/posture/counts", headers=VIEWER).json()
    assert "unrated" in counts, counts
    assert sum(counts[band] for band in ("critical", "high", "medium", "low", "unrated")) == counts["total"], counts
    assert counts["unrated"] > 0, (
        "no unrated finding survives to the tiles, so an unevaluable control is indistinguishable from one that passed"
    )

    # The bounded page reports the unbounded total, never its own size.
    page = shared_demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 25}).json()
    assert len(page["findings"]) <= 25
    assert page["total"] == total > len(page["findings"]), (page["total"], len(page["findings"]))


def test_demo_estate_cis_posture_spans_aws_gcp_azure(shared_demo_estate_client: TestClient) -> None:
    result = _demo_report(shared_demo_estate_client)
    # Curated multi-cloud CIS posture is attached to the demo scan result, which
    # is exactly what the CIS/compliance surfaces read (build_cis_benchmark_check_rows).
    seen_clouds: set[str] = set()
    for key, cloud in (
        ("cis_benchmark", "aws"),
        ("gcp_cis_benchmark", "gcp"),
        ("azure_cis_benchmark", "azure"),
    ):
        checks = (result.get(key) or {}).get("checks") or []
        assert checks, f"expected CIS checks for {key}"
        statuses = {c.get("status") for c in checks}
        # A believable spread — neither empty nor all-passing.
        assert "pass" in statuses and "fail" in statuses, f"{key} needs a pass/fail spread: {statuses}"
        seen_clouds.add(cloud)
    assert seen_clouds == {"aws", "gcp", "azure"}

    # The rows normalize through the same contract the /v1/cis/checks route uses.
    from agent_bom.analytics_contract import build_cis_benchmark_check_rows

    rows = build_cis_benchmark_check_rows(result, "showcase")
    clouds = Counter(r["cloud"] for r in rows)
    assert {"aws", "gcp", "azure"} <= set(clouds), clouds
    statuses = Counter(r["status"] for r in rows)
    assert statuses["pass"] > 0 and statuses["fail"] > 0, statuses


def test_demo_estate_firewall_stats_require_audit_permission(shared_demo_estate_client: TestClient) -> None:
    response = shared_demo_estate_client.get("/v1/firewall/stats")
    assert response.status_code == 403
    assert "audit_read" in response.json()["detail"]


def test_demo_estate_graph_snapshots_support_drift_lens(shared_demo_estate_client: TestClient) -> None:
    """Baseline + current snapshots let the shipped drift lens diff against a prior estate."""
    snapshots = shared_demo_estate_client.get("/v1/graph/snapshots", headers=VIEWER).json()
    scan_ids = {row.get("scan_id") for row in snapshots}
    assert SHOWCASE_BASELINE_SCAN_ID in scan_ids
    assert "showcase" in scan_ids
    assert len(snapshots) >= 2

    diff = shared_demo_estate_client.get(
        "/v1/graph/diff",
        headers=VIEWER,
        params={"old": SHOWCASE_BASELINE_SCAN_ID, "new": "showcase", "view": "full"},
    )
    assert diff.status_code == 200, diff.text
    body = diff.json()
    index = body.get("change_kind_index") or {}
    node_kinds = index.get("nodes") or {}
    assert node_kinds, "expected node drift between baseline and current showcase snapshots"
    kinds = set(node_kinds.values())
    assert kinds & {"new", "removed", "changed"}, kinds

    deltas = body.get("attribute_deltas") or {}
    pii_deltas = deltas.get("cloud:pii-bucket") or []
    summaries = {row.get("summary") for row in pii_deltas}
    assert "Public exposure opened" in summaries or "Encryption at rest disabled" in summaries, pii_deltas

    assert body.get("nodes_added"), "expected at least one new node in the showcase drift story"
    assert body.get("nodes_removed"), "expected at least one removed node in the showcase drift story"
    assert body.get("nodes_changed"), "expected at least one changed node in the showcase drift story"


def test_demo_estate_exec_severity_counts_reconcile_across_surfaces(
    shared_demo_estate_client: TestClient,
) -> None:
    """Exec-facing severity counts agree across surfaces on one estate (#3961).

    Regression for the exec-read honesty bug: ``/v1/posture/counts`` read the
    CVE-only ``blast_radius`` while ``/v1/overview`` read the unified findings
    spine, so a leader saw different critical/high on the same estate (2/10 vs
    3/12 on the demo estate). Both exec surfaces must now derive from the one
    reconciled source of truth. The graph snapshot ``risk_summary`` is a
    *different* metric (graph nodes at risk, per scan) and is explicitly tagged
    as such so it is never mistaken for the exec headline.
    """
    counts = shared_demo_estate_client.get("/v1/posture/counts").json()
    overview = shared_demo_estate_client.get("/v1/overview").json()
    headline = overview["headline"]

    # 1. The exec headline and the nav-badge issue counts are the same number;
    #    occurrence counts reconcile with the overview's ``finding_counts``.
    assert counts["issues"]["critical"] == headline["critical"], (counts, headline)
    assert counts["issues"]["high"] == headline["high"], (counts, headline)
    assert counts["critical"] == overview["finding_counts"]["critical"], (counts, overview["finding_counts"])
    assert overview["posture"]["severity_basis"] == "issue_groups"
    # The headline is one unit: KEV beside critical/high counts issues too.
    assert headline["basis"] == "issue_groups"
    assert counts["issues"]["kev"] == headline["kev"], (counts, headline)
    assert counts["kev"] == overview["finding_counts"]["kev"] >= headline["kev"]
    # The demo estate carries the non-CVE critical/high that blast_radius missed.
    assert counts["critical"] >= 3 and counts["high"] >= 12, counts

    # 2. Honest histogram: unrated is an explicit bucket and the buckets sum to
    #    total — no severity is silently dropped.
    assert "unrated" in counts, counts
    bucketed = sum(counts[band] for band in ("critical", "high", "medium", "low", "unrated"))
    assert bucketed == counts["total"], counts

    # 3. The graph snapshot risk_summary is a distinctly-labeled metric
    #    (graph-node severity), NOT the reconciled exec headline.
    snapshots = shared_demo_estate_client.get("/v1/graph/snapshots").json()
    assert snapshots, "expected persisted demo snapshots"
    for snapshot in snapshots:
        assert snapshot.get("severity_basis") == "graph_nodes", snapshot


def test_demo_estate_showcase_cloud_hierarchy_and_exposure(shared_demo_estate_client: TestClient) -> None:
    """Showcase graph carries org→account containment and a bastion→PII exposure edge.

    Read through the cursor rather than from a single default page. This asserts
    a property of the *graph* — two named low-severity leaves and the edge
    between them — and node pages are ordered by severity, so at estate scale no
    page-size choice can promise a particular leaf is on page one. Asserting it
    against the default page passed only while the estate was small enough to
    fit, which made the test a size check wearing a topology check's clothes.

    The default page's own contract — that it still describes a shaped estate
    rather than a heap of findings — is asserted separately in
    ``test_default_graph_page_carries_the_containment_spine``.
    """
    payload = _graph_with_all_nodes(shared_demo_estate_client)
    node_ids = {node.get("id") for node in payload.get("nodes") or []}
    assert "org:corp" in node_ids
    assert "account:aws:123456789012" in node_ids

    edges = _outgoing_graph_edges(shared_demo_estate_client, payload, {"org:corp", "account:aws:123456789012", "cloud:bastion"})
    contains = {(row.get("source"), row.get("target")) for row in edges if row.get("relationship") == "contains"}
    assert ("org:corp", "account:aws:123456789012") in contains
    assert ("account:aws:123456789012", "cloud:pii-bucket") in contains
    assert ("account:aws:123456789012", "cloud:bastion") in contains

    exposed = [
        row
        for row in edges
        if row.get("relationship") == "exposed_to" and row.get("source") == "cloud:bastion" and row.get("target") == "cloud:pii-bucket"
    ]
    assert exposed, "expected bastion→PII EXPOSED_TO edge in showcase snapshot"


def test_demo_estate_graph_tags_runtime_evidence_tiers(shared_demo_estate_client: TestClient) -> None:
    # Whole snapshot: runtime-evidence tiers sit on unrated tool/tool-call nodes,
    # which the estate's rated findings now outrank on the default page.
    payload = _graph_with_all_nodes(shared_demo_estate_client)
    attrs_by_id = {node.get("id"): (node.get("attributes") or {}) for node in payload.get("nodes") or []}
    assert attrs_by_id.get("call:0", {}).get("evidence_tier") == "runtime_observed"
    assert attrs_by_id.get("tool:shell-runner-server:run_shell", {}).get("evidence_tier") == "runtime_blocked"


def test_demo_estate_catalog_seeds_connections_sources_and_spend(shared_demo_estate_client: TestClient) -> None:
    """Connections, Sources, and AI Spend surfaces are populated on first demo boot."""
    from agent_bom.api.connection_store import get_connection_store
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    connections = get_connection_store().list_for_tenant(SHOWCASE_TENANT)
    assert len(connections) >= 3
    assert any(record.id.startswith("demo-conn-") for record in connections)
    demo_connection = next(record for record in connections if record.id.startswith("demo-conn-"))
    assert demo_connection.external_id_encrypted == ""
    from agent_bom.api.routes.cloud_connections import _reject_showcase_connection

    with pytest.raises(HTTPException) as exc_info:
        _reject_showcase_connection(demo_connection)
    assert exc_info.value.status_code == 409
    assert "synthetic" in str(exc_info.value.detail).lower()

    sources = shared_demo_estate_client.get("/v1/sources").json()
    source_rows = sources.get("sources") or []
    assert len(source_rows) >= 2
    assert any(row.get("source_id", "").startswith("demo-src-") for row in source_rows)

    counts = shared_demo_estate_client.get("/v1/posture/counts").json()
    services = counts.get("services") or {}
    assert services.get("cloud_accounts", {}).get("state") == "live"
    assert services.get("cloud_accounts", {}).get("count", 0) >= 3
    assert services.get("data_sources", {}).get("state") == "live"
    assert services.get("data_sources", {}).get("count", 0) >= 2
    assert services.get("ai_spend", {}).get("state") == "live"


def test_demo_estate_exposure_paths_materialized(shared_demo_estate_client: TestClient) -> None:
    """The bounded exposure-path queue reports materialized output truthfully.

    The broader synthetic estate can contain thousands of mixed governance and
    vulnerability candidates. Do not require a hand-authored demo chain to
    outrank stronger evidence in the first page; the reference evidence lab
    owns the real-CVE end-to-end proof contract.
    """
    payload = shared_demo_estate_client.get("/v1/graph/exposure-paths", headers=VIEWER, params={"limit": 10}).json()
    paths = payload.get("paths") or []

    assert payload.get("count") == len(paths) == 10, payload
    assert payload.get("total", 0) > len(paths), payload
    assert payload.get("completeness", {}).get("truncated") is True, payload
    assert payload.get("completeness", {}).get("reason") == "path_page_limit", payload
    # Same queue order as the dashboard: exploitability evidence first, stored risk within a tier.
    queue = shared_demo_estate_client.get("/v1/graph/attack-paths", headers=VIEWER, params={"limit": 10}).json()
    assert [path["id"] for path in paths] == [row["exposure_path"]["id"] for row in queue["attack_paths"]]
    assert [path["rank"] for path in paths] == list(range(1, 11))


def test_demo_estate_nhi_governance_tells_a_story(shared_demo_estate_client: TestClient) -> None:
    """NHI governance evaluates the seeded identities and surfaces at least one
    over-granted, one dormant/orphaned, and one clearly high/critical identity."""
    posture = shared_demo_estate_client.get("/v1/graph/nhi/governance", headers=VIEWER).json()
    assert posture.get("evaluated", 0) >= 5, posture
    counts = posture.get("counts") or {}
    assert counts.get("over_granted", 0) >= 1, counts
    assert counts.get("dormant", 0) >= 1, counts
    assert counts.get("orphaned", 0) >= 1, counts
    bands = counts.get("by_risk_band") or {}
    assert (bands.get("critical", 0) + bands.get("high", 0)) >= 1, bands

    # A dormant + orphaned admin identity is the headline risk.
    worst = (posture.get("identities") or [])[0]
    assert worst.get("is_dormant") and worst.get("is_orphaned"), worst
    assert worst.get("risk_band") in {"high", "critical"}, worst


def _graph_with_all_nodes(client: TestClient) -> dict:
    """Read every node, retaining only the bounded edge context of each page.

    Node cursor exhaustion does not establish edge completeness. Consumers that
    assert topology must read the relevant incident-edge cursors separately.
    """
    nodes: list[dict] = []
    edges: list[dict] = []
    seen: set[str] = set()
    payload: dict = {}
    cursor: str | None = None
    identity: dict[str, str] = {}
    for _page in range(20):  # bounded so a paging bug fails rather than hangs
        params: dict[str, object] = {"limit": 5000, **identity}
        if cursor:
            params["cursor"] = cursor
        response = demo_graph_get(client, "/v1/graph", params)
        assert response.status_code == 200, response.text
        payload = response.json()
        current = {key: payload[key] for key in ("scan_id", "snapshot_generation")}
        assert current["snapshot_generation"]
        assert not identity or identity == current
        identity = current
        for node in payload.get("nodes") or []:
            node_id = node.get("id")
            if node_id not in seen:
                seen.add(str(node_id))
                nodes.append(node)
        edges.extend(payload.get("edges") or [])
        cursor = payload.get("next_cursor") or (payload.get("pagination") or {}).get("next_cursor")
        if not cursor:
            break
    else:  # pragma: no cover - only reached when paging never terminates
        raise AssertionError("graph paging did not terminate")

    total = (payload.get("completeness") or {}).get("total")
    assert total is None or len(nodes) >= int(total), (len(nodes), total)
    # The last page's completeness/returned count describes that page, not
    # this node union. Do not promote it to whole-graph completeness.
    return {**identity, "nodes": nodes, "edges": edges}


def _outgoing_graph_edges(client: TestClient, graph: dict, node_ids: set[str], *, limit: int = 100) -> list[dict]:
    """Read recorded outgoing relationships for exact nodes in one revision."""
    identity = {key: graph[key] for key in ("scan_id", "snapshot_generation")}
    assert identity["scan_id"] and identity["snapshot_generation"]
    edges: dict[str, dict] = {}
    for node_id in sorted(node_ids):
        cursor: str | None = None
        seen_cursors: set[str] = set()
        for _page in range(100):
            params = {**identity, "node_id": node_id, "direction": "out", "limit": limit}
            if cursor:
                params["cursor"] = cursor
            response = demo_graph_get(client, "/v1/graph/incident-edges", params)
            assert response.status_code == 200, response.text
            page = response.json()
            assert page["found"], node_id
            assert {key: page[key] for key in identity} == identity
            assert page["node_id"] == node_id and page["direction"] == "out"
            completeness = page["completeness"]
            assert completeness["scope"] == "incident_edge_page"
            assert completeness["missing_endpoint_count"] == 0, page
            for edge in page["edges"]:
                assert edge["source"] == node_id, edge
                edges[edge["canonical_id"]] = edge
            cursor = page["next_cursor"]
            if not cursor:
                assert not completeness["truncated"], page
                break
            assert completeness["truncated"], page
            assert cursor not in seen_cursors, "incident-edge cursor repeated"
            seen_cursors.add(cursor)
        else:  # pragma: no cover - fail instead of hanging on broken paging
            raise AssertionError(f"incident-edge paging did not terminate for {node_id}")
    return list(edges.values())


def test_demo_estate_graph_carries_the_projected_estate(shared_demo_estate_client: TestClient) -> None:
    """The graph a prospect clicks IS the estate, not a 112-node stand-in."""
    payload = _graph_with_all_nodes(shared_demo_estate_client)
    nodes = payload.get("nodes") or []
    node_ids = {n.get("id") for n in nodes}
    by_type = Counter(n.get("entity_type") for n in nodes)

    assert len(nodes) >= 2500, len(nodes)
    # org → account → environment → asset, all four levels present.
    assert "org:enterprise:northstar-health-ai" in node_ids
    assert "account:aws:123456789012" in node_ids
    assert "env:aws:123456789012:production" in node_ids
    assert "cloud_resource:aws:iam:role:member-copilot-prod" in node_ids
    assert by_type["account"] >= 40, by_type
    assert by_type["environment"] >= 100, by_type
    assert by_type["misconfiguration"] >= 439, by_type

    # Node paging bounds each page's edges; read the parents' recorded edges completely.
    parents = {"org:enterprise:northstar-health-ai", "account:aws:123456789012", "env:aws:123456789012:production"}
    contains = {
        (row.get("source"), row.get("target"))
        for row in _outgoing_graph_edges(shared_demo_estate_client, payload, parents)
        if row.get("relationship") == "contains"
    }
    assert ("org:enterprise:northstar-health-ai", "account:aws:123456789012") in contains
    assert ("account:aws:123456789012", "env:aws:123456789012:production") in contains
    assert (
        "env:aws:123456789012:production",
        "cloud_resource:aws:iam:role:member-copilot-prod",
    ) in contains
    # One estate, one root: the hand-built showcase org hangs off the estate org.
    assert ("org:enterprise:northstar-health-ai", "org:corp") in contains


def test_demo_estate_graph_incident_chain_is_traversable(shared_demo_estate_client: TestClient) -> None:
    """workflow → role → workload → MCP tool → PHI table → hosted model.

    Asserts each landmark is *reachable* from the one before it, not that the
    two are directly adjacent. The chain names the six assets the incident story
    is told through; how many hops sit between them is a property of the estate,
    not of the story. Pinning adjacency made this a test of chain length — it
    broke the moment the estate started modelling the real intermediate assets
    (the ECR image the role deploys, the cluster hosting the workload, the MCP
    server publishing the tool, the database holding the table), all of which
    make the traversal *more* faithful, not less.
    """
    payload = _graph_with_all_nodes(shared_demo_estate_client)
    adjacency: dict[str, set[str]] = {}
    chain = (
        "github:workflow:member-copilot/deploy-prod",
        "cloud_resource:aws:iam:role:member-copilot-prod",
        "kubernetes:workload:member-ai-prod/ai-prod/member-copilot",
        "mcp:tool:clinical-analytics/execute_sql",
        "snowflake:table:nh_prod/analytics/phi/patient_summary",
        "model:openai:gpt-4.1",
    )
    node_ids = {n.get("id") for n in payload.get("nodes") or []}
    for hop in chain:
        assert hop in node_ids, f"missing incident hop {hop}"

    def _reaches(source: str, target: str, *, max_hops: int = 6) -> bool:
        frontier = {source}
        seen = {source}
        for _ in range(max_hops):
            # Expand only this investigation frontier, including intermediates,
            # instead of treating bounded page context as complete adjacency.
            unread = frontier - adjacency.keys()
            rows = _outgoing_graph_edges(shared_demo_estate_client, payload, unread)
            for node in unread:
                adjacency[node] = set()
            for row in rows:
                adjacency[row["source"]].add(row["target"])
            frontier = {nxt for node in frontier for nxt in adjacency.get(node, ())} - seen
            if target in frontier:
                return True
            if not frontier:
                return False
            seen |= frontier
        return False

    for source, target in zip(chain, chain[1:], strict=False):
        assert _reaches(source, target), f"incident chain broken at {source} -> {target}"


def test_demo_estate_findings_land_on_inventoried_graph_nodes(
    shared_demo_estate_client: TestClient,
) -> None:
    """No finding materialises its own stub target (the #4637 defect class)."""
    payload = _graph_with_all_nodes(shared_demo_estate_client)
    nodes_by_id = {n.get("id"): n for n in payload.get("nodes") or []}
    finding_ids = {node["id"] for node in nodes_by_id.values() if node.get("entity_type") == "misconfiguration"}
    affected: set[str] = set()
    for row in _outgoing_graph_edges(shared_demo_estate_client, payload, finding_ids):
        if row.get("relationship") != "affects":
            continue
        source = nodes_by_id.get(row.get("source")) or {}
        if source.get("entity_type") != "misconfiguration":
            continue
        target = nodes_by_id.get(row.get("target"))
        assert target is not None, row
        if (target.get("attributes") or {}).get("estate_id"):
            affected.add(row.get("target"))
    assert len(affected) >= 407, len(affected)


def test_demo_estate_default_graph_page_declares_its_truncation(
    shared_demo_estate_client: TestClient,
) -> None:
    """A bounded page must never read as the whole estate (#4631)."""
    payload = shared_demo_estate_client.get("/v1/graph", headers=VIEWER).json()
    completeness = payload.get("completeness") or {}
    stats = payload.get("stats") or {}

    assert completeness.get("truncated") is True, completeness
    assert completeness.get("complete") is False, completeness
    assert completeness.get("returned") == len(payload.get("nodes") or [])
    assert completeness.get("reason"), completeness
    # The two numbers a reader reconciles must agree.
    assert completeness.get("total") == stats.get("total_nodes_source"), (completeness, stats)
    assert completeness["total"] > completeness["returned"]


def test_demo_estate_graph_rolls_up_to_a_readable_estate(shared_demo_estate_client: TestClient) -> None:
    """2,000 raw nodes are unreadable — the default read is account → env → resource."""
    rollup = shared_demo_estate_client.get("/v1/graph/rollup", headers=VIEWER).json()
    top_level = rollup.get("top_level") or []
    containers = [row for row in top_level if row.get("is_container") and row.get("has_children")]
    root_ids = {row.get("id") for row in containers}
    assert "org:enterprise:northstar-health-ai" in root_ids, root_ids

    root = next(row for row in containers if row["id"] == "org:enterprise:northstar-health-ai")
    assert root["aggregate"]["descendant_count"] >= 2500, root["aggregate"]
    assert rollup["summary"]["total_nodes_source"] >= 2500, rollup["summary"]

    accounts = shared_demo_estate_client.get(
        "/v1/graph/rollup",
        headers=VIEWER,
        params={"node": "org:enterprise:northstar-health-ai"},
    ).json()
    account_ids = {row.get("id") for row in accounts.get("children") or []}
    assert "account:aws:123456789012" in account_ids
    assert len(account_ids) >= 40, len(account_ids)

    envs = shared_demo_estate_client.get("/v1/graph/rollup", headers=VIEWER, params={"node": "account:aws:123456789012"}).json()
    env_children = {row.get("id"): row for row in envs.get("children") or []}
    assert "env:aws:123456789012:production" in env_children, list(env_children)

    resources = shared_demo_estate_client.get("/v1/graph/rollup", headers=VIEWER, params={"node": "env:aws:123456789012:production"}).json()
    assert resources.get("children"), resources


def test_default_graph_page_carries_the_containment_spine(shared_demo_estate_client: TestClient) -> None:
    """The first page a client gets must describe a shaped estate, not a heap.

    ``/v1/graph`` orders nodes by severity. Once the estate carries more
    high-severity findings than a page holds — 2,582 findings against a default
    limit of 500 — every org, account and environment ranks below the cut, and
    the default response contains findings floating with no structure. It looked
    correct only while the estate was small enough that the spine happened to
    fit inside the page.

    Containment ancestors are few at any estate size, so they are resolved
    explicitly and added on top of the page rather than left to compete on rank.
    """
    payload = shared_demo_estate_client.get("/v1/graph", headers=VIEWER).json()
    nodes = payload.get("nodes") or []
    kinds = {str(node.get("type") or node.get("entity_type") or "") for node in nodes}
    assert {"org", "account"} <= kinds, f"default page has no containment spine: {sorted(kinds)}"

    node_ids = {node.get("id") for node in nodes}
    contains = {
        (row.get("source"), row.get("target"))
        for row in payload.get("edges") or []
        if row.get("relationship") in {"contains", "hosts", "owns"}
    }
    linked = [pair for pair in contains if pair[0] in node_ids and pair[1] in node_ids]
    assert linked, "containment nodes arrived with no edge joining them to the page"
