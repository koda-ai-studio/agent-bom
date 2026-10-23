from __future__ import annotations

import inspect
import os
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.demo_estate.showcase_graph import SHOWCASE_BASELINE_SCAN_ID
from tests._demo_estate_fixtures import VIEWER, demo_graph_get


def test_demo_bootstrap_log_does_not_emit_raw_graph_owner_scan_id() -> None:
    """Keep the exact owner in the summary without copying it into logs."""
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    source = inspect.getsource(maybe_bootstrap_demo_estate)
    assert "graph_owner_scan_id=%s" not in source
    assert "graph_owner_scan_id_present=%s" in source


def test_demo_estate_bootstrap_seeds_honest_posture_trajectory(
    demo_estate_client: TestClient,
) -> None:
    """Recorded stages move through the live trend path and end at the headline."""
    from agent_bom.demo_estate.showcase_graph import (
        SHOWCASE_BASELINE_CREATED_AT,
        SHOWCASE_CURRENT_CREATED_AT,
        SHOWCASE_SCAN_ID,
    )

    response = demo_estate_client.get("/v1/trends", headers=VIEWER, params={"limit": 30})

    assert response.status_code == 200, response.text
    payload = response.json()
    points = payload["data_points"]
    assert payload["count"] >= 5
    current = points[0]
    assert current["scan_id"] == SHOWCASE_SCAN_ID
    assert current["timestamp"] == SHOWCASE_CURRENT_CREATED_AT
    baseline = next(point for point in points if point["scan_id"] == SHOWCASE_BASELINE_SCAN_ID)
    assert baseline["timestamp"] == SHOWCASE_BASELINE_CREATED_AT
    assert all(point["issues"] and point["issues"]["basis"] == "issue_groups" for point in points)
    # Movement comes from the recorded evidence, not a constant series.
    assert len({(point["issues"]["critical"], point["issues"]["high"]) for point in points}) >= 4
    comparable = [point["comparison"] for point in points if point["comparison"]["status"] == "comparable"]
    assert len(comparable) >= 4
    assert sum(item["new_findings"] for item in comparable) > 0
    assert sum(item["no_longer_detected"] for item in comparable) > 0
    assert current["verified_remediations"] is None
    # The latest point is the headline the posture endpoints serve right now.
    counts = demo_estate_client.get("/v1/posture/counts", headers=VIEWER).json()["issues"]
    for key in ("critical", "high", "medium", "low", "total"):
        assert current["issues"][key] == counts[key], key
    posture = demo_estate_client.get("/v1/posture", headers=VIEWER).json()
    assert (current["posture_grade"], current["posture_score"]) == (posture["grade"], posture["score"])
    findings = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"status": "suppressed", "limit": 1}).json()
    assert findings.get("total", 0) == 0, "suppressed history findings were fixed before the current scan"

    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    assert maybe_bootstrap_demo_estate().get("reason") == "demo_jobs_present"
    repeated = demo_estate_client.get("/v1/trends", headers=VIEWER, params={"limit": 30}).json()
    assert repeated["count"] == payload["count"]


def test_demo_estate_bootstrap_validates_versioned_enterprise_contract(
    demo_estate_client: TestClient,
) -> None:
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
    from agent_bom.demo_estate.enterprise import ENTERPRISE_SCHEMA_VERSION

    summary = maybe_bootstrap_demo_estate()
    contract = summary.get("enterprise_contract") or {}

    assert contract["schema_version"] == ENTERPRISE_SCHEMA_VERSION
    # The demo now boots the narrative estate composed into a generated
    # population, so the id gains its suffix and the floors move from
    # "the story exists" to "the story sits inside an enterprise". The old
    # values (20 assets, 15 observations) passed against an estate too small
    # to demonstrate correlation at all.
    assert contract["estate_id"] == "northstar-health-ai-v1-composed"
    assert contract["assets"] >= 2000
    assert contract["observations"] >= 6000
    assert contract["snapshots"] == 3
    assert contract["partial_sources"] == ["gcp_audit"]
    assert len(contract["content_hash"]) == 64


def test_demo_estate_status_never_presents_a_non_demo_snapshot(
    demo_estate_client: TestClient,
) -> None:
    """A non-showcase snapshot in the demo store blocks the demo instead of being shown as sample data."""
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
    from agent_bom.demo_estate.showcase_graph import (
        SHOWCASE_CURRENT_CREATED_AT,
        SHOWCASE_TENANT,
    )
    from agent_bom.graph.container import UnifiedGraph
    from agent_bom.graph.node import UnifiedNode
    from agent_bom.graph.types import EntityType

    operator_graph = UnifiedGraph(
        scan_id="operator-scan",
        tenant_id=SHOWCASE_TENANT,
        created_at=(datetime.fromisoformat(SHOWCASE_CURRENT_CREATED_AT) + timedelta(days=1)).isoformat(),
    )
    operator_graph.add_node(
        UnifiedNode(
            id="agent:operator",
            entity_type=EntityType.AGENT,
            label="Operator scan",
        )
    )
    api_stores._get_graph_store().save_graph(operator_graph)
    summary = maybe_bootstrap_demo_estate()
    assert summary["seeded"] is False
    assert summary["blocked"] == "non_demo_snapshot_present"

    response = demo_estate_client.get("/v1/demo-estate/status", headers=VIEWER)

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["showcase_available"] is True
    assert payload["graph_owner_scan_id"] is None
    assert payload["graph_alignment"] == "blocked"
    assert payload["reason"] == "non_demo_snapshot_present"
    assert "operator-scan" not in response.text


<<<<<<< HEAD
=======
def test_demo_estate_graph_is_a_rich_multi_agent_estate(demo_estate_client: TestClient) -> None:
    # Reads the whole snapshot rather than the default page. Since the
    # enterprise estate is projected into this snapshot it holds ~2,900 nodes,
    # and the default page is 500 ordered by severity — which the estate's 439
    # posture findings now fill. The agents/servers/packages asserted here are
    # unrated inventory, so a default-page read would be testing the pager, not
    # the estate. ``test_demo_estate_default_graph_page_declares_its_truncation``
    # covers the bounded read.
    payload = _graph_with_all_nodes(demo_estate_client)
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


def test_demo_estate_headline_blast_radius_chain(demo_estate_client: TestClient) -> None:
    """agent -> MCP server -> vulnerable package -> critical CVE -> reachable
    credential + reachable run_shell tool -> potential RCE renders in the graph.

    Whole snapshot, not the default page: the hand-built chain is *extended* by
    the projected enterprise estate, never replaced, but its unrated inventory
    nodes no longer land in a 500-row severity-ranked page.
    """
    payload = _graph_with_all_nodes(demo_estate_client)
    node_ids = {n.get("id") for n in payload.get("nodes") or []}
    # Node pages carry bounded incident evidence. Read the chain's source
    # relationships explicitly; limit=2 also exercises cursor continuation.
    edges = _outgoing_graph_edges(
        demo_estate_client,
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


def test_demo_estate_findings_include_critical_and_kev(demo_estate_client: TestClient) -> None:
    result = _demo_report(demo_estate_client)
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


def test_demo_estate_hero_findings_carry_the_persisted_graph_path(demo_estate_client: TestClient) -> None:
    """The scan and graph surfaces must tell the same hero-path story."""
    result = _demo_report(demo_estate_client)
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

    listing = demo_estate_client.get(
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


def test_demo_estate_graph_evidence_covers_every_hand_built_path(demo_estate_client: TestClient) -> None:
    """Every hand-built path is evidenced on its finding, and no other row borrows one."""
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_PACKAGES

    blast = _demo_report(demo_estate_client).get("blast_radius") or []
    evidenced = [row for row in blast if row.get("graph_reachable") is True]
    paths = {f"{row.get('package_name')}@{row.get('package_version')}".lower() for row in evidenced}

    assert paths == set(SHOWCASE_PACKAGES), sorted(paths ^ set(SHOWCASE_PACKAGES))
    assert all((row.get("asset") or {}).get("asset_type") == "mcp_server" for row in evidenced)


def test_demo_estate_posture_findings_resolve_to_inventoried_assets(
    demo_estate_client: TestClient,
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

    listing = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1000, "domain": "cspm"}).json()
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
    demo_estate_client: TestClient,
) -> None:
    """One estate, one total — whatever surface is asked.

    The tile, the list header, and the severity facet histogram are three
    different code paths over the same evidence. Adding hundreds of posture
    findings is exactly the change that makes them drift apart, so pin them
    together on the seeded estate rather than trusting that they agree.
    """
    listing = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1, "include_facets": "true"}).json()
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

    counts = demo_estate_client.get("/v1/posture/counts", headers=VIEWER).json()
    assert "unrated" in counts, counts
    assert sum(counts[band] for band in ("critical", "high", "medium", "low", "unrated")) == counts["total"], counts
    assert counts["unrated"] > 0, (
        "no unrated finding survives to the tiles, so an unevaluable control is indistinguishable from one that passed"
    )

    # The bounded page reports the unbounded total, never its own size.
    page = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 25}).json()
    assert len(page["findings"]) <= 25
    assert page["total"] == total > len(page["findings"]), (page["total"], len(page["findings"]))


def test_demo_estate_cis_posture_spans_every_estate_cloud(demo_estate_client: TestClient) -> None:
    result = _demo_report(demo_estate_client)
    # The CIS benchmark blobs are derived from the estate's own CIS findings, so
    # every cloud the estate evaluates is present, Snowflake included.
    for key in ("cis_benchmark", "gcp_cis_benchmark", "azure_cis_benchmark", "snowflake_cis_benchmark"):
        checks = (result.get(key) or {}).get("checks") or []
        assert checks, f"expected CIS checks for {key}"
        # Only recorded results: the estate records failures and unevaluable
        # attempts, never a pass it did not observe.
        assert {c.get("status") for c in checks} <= {"fail", "error"}, key

    # The rows normalize through the same contract the /v1/cis/checks route uses.
    from agent_bom.analytics_contract import build_cis_benchmark_check_rows

    rows = build_cis_benchmark_check_rows(result, "showcase")
    assert set(Counter(r["cloud"] for r in rows)) == {"aws", "gcp", "azure", "snowflake"}
    assert Counter(r["status"] for r in rows)["fail"] == 28


def test_demo_estate_gateway_feed_shows_the_ai_firewall(demo_estate_client: TestClient) -> None:
    """The gateway live feed renders authorized / blocked / shadow / redacted
    tool-call events on the demo — the AI-firewall differentiator."""
    feed = demo_estate_client.get("/v1/gateway/feed")
    assert feed.status_code == 200, feed.text
    payload = feed.json()
    events = payload.get("events") or []
    assert len(events) >= 12, f"expected a dense gateway feed, got {len(events)}"

    by_action = Counter(e.get("action_type") for e in events)
    # A believable mix mirroring a real AI-firewall feed.
    assert by_action["tool_call_authorized"] >= 5, by_action
    assert by_action["tool_call_blocked"] >= 5, by_action
    assert by_action["data_filter_applied"] >= 2, by_action

    # Shadow / undeclared-agent blocks are labeled as such.
    shadow = [e for e in events if e.get("shadow")]
    assert len(shadow) >= 2, "expected shadow/undeclared-agent blocks in the feed"
    assert any("shadow" in (e.get("agent") or "").lower() for e in shadow)

    # Attribution uses the showcase graph's real agent names.
    agents = {e.get("agent") for e in events}
    assert {"Cursor", "Claude Desktop", "Data Pipeline"} & agents

    # Feed is time-ordered newest-first and redaction-safe (metadata only).
    ts_values = [e.get("ts") for e in events]
    assert ts_values == sorted(ts_values, reverse=True)
    for e in events:
        assert "arguments" not in e and "response" not in e


def test_demo_estate_gateway_feed_kpis_populated(demo_estate_client: TestClient) -> None:
    kpis = demo_estate_client.get("/v1/gateway/feed/kpis").json()
    assert kpis.get("calls_today", 0) >= 12, kpis
    assert kpis.get("blocked_today", 0) >= 5, kpis
    assert kpis.get("shadow_ai_blocked", 0) >= 2, kpis
    assert kpis.get("data_filters_applied", 0) >= 2, kpis
    assert kpis.get("uptime_seconds", 0) > 0, kpis


def test_demo_estate_runtime_production_index_has_traffic(demo_estate_client: TestClient) -> None:
    idx = demo_estate_client.get("/v1/runtime/production-index", headers=VIEWER).json()
    assert idx.get("status") == "ok", idx
    traffic = idx.get("traffic") or {}
    assert traffic.get("total_tool_calls", 0) > 100, traffic
    assert traffic.get("blocked_tool_calls", 0) > 0, traffic
    assert traffic.get("uptime_seconds", 0) > 0, traffic
    trace = (idx.get("authorization_trace") or {}).get("recent") or []
    assert trace, "expected recent authorization-trace events"


def test_demo_estate_firewall_stats_require_audit_permission(demo_estate_client: TestClient) -> None:
    response = demo_estate_client.get("/v1/firewall/stats")
    assert response.status_code == 403
    assert "audit_read" in response.json()["detail"]


>>>>>>> f18d23714 (fix(compliance): read CIS failures from the graph and stop implying passes)
def test_demo_estate_gateway_feed_is_idempotent(demo_estate_client: TestClient) -> None:
    first = len(demo_estate_client.get("/v1/gateway/feed").json().get("events") or [])
    from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events

    again = seed_showcase_gateway_events()
    assert again.get("seeded") is False and again.get("reason") == "already_present"
    second = len(demo_estate_client.get("/v1/gateway/feed").json().get("events") or [])
    assert second == first


def test_demo_estate_catalog_is_idempotent(demo_estate_client: TestClient) -> None:
    from agent_bom.demo_estate.showcase_catalog import seed_showcase_catalog_if_empty

    again = seed_showcase_catalog_if_empty()
    assert again.get("seeded") is False and again.get("reason") == "catalog_present"


def test_showcase_catalog_needs_no_ephemeral_key_and_is_tenant_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.api.connection_crypto import CONNECTIONS_KEY_ENV
    from agent_bom.api.connection_store import InMemoryConnectionStore
    from agent_bom.api.cost_store import InMemoryCostStore
    from agent_bom.api.source_store import InMemorySourceStore
    from agent_bom.demo_estate import showcase_catalog

    connection_store = InMemoryConnectionStore()
    source_store = InMemorySourceStore()
    cost_store = InMemoryCostStore()
    monkeypatch.delenv(CONNECTIONS_KEY_ENV, raising=False)
    monkeypatch.setattr(showcase_catalog, "get_connection_store", lambda: connection_store)
    monkeypatch.setattr(showcase_catalog, "_get_source_store", lambda: source_store)
    monkeypatch.setattr(showcase_catalog, "get_cost_store", lambda: cost_store)

    first = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-a")
    second = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-a")
    other = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="tenant-b")

    assert first == {"seeded": True, "connections": 3, "sources": 2, "cost_samples": 1}
    assert second.get("seeded") is False and second.get("reason") == "catalog_present"
    assert other.get("seeded") is True
    assert CONNECTIONS_KEY_ENV not in os.environ
    tenant_a_connections = connection_store.list_for_tenant("tenant-a")
    tenant_b_connections = connection_store.list_for_tenant("tenant-b")
    assert len(tenant_a_connections) == len(tenant_b_connections) == 3
    assert {row.id for row in tenant_a_connections}.isdisjoint({row.id for row in tenant_b_connections})
    assert all(not row.external_id_encrypted for row in tenant_a_connections)
    assert len(source_store.list_all("tenant-a")) == 2
    assert len(source_store.list_all("tenant-b")) == 2
    assert len(cost_store.list_records("tenant-a")) == 1
    assert len(cost_store.list_records("tenant-b")) == 1


def test_showcase_catalog_retry_heals_partial_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.connection_store import InMemoryConnectionStore
    from agent_bom.api.cost_store import InMemoryCostStore
    from agent_bom.api.source_store import InMemorySourceStore
    from agent_bom.demo_estate import showcase_catalog

    connection_store = InMemoryConnectionStore()
    source_store = InMemorySourceStore()
    cost_store = InMemoryCostStore()
    original_put = source_store.put
    should_fail = True

    def flaky_put(source, **kwargs) -> None:
        nonlocal should_fail
        if should_fail:
            should_fail = False
            raise RuntimeError("injected source failure")
        original_put(source, **kwargs)

    monkeypatch.setattr(showcase_catalog, "get_connection_store", lambda: connection_store)
    monkeypatch.setattr(showcase_catalog, "_get_source_store", lambda: source_store)
    monkeypatch.setattr(showcase_catalog, "get_cost_store", lambda: cost_store)
    monkeypatch.setattr(source_store, "put", flaky_put)

    with pytest.raises(RuntimeError, match="injected source failure"):
        showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="retry-tenant")

    summary = showcase_catalog.seed_showcase_catalog_if_empty(tenant_id="retry-tenant")
    assert summary == {"seeded": True, "connections": 0, "sources": 2, "cost_samples": 1}
    assert len(connection_store.list_for_tenant("retry-tenant")) == 3
    assert len(source_store.list_all("retry-tenant")) == 2
    assert len(cost_store.list_records("retry-tenant")) == 1


def test_demo_estate_bootstrap_is_idempotent(demo_estate_client: TestClient) -> None:
    first = demo_estate_client.get("/v1/jobs", headers=VIEWER).json()
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate

    second = maybe_bootstrap_demo_estate()
    assert second.get("reason") == "demo_jobs_present"
    again = demo_estate_client.get("/v1/jobs", headers=VIEWER).json()
    assert again.get("total") == first.get("total")


def test_demo_estate_reseeds_when_marker_job_has_no_findings(
    demo_estate_client: TestClient,
) -> None:
    """A demo-tagged job with empty findings must not block reseed (empty demo)."""
    import uuid

    from agent_bom.api import stores as api_stores
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.pipeline import _now
    from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY
    from agent_bom.demo_estate.bootstrap import maybe_bootstrap_demo_estate
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    store = api_stores._get_store()
    for job in list(store.list_all(tenant_id=SHOWCASE_TENANT)):
        store.delete(job.job_id, tenant_id=SHOWCASE_TENANT)

    empty = ScanJob(
        job_id=str(uuid.uuid4()),
        tenant_id=SHOWCASE_TENANT,
        triggered_by=DEMO_ESTATE_TRIGGERED_BY,
        created_at=_now(),
        request=ScanRequest(offline=True),
    )
    empty.status = JobStatus.DONE
    empty.completed_at = _now()
    empty.result = {"scan_sources": ["demo", "demo-estate"], "findings": [], "agents": []}
    store.put(empty)

    before_total = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert before_total.get("total", 0) == 0

    summary = maybe_bootstrap_demo_estate()
    assert summary.get("seeded") is True, summary
    assert (summary.get("findings") or 0) >= 1

    after = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert after.get("total", 0) > 0


def test_demo_estate_survives_job_ttl_cleanup(demo_estate_client: TestClient) -> None:
    """API job TTL must not delete curated demo-estate scan jobs."""
    from agent_bom.api import stores as api_stores
    from agent_bom.api.pipeline import _now
    from agent_bom.api.store import DEMO_ESTATE_TRIGGERED_BY
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    store = api_stores._get_store()
    demo_jobs = [job for job in store.list_all(tenant_id=SHOWCASE_TENANT) if getattr(job, "triggered_by", None) == DEMO_ESTATE_TRIGGERED_BY]
    assert demo_jobs, "precondition: bootstrap seeded a demo-estate job"
    for job in demo_jobs:
        job.completed_at = "2020-01-01T00:00:00+00:00"
        store.put(job)

    removed = store.cleanup_expired(ttl_seconds=1)
    remaining = [job for job in store.list_all(tenant_id=SHOWCASE_TENANT) if getattr(job, "triggered_by", None) == DEMO_ESTATE_TRIGGERED_BY]
    assert remaining, f"demo estate jobs were purged by TTL (removed={removed})"

    # Restore a current completed_at so the default findings window still sees them.
    now = _now()
    for job in remaining:
        job.completed_at = now
        store.put(job)
    findings = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 1}).json()
    assert findings.get("total", 0) > 0


def test_demo_estate_agents_fall_back_to_demo_inventory(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """On a hosted server local discovery is empty; the demo estate falls back to
    the curated inventory so /v1/agents + /v1/agents/mesh are non-empty and
    correlated with the graph agents."""
    import agent_bom.discovery as discovery_mod

    monkeypatch.setattr(discovery_mod, "discover_all", lambda: [])
    from agent_bom.api.routes.discovery import _clear_agents_response_cache_for_tests

    _clear_agents_response_cache_for_tests()

    agents = demo_estate_client.get("/v1/agents", headers=VIEWER).json()
    names = {a.get("name") for a in agents.get("agents", [])}
    assert agents.get("count", 0) >= 5, agents
    assert {"cursor", "langchain-service", "support-copilot"} <= names, names

    mesh = demo_estate_client.get("/v1/agents/mesh", headers=VIEWER).json()
    assert len(mesh.get("nodes") or []) >= 5, mesh

    detail = demo_estate_client.get("/v1/agents/support-copilot", headers=VIEWER)
    assert detail.status_code == 200, detail.text
    assert detail.json()["agent"]["name"] == "support-copilot"

    lifecycle = demo_estate_client.get("/v1/agents/support-copilot/lifecycle", headers=VIEWER)
    assert lifecycle.status_code == 200, lifecycle.text


def test_demo_estate_agents_no_fallback_without_demo_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Env unset ⇒ live discovery only; the demo inventory is never injected."""
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    import agent_bom.discovery as discovery_mod
    from agent_bom.api.routes.discovery import _discover_agents_with_demo_fallback

    monkeypatch.setattr(discovery_mod, "discover_all", lambda: [])
    assert _discover_agents_with_demo_fallback() == []


@pytest.mark.parametrize("durable", [False, True])
def test_demo_estate_scan_findings_restored_after_restart(
    demo_estate_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
    durable: bool,
) -> None:
    """Restart retains durable jobs or re-seeds an empty in-memory job store."""
    from agent_bom.api import stores as api_stores
    from agent_bom.demo_estate.bootstrap import (
        _tenant_has_demo_jobs,
        maybe_bootstrap_demo_estate,
    )
    from agent_bom.demo_estate.showcase_graph import SHOWCASE_TENANT

    before = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 3}).json()
    assert before.get("total", 0) > 0

    # The persisted graph survives both job-store lifecycle policies.
    if not durable:
        monkeypatch.delenv("AGENT_BOM_DB")
    api_stores._store = None
    assert _tenant_has_demo_jobs(api_stores._get_store(), SHOWCASE_TENANT) is durable

    summary = maybe_bootstrap_demo_estate()
    assert summary.get("seeded") is (not durable), summary

    after = demo_estate_client.get("/v1/findings", headers=VIEWER, params={"limit": 3}).json()
    assert after.get("total", 0) == before.get("total", 0), (before.get("total"), after.get("total"))


# ── Enterprise estate projected into the graph ────────────────────────────
#
# Once the estate is in the graph the snapshot no longer fits one severity-ranked
# API page, so these read the whole snapshot explicitly and separately assert
# that the *default* page says so rather than reading as the estate.


def test_demo_topology_reader_honors_bounded_backpressure(demo_estate_client):
    from agent_bom.backpressure import _controller_for

    controller = _controller_for("graph")
    controller.open_until_monotonic = time.monotonic() + 1
    controller.last_trigger_reason = "p99_latency_threshold"
    response = demo_graph_get(demo_estate_client, "/v1/graph", {"limit": 1})
    assert response.status_code == 200, response.text
    assert controller.rejected >= 1


# ── UTC day rollover ────────────────────────────────────────────────────────
#
# CI caught this the hard way: a run whose demo bootstrap landed at 23:59 and
# whose request landed at 00:00:04 read ``calls_today: 0`` and failed
# ``assert 0 >= 12``. The same clock makes the hosted demo claim no traffic on
# an estate the tile beside it describes as busy, and left the seeded LLM spend
# permanently invisible — its guard treated "any records exist" as "already
# seeded", so it never re-seeded at all.
#
# Running these once proves nothing, so nothing below reads the wall clock for
# the behaviour under test: evidence is seeded against an explicit yesterday and
# is read back through the real ``[UTC midnight, now]`` window.


def _seed_only_yesterdays_evidence() -> datetime:
    """Reset the day-scoped stores and leave them holding yesterday's demo data.

    Covers both halves of the rollover: the gateway feed (which the maintenance
    loop reseeds, so it was merely late) and the seeded LLM spend (which was
    guarded on "any records exist" and so never came back at all).
    """
    from agent_bom.api import cost_store
    from agent_bom.api import stores as api_stores
    from agent_bom.api.gateway_activity_store import get_gateway_activity_store
    from agent_bom.api.routes.proxy import _reset_proxy_runtime_for_tests
    from agent_bom.demo_estate.bootstrap import reset_daily_evidence_day
    from agent_bom.demo_estate.showcase_gateway import seed_showcase_gateway_events
    from agent_bom.demo_estate.showcase_governance import _seed_cost_records

    _reset_proxy_runtime_for_tests()
    api_stores._get_firewall_decision_store().reset()
    reset_gateway_activity = getattr(get_gateway_activity_store(), "reset", None)
    if callable(reset_gateway_activity):
        reset_gateway_activity()
    # The client uses SQLite. Clearing the singleton would reopen its seeded
    # database, including today's records, instead of establishing yesterday's
    # pre-state. Keep this simulated rollover isolated from persisted boot data.
    cost_store.set_cost_store(cost_store.InMemoryCostStore())
    reset_daily_evidence_day()

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    seeded = seed_showcase_gateway_events(now=yesterday)
    assert seeded.get("seeded") is True, seeded
    assert _seed_cost_records(tenant_id="default", now=yesterday) > 0
    records = cost_store.get_cost_store().list_records("default", limit=5000)
    assert max(record.observed_at[:10] for record in records) == yesterday.date().isoformat()
    return yesterday


def test_yesterdays_gateway_evidence_is_outside_todays_kpi_window() -> None:
    """The mechanism itself: day-scoped evidence goes dark when the day turns.

    Pinned separately from the fix so a future change that stops scoping the
    seed to a single UTC day fails here loudly rather than quietly making the
    rollover test below tautological.
    """
    from agent_bom.demo_estate.showcase_gateway import _event_time

    yesterday = datetime.now(timezone.utc) - timedelta(days=1)
    todays_window_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)

    for minutes_ago in (0, 1, 20):
        assert _event_time(yesterday, minutes_ago) < todays_window_start


def test_yesterday_fixture_replaces_persisted_cost_evidence(demo_estate_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """Resetting a singleton must not reopen the boot day's SQLite evidence."""
    from agent_bom.api import cost_store
    from agent_bom.demo_estate.showcase_governance import _seed_cost_records

    class Midnight(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 9, 15, 0, 0, 2, tzinfo=timezone.utc)

    monkeypatch.setattr(f"{__name__}.datetime", Midnight)
    yesterday = Midnight.now(timezone.utc) - timedelta(days=1)
    _seed_cost_records(tenant_id="default", now=yesterday)

    _seed_only_yesterdays_evidence()

    records = cost_store.get_cost_store().list_records("default", limit=5000)
    assert records
    assert max(record.observed_at[:10] for record in records) == yesterday.date().isoformat()


def test_gateway_kpis_recover_after_a_utc_day_rollover(demo_estate_client: TestClient) -> None:
    """A request landing on the far side of midnight still reports the estate."""
    _seed_only_yesterdays_evidence()

    # Pre-state: the stores hold demo evidence, but none of it is inside the
    # window the KPI header reports on. This is precisely what CI saw.
    from agent_bom.api.routes.proxy import _load_proxy_alerts

    today = datetime.now(timezone.utc).date().isoformat()
    assert not [alert for alert in _load_proxy_alerts("default") if str(alert.get("ts") or "").startswith(today)]

    kpis = demo_estate_client.get("/v1/gateway/feed/kpis").json()

    assert kpis.get("calls_today", 0) >= 12, kpis
    assert kpis.get("blocked_today", 0) >= 5, kpis
    assert kpis.get("shadow_ai_blocked", 0) >= 2, kpis
    assert kpis.get("data_filters_applied", 0) >= 2, kpis
    # The spend half of the same rollover: this one never self-healed.
    assert kpis.get("llm_calls", 0) > 0, kpis


def test_daily_refresh_does_not_reseed_twice_in_one_day(demo_estate_client: TestClient) -> None:
    """The per-request hook must cost one comparison, not a reseed each time."""
    from agent_bom.demo_estate.bootstrap import refresh_demo_daily_evidence

    _seed_only_yesterdays_evidence()
    demo_estate_client.get("/v1/gateway/feed/kpis")

    assert refresh_demo_daily_evidence() == {
        "refreshed": False,
        "reason": "current",
        "day": datetime.now(timezone.utc).date().isoformat(),
    }


def test_daily_refresh_is_a_no_op_outside_demo_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Every deployment pays for this hook; only the demo may act on it."""
    from agent_bom.demo_estate.bootstrap import refresh_demo_daily_evidence, reset_daily_evidence_day

    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    reset_daily_evidence_day()

    assert refresh_demo_daily_evidence() == {"refreshed": False, "reason": "disabled"}


def test_refreshed_demo_graph_gets_matching_scan_evidence(demo_estate_client, monkeypatch):
    from agent_bom.api.server import _cleanup_tick
    from agent_bom.api.stores import _get_store
    from agent_bom.demo_estate import bootstrap

    store = _get_store()
    before = store.list_all(tenant_id="default")
    report = next(job.result for job in before if job.result and bootstrap._job_has_demo_source(job))
    monkeypatch.setattr(bootstrap, "seed_showcase_graph_if_empty", lambda *args, **kwargs: True)
    monkeypatch.setattr(bootstrap, "_run_demo_scan_report", lambda **kwargs: report)
    refreshed = bootstrap.maybe_bootstrap_demo_estate(tenant_id="default")
    assert refreshed["seeded"] is True
    assert len(store.list_all(tenant_id="default")) == len(before) + 1
    monkeypatch.setattr(bootstrap, "seed_showcase_graph_if_empty", lambda *args, **kwargs: False)
    assert bootstrap.maybe_bootstrap_demo_estate(tenant_id="default")["reason"] == "demo_jobs_present"
    assert len(store.list_all(tenant_id="default")) == len(before) + 1
    # A real maintenance pass must preserve the already-refreshed evidence.
    demo_estate_client.portal.call(_cleanup_tick)
    assert len(store.list_all(tenant_id="default")) == len(before) + 1


# The gateway feed, KPIs and identity tile read in-memory stores that the
# per-test global reset clears, so they need a seed booted for the test itself.
def test_demo_estate_gateway_feed_shows_the_ai_firewall(demo_estate_client: TestClient) -> None:
    """The gateway live feed renders authorized / blocked / shadow / redacted
    tool-call events on the demo — the AI-firewall differentiator."""
    feed = demo_estate_client.get("/v1/gateway/feed")
    assert feed.status_code == 200, feed.text
    payload = feed.json()
    events = payload.get("events") or []
    assert len(events) >= 12, f"expected a dense gateway feed, got {len(events)}"

    by_action = Counter(e.get("action_type") for e in events)
    # A believable mix mirroring a real AI-firewall feed.
    assert by_action["tool_call_authorized"] >= 5, by_action
    assert by_action["tool_call_blocked"] >= 5, by_action
    assert by_action["data_filter_applied"] >= 2, by_action

    # Shadow / undeclared-agent blocks are labeled as such.
    shadow = [e for e in events if e.get("shadow")]
    assert len(shadow) >= 2, "expected shadow/undeclared-agent blocks in the feed"
    assert any("shadow" in (e.get("agent") or "").lower() for e in shadow)

    # Attribution uses the showcase graph's real agent names.
    agents = {e.get("agent") for e in events}
    assert {"Cursor", "Claude Desktop", "Data Pipeline"} & agents

    # Feed is time-ordered newest-first and redaction-safe (metadata only).
    ts_values = [e.get("ts") for e in events]
    assert ts_values == sorted(ts_values, reverse=True)
    for e in events:
        assert "arguments" not in e and "response" not in e


def test_demo_estate_gateway_feed_kpis_populated(demo_estate_client: TestClient) -> None:
    kpis = demo_estate_client.get("/v1/gateway/feed/kpis").json()
    assert kpis.get("calls_today", 0) >= 12, kpis
    assert kpis.get("blocked_today", 0) >= 5, kpis
    assert kpis.get("shadow_ai_blocked", 0) >= 2, kpis
    assert kpis.get("data_filters_applied", 0) >= 2, kpis
    assert kpis.get("uptime_seconds", 0) > 0, kpis


def test_demo_estate_overview_identity_tile_populated(demo_estate_client: TestClient) -> None:
    """The Overview NHI/Identity tile reads the live identity store, which the
    demo seed populates, so it is no longer 0/idle."""
    overview = demo_estate_client.get("/v1/overview").json()
    identity = overview["domains"]["identity"]
    assert identity["metric"] >= 5, identity
    assert identity["detail"]["managed_identities"] >= 5, identity
    assert identity["status"] != "idle", identity


# Reads the in-memory runtime index, which the autouse reset clears between tests.
def test_demo_estate_runtime_production_index_has_traffic(demo_estate_client: TestClient) -> None:
    idx = demo_estate_client.get("/v1/runtime/production-index", headers=VIEWER).json()
    assert idx.get("status") == "ok", idx
    traffic = idx.get("traffic") or {}
    assert traffic.get("total_tool_calls", 0) > 100, traffic
    assert traffic.get("blocked_tool_calls", 0) > 0, traffic
    assert traffic.get("uptime_seconds", 0) > 0, traffic
    trace = (idx.get("authorization_trace") or {}).get("recent") or []
    assert trace, "expected recent authorization-trace events"
