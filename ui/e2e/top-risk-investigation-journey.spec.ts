import { expect, test, type Page } from "@playwright/test";

// The ranked occurrence, its canonical node, and a path that records only the advisory.
const occurrenceId = "7a1c0e52-0000-5000-8000-000000000001";
const packageNode = "pkg:pypi:orchestrator-lib@1.0.0";
const advisory = "CVE-2026-7101";
const estate = "current-estate:0123456789abcdef0123456789abcdef";
const stamp = "2026-10-18T00:00:00Z";

const node = (id: string, entity_type: string, label: string, severity = "none") => ({
  id, entity_type, label, severity, status: "active", risk_score: 0, attributes: {}, dimensions: {}, data_sources: ["synthetic-fixture"], compliance_tags: [],
});
const nodes = [
  node("agent:planner", "agent", "planner-agent"),
  node("server:orchestrator", "server", "orchestrator-server"),
  node(packageNode, "package", "orchestrator-lib@1.0.0"),
  node(`vuln:${advisory}`, "vulnerability", advisory, "critical"),
];
const path = {
  source: "agent:planner", target: `vuln:${advisory}`, hops: nodes.map((n) => n.id), edges: ["uses", "depends_on", "has_finding"],
  composite_risk: 83, summary: "", credential_exposure: [], tool_exposure: [], vuln_ids: [advisory], finding_ids: [advisory],
};

const row = {
  schema_version: "1", id: occurrenceId, finding_id: occurrenceId, canonical_id: occurrenceId, finding_type: "CVE", finding_class: "vulnerability",
  severity: "critical", title: `${advisory}: orchestrator-lib@1.0.0`, cve_id: advisory, vulnerability_id: advisory,
  node_id: packageNode, finding_node_id: `vuln:${advisory}`, entity_type: "package", scan_id: "snapshot-a",
  package: "orchestrator-lib@1.0.0", package_version: "1.0.0", ecosystem: "pypi", fixed_version: "1.0.1",
  affected_agents: ["planner-agent"], affected_servers: ["orchestrator-server"], status: "open", lane: "vulnerabilities",
  asset: { name: "orchestrator-server", asset_type: "mcp_server", stable_id: "asset-1", canonical_id: "asset-1" },
};

async function routeJourney(page: Page, queries: URL[]) {
  await page.route("**/health", (r) => r.fulfill({ json: { status: "ok", version: "9.8.7" } }));
  await page.route("**/v1/**", (r) => {
    const u = new URL(r.request().url());
    const json = (body: unknown) => r.fulfill({ json: body });
    if (u.pathname === "/v1/auth/me") return json({ authenticated: true, auth_required: false, tenant_id: "fixture", role: "admin", auth_method: "anonymous", memberships: [], configured_modes: [], recommended_ui_mode: "no_auth" });
    if (u.pathname === "/v1/overview") return json({
      schema_version: "overview.v1", tenant_id: "fixture",
      posture: { grade: "D", score: 48, display_format: "percent", summary: "Fixture", breakdown: [] },
      headline: { critical: 1, high: 0, critical_high: 1, kev: 0, credential_exposed: 0, scans: 1, latest_scan_at: stamp, hub_findings: 1 },
      coverage: [{ domain: "vuln", label: "Vuln mgmt", href: "/findings?scope=all&domain=vuln", count: 1, severity: { critical: 1, high: 0, medium: 0, low: 0, unrated: 0 } }],
      domains: { vuln: { label: "Vuln / SCA", metric: 1, metric_label: "open CVEs", href: "/findings", status: "ok", detail: {} } },
      top_risks: [
        { vulnerability_id: advisory, canonical_id: occurrenceId, package: "orchestrator-lib@1.0.0", severity: "critical", risk_score: 9.9, is_kev: false, cvss_score: 9.8, epss_score: null, affected_agents: ["planner-agent"], affected_servers: ["orchestrator-server"] },
      ],
    });
    if (u.pathname === "/v1/posture/counts") return json({ critical: 1, high: 0, medium: 0, low: 0, unrated: 0, total: 1, kev: 0, compound_issues: 0, deployment_mode: "fleet", scan_count: 1, scan_sources: ["local-agents"], services: {} });
    if (u.pathname === "/v1/posture") return json({ grade: "D", score: 48, summary: "Fixture" });
    if (u.pathname === "/v1/jobs") return json({ jobs: [] });
    if (u.pathname === "/v1/findings/triage") return json({ triage: [], count: 0 });
    if (u.pathname === "/v1/findings") return json({
      schema_version: "v1", findings: [row], count: 1, total: 1, limit: 25, offset: 0, sort: "severity", cursor: "", next_cursor: "", has_more: false, warnings: [],
      window: { days: 90, since: "2026-07-18T00:00:00Z", applied: true, label: "Last 90 days" },
    });
    if (u.pathname === "/v1/graph/snapshots") return json([{ scan_id: "snapshot-a", created_at: stamp, snapshot_kind: "scan", node_count: 4, edge_count: 3 }]);
    if (u.pathname === "/v1/inventory/summary") return json({ schema_version: "v1", scan_id: estate, evidence_scope: "current_estate", total_assets: 4, by_type: { agent: 1, server: 1, package: 1 } });
    if (u.pathname === "/v1/graph/attack-paths") {
      queries.push(u);
      // Paths carry the advisory, never the finding store's occurrence id.
      const resolved = u.searchParams.get("node_id") === packageNode && u.searchParams.get("advisory_id") === advisory;
      const paths = resolved ? [path] : [];
      return json({
        scan_id: estate, tenant_id: "fixture", created_at: stamp, snapshot_generation: "0123456789abcdef0123456789abcdef",
        nodes: resolved ? nodes : [], edges: [], attack_paths: paths, interaction_risks: [],
        stats: { total_nodes: 4, total_edges: 3, severity_counts: {}, analysis_status: { attack_path_fusion: { status: "complete", reason_codes: [], observed: {} } } },
        pagination: { total: paths.length, offset: 0, limit: 10, returned: paths.length, has_more: false, cursor: "", next_cursor: "" },
        count_metadata: { source: "persisted_graph_paths", snapshot_total: 40, returned: paths.length, total: paths.length },
        focus: { node_id: packageNode, finding_id: occurrenceId, resolved_from: null, covers_all_matches: true, advisory_id: advisory, matched_by: "node_advisory" },
      });
    }
    return r.fulfill({ status: 404, json: { detail: "Outside fixture" } });
  });
}

for (const theme of ["light", "dark"] as const) {
  test(`CISO top risk opens its own attack path in investigation (${theme})`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await page.addInitScript((t) => localStorage.setItem("agent-bom-theme", t), theme);
    const queries: URL[] = [];
    await routeJourney(page, queries);

    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Overview", exact: true })).toBeVisible();
    await page.getByRole("tab", { name: "Top risks", exact: true }).click();
    const review = page.getByRole("region", { name: "Selected risk" }).getByRole("link").first();
    await expect(review).toHaveAttribute("href", `/findings?finding=${occurrenceId}`);
    await review.click();

    const drawer = page.getByRole("dialog", { name: `Finding details for ${advisory}` });
    await expect(drawer).toBeVisible();
    await drawer.getByRole("link", { name: /Open in investigation/ }).first().click();

    await expect(page.getByRole("heading", { name: "Investigation" })).toBeVisible();
    await expect(page.getByRole("heading", { name: new RegExp(`Planner Agent → ${advisory}`, "i") })).toBeVisible();
    await expect(page.getByText(/No attack path reaches this finding/)).toHaveCount(0);
    const focused = queries.find((q) => q.searchParams.get("finding_id") === occurrenceId);
    expect(focused?.searchParams.get("node_id")).toBe(packageNode);
    expect(focused?.searchParams.get("advisory_id")).toBe(advisory);
  });
}
