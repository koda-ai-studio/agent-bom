import { describe, expect, it } from "vitest";

import { auditEntriesWithOutcomes, enrichFindings, findingFacets, graphImpact, installStaticDemoRoutes, overviewFromFindings, postureCountsFromFindings, severityTotals } from "../scripts/static-demo-routes.mjs";

const graph = {
  nodes: [
    { id: "user:contractor", entity_type: "user", label: "contractor-reviewer" },
    { id: "agent:copilot", entity_type: "agent", label: "Developer Copilot" },
    { id: "server:github", entity_type: "server", label: "github-enterprise MCP" },
    { id: "pkg:next", entity_type: "package", label: "next@15.2.2" },
    { id: "cve:next", entity_type: "vulnerability", label: "CVE-2025-29927" },
    { id: "pkg:other", entity_type: "package", label: "left-pad@1.0.0" },
  ],
  edges: [
    { source: "user:contractor", target: "agent:copilot", relationship: "can_access" },
    { source: "agent:copilot", target: "server:github", relationship: "uses" },
    { source: "server:github", target: "pkg:next", relationship: "depends_on" },
    { source: "pkg:next", target: "cve:next", relationship: "vulnerable_to" },
  ],
};

describe("static demo sample answers", () => {
  it("excludes structural and correlation edges from impact, including trace order", () => {
    for (const relationship of ["hosts", "correlates_with", "shares_server", "trace_step"]) {
      const fixture = { ...graph, edges: [...graph.edges, { source: "pkg:other", target: "server:github", relationship }] };
      expect(graphImpact(fixture, "cve:next").affected_nodes).not.toContain("pkg:other");
    }
  });

  it("marks an impact cut short by depth as a lower bound", () => {
    const impact = graphImpact(graph, "cve:next", { maxDepth: 2 });
    expect(impact.completeness).toMatchObject({ complete: false, total: null, returned: 2, lower_bound: 2 });
  });
  it("reports the returned impact count and direction consistently", async () => {
    type Route = { request: () => { url: () => string }; fulfill: (options: { body: string }) => Promise<void> };
    const handlers = new Map<string, (route: Route) => Promise<void>>();
    const page = { evaluate: async () => ({}), route: async (pattern: string, handler: (route: Route) => Promise<void>) => handlers.set(pattern, handler) };
    await installStaticDemoRoutes(page, { graph, findings: [], auditEntries: [], scanId: "scan", tenantId: "default", snapshotAt: "2026-06-03T20:30:00Z" });
    let response = "";
    await handlers.get("**/v1/graph/impact?**")!({
      request: () => ({ url: () => "http://localhost/v1/graph/impact?node=cve%3Anext&direction=forward" }),
      fulfill: async ({ body: json }) => { response = json; },
    });
    const body = JSON.parse(response);
    expect(body.affected_count).toBe(1);
    expect(body.completeness.returned).toBe(1);
    expect(body.interpretation.basis).toBe("recorded_forward_reachability");
  });

  it("walks the recorded graph in reverse from a finding and counts what reaches it", () => {
    const impact = graphImpact(graph, "cve:next", { maxDepth: 4 });
    expect(impact.affected_count).toBe(4);
    expect(impact.affected_by_type).toEqual({ package: 1, server: 1, agent: 1, user: 1 });
    expect(impact.max_depth_reached).toBe(4);
    expect(impact.affected_nodes_detail[0]).toEqual({ id: "pkg:next", label: "next@15.2.2", entity_type: "package", depth: 1 });
    expect(graphImpact(graph, "cve:next", { maxDepth: 2 }).affected_count).toBe(2);
    expect(graphImpact(graph, "cve:next", { direction: "forward" }).affected_nodes).toEqual(["pkg:next"]);
  });

  it("anchors findings to the path and gives them a lane, owner and SLA dated from the snapshot", () => {
    const [finding] = enrichFindings([{ cve_id: "CVE-2025-29927", finding_type: "vulnerability", package_name: "next", package_version: "15.2.2", severity: "critical", fixed_version: "15.2.3" }], graph, { snapshotAt: "2026-06-03T20:30:00Z" });
    expect(finding).toMatchObject({ lane: "vulnerabilities", node_id: "cve:next", package: "next@15.2.2", owner: "data-platform", sla_due_at: "2026-06-10T20:30:00.000Z", sla_due_at_source: "severity-kev/v1" });
  });

  it("derives lane and severity facets from the same rows the page lists", () => {
    const rows = enrichFindings([
      { cve_id: "CVE-2025-29927", finding_type: "vulnerability", severity: "critical", fixed_version: "15.2.3" },
      { cve_id: "CVE-2024-37891", finding_type: "vulnerability", severity: "high" },
    ], graph, { snapshotAt: "2026-06-03T20:30:00Z" });
    const facets = findingFacets(rows);
    expect(facets.lane).toEqual({ vulnerabilities: 2 });
    expect(facets.severity).toMatchObject({ critical: 1, high: 1, medium: 0 });
    expect(facets.fixability).toEqual({ fix_available: 1, no_fix_available: 1 });
    expect(facets.status).toEqual({ open: 2, resolved: 0 });
  });

  it("re-derives the overview and posture counts from the rows the findings page lists", () => {
    const rows = [
      { severity: "critical", exposed_credentials: ["KEY"], is_kev: true },
      { severity: "critical", exposed_credentials: [] },
      { severity: "high" },
      { severity: "medium", exposed_credentials: ["TOKEN"] },
    ];
    expect(severityTotals(rows)).toEqual({ critical: 2, high: 1, medium: 1, low: 0, total: 4 });
    const base = {
      posture: { grade: "D", score: 43 },
      headline: { critical: 3, high: 9, critical_high: 12, credential_exposed: 3, hub_findings: 15, scans: 3 },
      coverage: [{ domain: "cspm", count: 0 }, { domain: "vuln", count: 15, severity: { critical: 3, high: 9, medium: 3, low: 0, unrated: 0 } }],
      domains: { vuln: { metric: 15, detail: { critical: 3, high: 9, packages: 148 } }, ops: { metric: 3 } },
      top_risks: [{ vulnerability_id: "CVE-2025-29927" }],
    };
    const overview = overviewFromFindings(base, rows);
    expect(overview.headline).toEqual({ critical: 2, high: 1, critical_high: 3, credential_exposed: 2, hub_findings: 4, kev: 1, scans: 3 });
    expect(overview.issue_counts).toEqual({ critical: 2, high: 1, medium: 1, low: 0, total: 4, kev: 1 });
    expect(overview.coverage[1]).toEqual({ domain: "vuln", count: 4, severity: { critical: 2, high: 1, medium: 1, low: 0, unrated: 0 } });
    expect(overview.coverage[0]).toEqual({ domain: "cspm", count: 0 });
    expect(overview.domains.vuln).toEqual({ metric: 4, detail: { critical: 2, high: 1, packages: 148, severity: { critical: 2, high: 1, medium: 1, low: 0, unrated: 0 } } });
    expect(overview.domains.ops).toEqual({ metric: 3 });
    expect(overview.posture).toEqual(base.posture);
    expect(overview.top_risks).toBe(base.top_risks);
    expect(postureCountsFromFindings({ critical: 3, high: 9, medium: 3, low: 0, total: 15, scan_count: 3 }, rows))
      .toEqual({ critical: 2, high: 1, medium: 1, low: 0, total: 4, scan_count: 3 });
  });

  it("records an outcome for every fixture audit action", () => {
    const entries = auditEntriesWithOutcomes([
      { action: "scan.completed", details: { findings: 15 } },
      { action: "gateway.policy.denied", details: { rule: "block-shell" } },
    ]);
    expect(entries[0].details).toEqual({ outcome: "completed", findings: 15 });
    expect(entries[1].details).toEqual({ decision: "denied", rule: "block-shell" });
  });
});
