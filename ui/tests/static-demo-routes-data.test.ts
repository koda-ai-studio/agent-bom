import { describe, expect, it } from "vitest";

import { auditEntriesWithOutcomes, enrichFindings, findingFacets, graphImpact } from "../scripts/static-demo-routes.mjs";

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
    { source: "user:contractor", target: "agent:copilot" },
    { source: "agent:copilot", target: "server:github" },
    { source: "server:github", target: "pkg:next" },
    { source: "pkg:next", target: "cve:next" },
    { source: "cve:next", target: "pkg:other" },
  ],
};

describe("static demo sample answers", () => {
  it("walks the recorded graph in reverse from a finding and counts what reaches it", () => {
    const impact = graphImpact(graph, "cve:next", { maxDepth: 4 });
    expect(impact.affected_count).toBe(4);
    expect(impact.affected_by_type).toEqual({ package: 1, server: 1, agent: 1, user: 1 });
    expect(impact.max_depth_reached).toBe(4);
    expect(impact.affected_nodes_detail[0]).toEqual({ id: "pkg:next", label: "next@15.2.2", entity_type: "package", depth: 1 });
    expect(graphImpact(graph, "cve:next", { maxDepth: 2 }).affected_count).toBe(2);
    expect(graphImpact(graph, "cve:next", { direction: "forward" }).affected_nodes).toEqual(["pkg:other"]);
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

  it("records an outcome for every fixture audit action", () => {
    const entries = auditEntriesWithOutcomes([
      { action: "scan.completed", details: { findings: 15 } },
      { action: "gateway.policy.denied", details: { rule: "block-shell" } },
    ]);
    expect(entries[0].details).toEqual({ outcome: "completed", findings: 15 });
    expect(entries[1].details).toEqual({ decision: "denied", rule: "block-shell" });
  });
});
