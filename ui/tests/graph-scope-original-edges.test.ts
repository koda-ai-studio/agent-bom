import { describe, expect, it } from "vitest";
import { scopeEvidenceGraph } from "@/lib/graph-scope-evidence";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import { buildGraph } from "../scripts/product-proof-graph.mjs";

describe("recorded agent neighborhood", () => {
  it("shows the actual MCP intermediary and preserves inbound admin access", () => {
    const original = buildGraph() as unknown as UnifiedGraphData;
    const graph = scopeEvidenceGraph(original, "agent:developer-copilot");
    expect(graph.nodes.map(node => node.id)).toContain("server:filesystem");
    expect(graph.edges).toEqual(expect.arrayContaining([
      expect.objectContaining({ source: "sa:jit-review", target: "role:prod-admin", relationship: "assumes" }),
      expect.objectContaining({ source: "role:prod-admin", target: "agent:developer-copilot", relationship: "can_access" }),
      expect.objectContaining({ source: "agent:developer-copilot", target: "server:filesystem", relationship: "uses" }),
      expect.objectContaining({ source: "agent:sre-runbook", target: "server:filesystem", relationship: "uses" }),
    ]));
    expect(graph.edges.some(edge => edge.relationship === "shares_server")).toBe(false);
    expect(graph.edges.every(edge => original.edges.some(recorded => recorded.id === edge.id && recorded.source === edge.source && recorded.target === edge.target))).toBe(true);
  });
  it("retains a shared-server relationship when its intermediary is not recorded", () => {
    const original = buildGraph() as unknown as UnifiedGraphData;
    const shortcut = original.edges.find(edge => edge.relationship === "shares_server")!;
    expect(shortcut).toBeDefined();
    const withoutServer = { ...original, nodes: original.nodes.filter(node => node.id !== "server:filesystem"),
      edges: original.edges.filter(edge => edge.source !== "server:filesystem" && edge.target !== "server:filesystem") };
    const graph = scopeEvidenceGraph(withoutServer, "agent:developer-copilot");
    expect(graph.edges).toContainEqual(shortcut);
    expect(graph.nodes.some(node => node.id === "server:filesystem")).toBe(false);
  });

});
