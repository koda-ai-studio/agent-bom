import { expect, it } from "vitest";
import { edgeIsDashed } from "@/lib/graph-edge-family";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import { agentPathGraph } from "@/lib/graph-agent-path";
import { buildGraph } from "../scripts/product-proof-graph.mjs";
import type { UnifiedGraphData } from "@/lib/graph-schema";

it.each(["static_scan", "recorded", "runtime_observed", "modeled_infrastructure", "legacy_unrecorded"])("keeps %s evidence consistent across path, base and compact access links", tier => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  graph.edges.forEach(edge => { edge.evidence = {tier}; });
  const flow = buildUnifiedFlowGraph(graph, {...createExpandedGraphFilters(), maxDepth: 32});
  const path = agentPathGraph(graph, flow, "agent:developer-copilot", () => {});
  const expected = tier === "modeled_infrastructure" ? "6 3" : tier === "legacy_unrecorded" ? "1.5 5" : undefined;
  for (const edge of path.edges.filter(edge => !edge.data?.displayOnly)) {
    const base = flow.edges.find(item => item.id === edge.id)!;
    expect(base.style?.strokeDasharray).toBe(expected);
    expect(edge.style?.strokeDasharray).toBe(expected);
    expect(edgeIsDashed("access", {...base.data, uniformlyModeled: true})).toBe(tier === "modeled_infrastructure");
  }
});
