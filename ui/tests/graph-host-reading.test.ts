import { expect, it } from "vitest";
import { buildGraph } from "../scripts/product-proof-graph.mjs";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import { agentPathGraph } from "@/lib/graph-agent-path";
import type { UnifiedGraphData } from "@/lib/graph-schema";

it("reads compute hosting host-to-agent in both views while preserving the original receipt", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  const before = JSON.stringify(graph);
  const flow = buildUnifiedFlowGraph(graph, createExpandedGraphFilters());
  const path = agentPathGraph(graph, flow, "agent:developer-copilot", () => {});
  const record = graph.edges.find(edge => edge.relationship === "hosted_on")!;
  for (const view of [flow, path]) expect(view.edges.find(edge => edge.id === record.id)).toMatchObject({
    source: record.target, target: record.source,
    data: {originalSource: record.source, originalTarget: record.target, originalRelationship: "hosted_on", relationshipLabel: "Hosts", inverseRecordedRelationship: true},
  });
  expect(JSON.stringify(graph)).toBe(before);
  expect(flow.edges.find(edge => edge.data?.relationship === "can_access")).toMatchObject({source: "role:prod-admin", target: "agent:developer-copilot"});
});

it("keeps a hosting hop in the selected path's direction when the view is that one path", () => {
  const full = buildGraph() as unknown as UnifiedGraphData;
  const path = full.attack_paths!.find(item => item.source === "user:contractor")!;
  const hops = new Set(path.hops);
  const graph = { ...full, nodes: full.nodes.filter(node => hops.has(node.id)), edges: full.edges.filter(edge => hops.has(edge.source) && hops.has(edge.target)), attack_paths: [path] };
  const flow = buildUnifiedFlowGraph(graph, createExpandedGraphFilters());
  expect(flow.edges.find(edge => edge.id === "agent:developer-copilot->container:copilot-portal:hosted_on")).toMatchObject({ source: "agent:developer-copilot", target: "container:copilot-portal" });
});

it("keeps the selected path's hosting hop in path direction inside the full graph", () => {
  const graph = buildGraph() as unknown as UnifiedGraphData;
  const path = graph.attack_paths!.find(item => item.source === "user:contractor")!;
  const flow = buildUnifiedFlowGraph(graph, createExpandedGraphFilters(), undefined, path.hops);
  expect(flow.edges.find(edge => edge.id === "agent:developer-copilot->container:copilot-portal:hosted_on")).toMatchObject({ source: "agent:developer-copilot", target: "container:copilot-portal" });
});
