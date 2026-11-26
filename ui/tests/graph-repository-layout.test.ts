import { readFileSync } from "node:fs";
import { expect, it } from "vitest";
import { buildScopeShowcase } from "../scripts/product-proof-scope-showcase.mjs";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import { countStraightCrossings } from "@/lib/dagre-layout";
import { INTERNET_ANCHOR_ID } from "@/lib/graph-internet-context";
import type { UnifiedGraphData } from "@/lib/graph-schema";

function repository() {
  const catalog = JSON.parse(readFileSync("fixtures/gallery-advisories.json", "utf8"));
  return buildScopeShowcase("repository", {
    base: { scan_id: "snapshot" },
    node: (id: string, entity_type: string, label: string, severity: string, risk_score: number, attributes: Record<string, unknown>) =>
      ({ id, entity_type, label, severity, risk_score, attributes, dimensions: {}, compliance_tags: [], data_sources: [] }),
    edge: (source: string, target: string, relationship: string, weight: number, evidence: Record<string, unknown>) =>
      ({ id: `${source}->${target}:${relationship}`, source, target, relationship, weight, evidence, direction: "directed", traversable: true }),
    advisory: (id: string) => catalog.advisories.find((item: { canonical_id: string; id: string }) => item.canonical_id === id || item.id === id),
    referenceCve: { label: "unused", attributes: {} },
  }) as UnifiedGraphData;
}

it("keeps recorded repository branches clear while deployment inputs converge on the exposed workload", () => {
  const graph = repository();
  const flow = buildUnifiedFlowGraph(graph, createExpandedGraphFilters(), new Set(graph.nodes.map(node => node.id)));
  const result = semanticGraphLayout(flow.nodes.map(node => ({ ...node, data: { ...node.data, connectedScope: true } })), flow.edges);
  const visible = result.nodes.filter(node => !node.hidden);
  expect(result.edges.filter(edge => !edge.data?.displayOnly).map(edge => [edge.id, edge.source, edge.target, edge.data?.relationship]))
    .toEqual(flow.edges.map(edge => [edge.id, edge.source, edge.target, edge.data?.relationship]));
  expect(visible.filter(node => node.id !== INTERNET_ANCHOR_ID).map(node => node.id).sort()).toEqual(graph.nodes.map(node => node.id).sort());
  expect(countStraightCrossings(visible, result.edges)).toBe(0);
  const at = new Map(visible.map(node => [node.id, node.position]));
  expect(at.get(INTERNET_ANCHOR_ID)!.y).toBe(at.get("container:api")!.y);
});
