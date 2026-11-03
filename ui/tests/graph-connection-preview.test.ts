import { describe, expect, it } from "vitest";
import { graphConnectionPreview } from "@/lib/graph-connection-preview";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import topology from "../e2e/fixtures/terraform-real-topology.json";

const flow = buildUnifiedFlowGraph({ ...topology, attack_paths: [], interaction_risks: [] } as unknown as UnifiedGraphData, createExpandedGraphFilters());
describe("connected graph preview", () => {
  it("bounds the real Terraform topology without inventing or reversing evidence", () => {
    const before = JSON.stringify(flow);
    const result = graphConnectionPreview(flow.nodes, flow.edges)!;
    expect(result.nodes).toHaveLength(6);
    expect(result.totalNodes).toBe(flow.nodes.length);
    expect(result.totalEdges).toBe(flow.edges.length);
    expect(result.roots).toHaveLength(flow.nodes.length);
    const connected = new Set([result.root.id]);
    for (let pass = 0; pass < 6; pass++) for (const edge of result.edges) {
      expect(flow.edges).toContain(edge);
      if (connected.has(edge.source) || connected.has(edge.target)) { connected.add(edge.source); connected.add(edge.target); }
    }
    expect(result.nodes.every(node => connected.has(node.id))).toBe(true);
    expect(JSON.stringify(flow)).toBe(before);
    const shuffled = graphConnectionPreview([...flow.nodes].reverse(), [...flow.edges].reverse())!;
    expect(shuffled.nodes.map(n => n.id).sort()).toEqual(result.nodes.map(n => n.id).sort());
  });
  it("can start from every node, including an isolated component", () => {
    for (const node of flow.nodes) expect(graphConnectionPreview(flow.nodes, flow.edges, node.id, 3)!.nodes).toContain(node);
    const isolated = { ...flow.nodes[0]!, id: "isolated" };
    const result = graphConnectionPreview([...flow.nodes, isolated], flow.edges, isolated.id)!;
    expect(result.nodes).toEqual([isolated]);
    expect(result.edges).toEqual([]);
  });
  it("handles empty and invalid roots without fabricating nodes", () => {
    expect(graphConnectionPreview([], [])).toBeNull();
    expect(graphConnectionPreview(flow.nodes, flow.edges, "missing", 3)!.nodes).toHaveLength(3);
  });
});
