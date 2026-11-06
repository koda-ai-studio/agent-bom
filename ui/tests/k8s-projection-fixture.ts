import type { Edge, Node } from "@xyflow/react";
import fixture from "../e2e/fixtures/k8s-projection.json";
import { createExpandedGraphFilters } from "@/components/lineage-filter";
import type { LineageNodeData } from "@/components/lineage-nodes";
import type { UnifiedGraphData } from "@/lib/graph-schema";
import { buildUnifiedFlowGraph } from "@/lib/unified-graph-flow";

export type K8sScenario = keyof typeof fixture;

/** The committed projection output through the same builder the page uses. */
export function k8sFlowGraph(scenario: K8sScenario): { nodes: Node<LineageNodeData>[]; edges: Edge[] } {
  const graph = { ...fixture[scenario], attack_paths: [], interaction_risks: [] } as unknown as UnifiedGraphData;
  const { nodes, edges } = buildUnifiedFlowGraph(graph, createExpandedGraphFilters());
  return { nodes, edges };
}

export const byLabel = (nodes: Node<LineageNodeData>[], label: string) => {
  const node = nodes.find(n => n.data.label === label);
  if (!node) throw new Error(`no node labelled ${label}: ${nodes.map(n => n.data.label).join(", ")}`);
  return node;
};
