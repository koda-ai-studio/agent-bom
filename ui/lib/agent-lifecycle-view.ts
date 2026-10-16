import type { UnifiedGraphData } from "@/lib/graph-schema";

export type LifecycleView = "servers" | "packages" | "tools";

/** Select recorded, directed inventory relationships without synthesizing hops.
 * Aggregate counts/export continue to describe the complete supplied inventory.
 */
export function lifecycleInventoryView(graph: UnifiedGraphData, view: LifecycleView, serverId: string): UnifiedGraphData {
  const ids = new Set(graph.nodes.filter(node => node.entity_type === "agent").map(node => node.id));
  const serverIds = new Set(graph.nodes.filter(node => node.entity_type === "server"
    && (view === "servers" || node.id === serverId)).map(node => node.id));
  serverIds.forEach(id => ids.add(id));
  const relationships = view === "packages" ? new Set(["depends_on"])
    : view === "tools" ? new Set(["provides_tool", "exposes_cred"]) : new Set<string>();
  const edges = graph.edges.filter(edge => edge.direction === "directed" && (
    (edge.relationship === "uses" && ids.has(edge.source) && serverIds.has(edge.target))
    || (serverIds.has(edge.source) && relationships.has(edge.relationship))
  ));
  edges.forEach(edge => ids.add(edge.target));
  if (view === "packages") {
    const packages = new Set(graph.nodes.filter(node => node.entity_type === "package" && ids.has(node.id)).map(node => node.id));
    const advisories = graph.edges.filter(edge => edge.direction === "directed" && edge.relationship === "vulnerable_to" && packages.has(edge.source));
    edges.push(...advisories);
    advisories.forEach(edge => ids.add(edge.target));
  }
  return { ...graph, nodes: graph.nodes.filter(node => ids.has(node.id)), edges,
    attack_paths: [], interaction_risks: [] };
}
