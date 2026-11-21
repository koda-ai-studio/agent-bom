import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

/** Render only the backend's typed runs link. No digest matching or identity
 * correlation is performed in the browser. Shared images remain shared nodes. */
export function workloadImageContext(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const byId = new Map(nodes.map(node => [node.id, node]));
  const parents = new Map<string, Set<string>>(), sources = new Map<string, Set<string>>();
  const addSources = (id: string, values: unknown) => {
    if (!Array.isArray(values)) return;
    const recorded = sources.get(id) ?? new Set<string>();
    for (const value of values) if (typeof value === "string" && value) recorded.add(value);
    sources.set(id, recorded);
  };
  for (const edge of edges) {
    if (edge.hidden || edge.data?.relationship !== "runs"
      || byId.get(edge.source)?.data.entityType !== "container"
      || byId.get(edge.target)?.data.entityType !== "container") continue;
    const owners = parents.get(edge.target) ?? new Set<string>();
    owners.add(edge.source); parents.set(edge.target, owners);
    const evidence = edge.data?.evidence;
    if (!evidence || typeof evidence !== "object") continue;
    addSources(edge.source, (evidence as Record<string, unknown>).workload_sources);
    addSources(edge.target, (evidence as Record<string, unknown>).image_sources);
  }
  return { owners: new Map([...parents].filter(([, owners]) => owners.size === 1).map(([id, owners]) => [id, [...owners][0]!])),
    sources: new Map([...sources].map(([id, values]) => [id, [...values].sort()])) };
}
