import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { mixedEvidenceFlow } from "@/lib/graph-mixed-flow";
import { cloudHierarchyLayout } from "@/lib/graph-cloud-hierarchy";

/** Display-only disclosure: canonical IDs, direction and evidence stay intact. */
export function cloudFindingDisclosure(nodes: Node<LineageNodeData>[], edges: Edge[], expanded: ReadonlySet<string>, toggle: (id: string) => void, preservePositions = false) {
  const groups = new Map<string, Node<LineageNodeData>[]>();
  const visibleIds = new Set(nodes.filter(n => !n.hidden).map(n => n.id));
  for (const n of nodes) if (!n.hidden && n.data.readingOwner && visibleIds.has(n.data.readingOwner)) {
    groups.set(n.data.readingOwner, [...(groups.get(n.data.readingOwner) ?? []), n]);
  }
  if (!groups.size) return { nodes, edges };
  const severityOrder = ["critical", "high", "medium", "low"];
  const mapped = nodes.map(n => {
    const findings = groups.get(n.id);
    const severity = severityOrder.find(s => findings?.some(f => f.data.severity?.toLowerCase() === s));
    return { ...n, hidden: n.hidden || Boolean(n.data.readingOwner && !expanded.has(n.data.readingOwner)),
      data: { ...n.data, ...(findings ? { readingFindings: { count: findings.length, expanded: expanded.has(n.id), severity, toggle: () => toggle(n.id) } } : {}) } };
  });
  const hidden = new Set(mapped.filter(n => n.hidden).map(n => n.id));
  const mappedEdges = edges.map(e => ({ ...e, hidden: e.hidden || hidden.has(e.source) || hidden.has(e.target) }));
  const layout = preservePositions ? null : mixedEvidenceFlow(mapped, mappedEdges) ?? cloudHierarchyLayout(mapped, mappedEdges);
  // Preserve operator positions in general views; only the bounded cloud layout reflows.
  return { nodes: layout?.nodes ?? mapped, edges: mappedEdges };
}
