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
      data: { ...n.data, ...(findings ? { readingFindingsGroup: !expanded.has(n.id), readingFindings: { count: findings.length, expanded: expanded.has(n.id), severity, toggle: () => toggle(n.id) } } : {}) } };
  });
  const hidden = new Set(mapped.filter(n => n.hidden).map(n => n.id));
  const mappedEdges = edges.map(e => ({ ...e, hidden: e.hidden || hidden.has(e.source) || hidden.has(e.target) }));
  const layout = preservePositions ? null : mixedEvidenceFlow(mapped, mappedEdges) ?? cloudHierarchyLayout(mapped, mappedEdges);
  // Preserve operator positions in general views; only the bounded cloud layout reflows.
  const positioned = layout?.nodes ?? mapped;
  const groupNodes: Node<LineageNodeData>[] = [];
  const groupEdges: Edge[] = [];
  for (const [owner, findings] of groups) {
    if (expanded.has(owner)) continue;
    const asset = positioned.find(n => n.id === owner)!;
    const first = nodes.find(n => n.id === findings[0]!.id)!;
    let id = `display:findings:${owner}`;
    while (nodes.some(n => n.id === id) || groupNodes.some(n => n.id === id)) id += ":group";
    groupNodes.push({ id, initialWidth: 240, initialHeight: 180, type: "findingGroupNode", position: preservePositions ? first.position : { x: asset.position.x + 520, y: asset.position.y - 340 },
      data: { label: "Findings", nodeType: "misconfiguration", displayOnly: true, displayTargetId: owner,
        description: asset.data.label, readingFindings: { count: findings.length, expanded: false, toggle: () => toggle(owner) } } });
    groupEdges.push({ id: `${id}:summary`, source: owner, target: id, type: "smoothstep", label: "Has findings",
      data: { displayOnly: true, relationship: "finding_group", traversable: false, quietLabel: true } });
  }
  return { nodes: [...positioned, ...groupNodes], edges: [...mappedEdges, ...groupEdges] };
}
