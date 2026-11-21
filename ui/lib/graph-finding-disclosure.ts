import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { mixedEvidenceFlow } from "@/lib/graph-mixed-flow";
import { cloudHierarchyLayout } from "@/lib/graph-cloud-hierarchy";
import type { GraphRollupContainer } from "@/lib/api-contracts/graph-views";

export function withFindingDrilldowns(nodes: Node<LineageNodeData>[], open: (item: GraphRollupContainer) => void) {
  return nodes.map(node => {
    const rollup = node.data.rollup;
    if (!rollup?.has_children) return node;
    const explore = () => open(rollup);
    return { ...node, data: { ...node.data, onExploreFindings: explore,
      ...(node.data.readingFindings ? { readingFindings: { ...node.data.readingFindings, toggle: explore } } : {}) } };
  });
}

const GROUP_ROW_GAP = 240;

/** Display-only disclosure: canonical IDs, direction and evidence stay intact. */
export function cloudFindingDisclosure(nodes: Node<LineageNodeData>[], edges: Edge[], expanded: ReadonlySet<string>, toggle: (id: string) => void, preservePositions = false) {
  const groups = new Map<string, Node<LineageNodeData>[]>();
  const visibleIds = new Set(nodes.filter(n => !n.hidden).map(n => n.id));
  const byId = new Map(nodes.map(node => [node.id, node]));
  for (const n of nodes) if (!n.hidden && n.data.semanticPathIndex === undefined && n.data.readingOwner && visibleIds.has(n.data.readingOwner)
    && typeof (byId.get(n.data.readingOwner)?.data.findingAggregate ?? byId.get(n.data.readingOwner)?.data.rollup?.aggregate)?.issue_count === "number") {
    groups.set(n.data.readingOwner, [...(groups.get(n.data.readingOwner) ?? []), n]);
  }
  if (!groups.size) return { nodes, edges };
  const groupedIds = new Set([...groups.values()].flatMap(findings => findings.map(node => node.id)));
  const mapped = nodes.map(n => {
    const findings = groups.get(n.id);
    const severity = (n.data.findingAggregate ?? n.data.rollup?.aggregate)?.worst_severity;
    return { ...n, hidden: n.hidden || Boolean(groupedIds.has(n.id) && n.data.readingOwner && !expanded.has(n.data.readingOwner)),
      data: { ...n.data, ...(findings ? { readingFindingsGroup: !expanded.has(n.id), readingFindings: { count: (n.data.findingAggregate ?? n.data.rollup!.aggregate).issue_count!, expanded: expanded.has(n.id), severity, toggle: () => toggle(n.id) } } : {}) } };
  });
  const hidden = new Set(mapped.filter(n => n.hidden).map(n => n.id));
  const mappedEdges = edges.map(e => ({ ...e, hidden: e.hidden || hidden.has(e.source) || hidden.has(e.target) }));
  const layout = preservePositions ? null : mixedEvidenceFlow(mapped, mappedEdges) ?? cloudHierarchyLayout(mapped, mappedEdges);
  // Preserve operator positions in general views; only the bounded cloud layout reflows.
  const positioned = layout?.nodes ?? mapped;
  const groupNodes: Node<LineageNodeData>[] = [];
  const groupEdges: Edge[] = [];
  for (const owner of groups.keys()) {
    if (expanded.has(owner)) continue;
    const asset = positioned.find(n => n.id === owner)!;
    let id = `display:findings:${owner}`;
    while (nodes.some(n => n.id === id) || groupNodes.some(n => n.id === id)) id += ":group";
    const position = { x: asset.position.x, y: asset.position.y + GROUP_ROW_GAP };
    while (positioned.some(node => !node.hidden && node.position.x === position.x && Math.abs(node.position.y - position.y) < GROUP_ROW_GAP)) position.y += GROUP_ROW_GAP;
    const count = (asset.data.findingAggregate ?? asset.data.rollup!.aggregate).issue_count!;
    const grouped = `${count} finding${count === 1 ? "" : "s"}`;
    groupNodes.push({ id, initialWidth: 240, initialHeight: 180, draggable: false, type: "findingGroupNode", position, ariaLabel: `Findings for ${asset.data.label}: ${count}`,
      data: { label: "Findings", nodeType: "misconfiguration", displayOnly: true, displayTargetId: owner,
        rollup: asset.data.rollup, findingAggregate: asset.data.findingAggregate, semanticLayout: true, semanticLayer: "finding", semanticOwner: owner,
        description: asset.data.label, readingFindings: { ...asset.data.readingFindings, count, expanded: false, toggle: () => toggle(owner) } } });
    // A group left of its owner is entered from its far side; otherwise the edge crosses its own glyph.
    groupEdges.push({ id: `${id}:summary`, source: owner, target: id, type: "smoothstep", label: "Has findings", ariaLabel: `${asset.data.label} has ${grouped}`,
      ...(position.x < asset.position.x ? { sourceHandle: "context", targetHandle: "context" } : {}),
      data: { displayOnly: true, relationship: "finding_group", traversable: false, quietLabel: true } });
  }
  return { nodes: [...positioned, ...groupNodes], edges: [...mappedEdges, ...groupEdges] };
}
