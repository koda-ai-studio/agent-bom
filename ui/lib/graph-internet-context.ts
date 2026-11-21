import { MarkerType, type Edge, type Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

export const INTERNET_ANCHOR_ID = "display:internet";

/** Read the folded verdict first. Unknown is never exposure. */
export function internetExposure(attributes: Record<string, unknown> = {}): boolean | undefined {
  const context = attributes.risk_context;
  const verdict = context && typeof context === "object" ? (context as Record<string, unknown>).internet_exposed : undefined;
  if (typeof verdict === "boolean") return verdict;
  return typeof attributes.internet_exposed === "boolean" ? attributes.internet_exposed : undefined;
}

/** A display anchor explains the recorded verdict; these links are not added
 * to the persisted graph and never count as traversable evidence. */
export function withInternetAnchor(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const visible = nodes.filter(node => !node.hidden && !node.data.displayOnly && internetExposure(node.data.attributes) === true);
  const cleanNodes = nodes.filter(node => !(node.id === INTERNET_ANCHOR_ID && node.data.displayOnly));
  const cleanEdges = edges.filter(edge => !(edge.source === INTERNET_ANCHOR_ID && edge.data?.displayOnly));
  if (!visible.length) return { nodes: cleanNodes, edges: cleanEdges };
  const anchor: Node<LineageNodeData> = {
    id: INTERNET_ANCHOR_ID, type: "cloudResourceNode", position: { x: 0, y: 0 }, draggable: false,
    data: { label: "Internet", nodeType: "cloudResource", semanticLayer: "user", displayOnly: true,
      readingLabel: "Exposure context", attributes: { resource_type: "internet_boundary" } },
  };
  return { nodes: [...cleanNodes, anchor], edges: [...cleanEdges, ...visible.map(node => ({
    id: `${INTERNET_ANCHOR_ID}:${node.id}`, source: INTERNET_ANCHOR_ID, target: node.id, type: "relationship",
    label: "Internet-exposed", markerEnd: { type: MarkerType.ArrowClosed },
    style: { stroke: "var(--text-secondary)", strokeWidth: 1, strokeDasharray: "6 3" },
    data: { relationship: "exposed_to", displayOnly: true, traversable: false, evidenceMode: "inferred", individualLabel: true },
  }))] };
}
