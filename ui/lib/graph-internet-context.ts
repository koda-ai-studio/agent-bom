import { MarkerType, type Edge, type Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { ingressAssessment } from "@/lib/graph-flow-model";

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
    id: INTERNET_ANCHOR_ID, ariaLabel: "Internet, recorded exposure context", type: "cloudResourceNode", position: { x: 0, y: 0 }, draggable: false,
    data: { label: "Internet", nodeType: "cloudResource", semanticLayer: "user", displayOnly: true,
      readingLabel: "Exposure context", attributes: { resource_type: "internet_boundary" } },
  };
  return { nodes: [...cleanNodes, anchor], edges: [...cleanEdges, ...visible.map(node => {
    // A recorded ingress assessment is the receipt behind the verdict; it never creates exposure on its own.
    const assessment = ingressAssessment(node);
    return {
      id: `${INTERNET_ANCHOR_ID}:${node.id}`, source: INTERNET_ANCHOR_ID, target: node.id, type: "relationship",
      ariaLabel: assessment ? `Assessed ingress from Internet to ${node.data.label}` : `Recorded internet exposure for ${node.data.label}; display context, not a traversable relationship`,
      label: "Internet-exposed", markerEnd: { type: MarkerType.ArrowClosed },
      style: { stroke: "var(--text-secondary)", strokeWidth: 1, strokeDasharray: "6 3" },
      data: { relationship: "exposed_to", displayOnly: true, traversable: false, evidenceMode: "inferred", individualLabel: true, ...(assessment ? { evidence: assessment } : {}) },
    };
  })] };
}
