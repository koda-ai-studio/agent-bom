import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

/** A named peer preview is a fan, with an explicit remainder, never a chain. */
export function peerPreviewLayout(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  if (nodes.length < 4 || nodes.length > 6 || !nodes.some(n => n.type === "clusterPillNode")) return null;
  const parents = new Set(edges.map(e => e.source));
  if (parents.size !== 1 || edges.length !== nodes.length - 1) return null;
  const root = nodes.find(n => parents.has(n.id));
  if (!root || edges.some(e => e.target === root.id)) return null;
  const children = nodes.filter(n => n.id !== root.id).sort((a, b) =>
    Number(a.type === "clusterPillNode") - Number(b.type === "clusterPillNode") || a.data.label.localeCompare(b.data.label) || a.id.localeCompare(b.id));
  if (new Set(edges.map(e => e.target)).size !== children.length) return null;
  const positions = new Map(children.map((n, i) => [n.id, { x: 460, y: i * 220 }]));
  positions.set(root.id, { x: 0, y: (children.length - 1) * 110 });
  return {
    nodes: nodes.map(n => ({ ...n, position: positions.get(n.id)!, style: { ...n.style, minHeight: 0 } })),
    edges: edges.map((e): Edge => ({ ...e, type: "smoothstep", data: { ...e.data, quietLabel: true, boundedOverview: true, directionEmphasis: true } })),
  };
}
