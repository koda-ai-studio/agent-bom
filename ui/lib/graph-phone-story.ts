import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

const ROW = 148;
const WIDTH = 280;

/** A bounded story reads down one caption column. Context never interrupts the
 * ranked path, and links that skip a row stay on the glyph side of every name.
 * Ordering and handles are presentation only; all recorded endpoints survive. */
export function phoneStoryLayout(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const frame = nodes.find(node => !node.hidden && node.type === "boundaryFrame");
  const visible = nodes.filter(node => !node.hidden && node.type !== "boundaryFrame");
  const primary = visible.filter(node => typeof node.data.semanticPathIndex === "number")
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex! || a.id.localeCompare(b.id));
  const ids = new Set(primary.map(node => node.id));
  const context = visible.filter(node => !ids.has(node.id)).sort((a, b) => a.position.x - b.position.x || a.position.y - b.position.y || a.id.localeCompare(b.id));
  const order = new Map([...primary, ...context].map((node, index) => [node.id, index]));
  const anchor = (node: Node<LineageNodeData>) => node.data.attributes?.resource_type === "internet_boundary";
  const y = (node: Node<LineageNodeData>) => (order.get(node.id) ?? 0) * ROW + (frame && !anchor(node) ? 84 : 0);
  const inside = visible.filter(node => !anchor(node));
  const frameTop = Math.min(...inside.map(y)) - 84;
  const frameBottom = Math.max(...inside.map(y)) + 104;
  return {
    nodes: nodes.map(node => {
      if (node === frame && inside.length) return { ...node, position: { x: 16, y: frameTop }, style: { ...node.style, width: 344, height: frameBottom - frameTop } };
      const row = order.get(node.id);
      return { ...node, position: row === undefined ? node.position : { x: anchor(node) ? 37 : 56, y: y(node) },
        style: { ...node.style, width: WIDTH, "--graph-node-card-width": `${WIDTH}px`, "--graph-node-glyph-size": "56px",
          "--graph-context-glyph-size": "56px", "--graph-node-icon-size": "28px", "--graph-context-icon-size": "28px",
          "--graph-node-label-size": "16px", "--graph-node-meta-size": "14px" },
        data: { ...node.data, phoneLayout: true, phoneLinear: true, phoneSide: "right" as const } };
    }),
    edges: edges.map((edge): Edge => {
      const from = order.get(edge.source), to = order.get(edge.target);
      if (from === undefined || to === undefined) return edge;
      const adjacent = Math.abs(from - to) === 1;
      return { ...edge,
        sourceHandle: adjacent ? from < to ? null : "phone-up" : "phone-left",
        targetHandle: adjacent ? from < to ? null : "phone-down" : "phone-left",
        data: { ...edge.data, phoneLayout: true, phoneLinear: true, labelShift: 1, restingVerb: undefined } };
    }),
  };
}
