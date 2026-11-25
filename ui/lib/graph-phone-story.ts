import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

const ROW = 148;
const WIDTH = 280;

/** A bounded story reads down one caption column. Context never interrupts the
 * ranked path, and links that skip a row stay on the glyph side of every name.
 * Ordering and handles are presentation only; all recorded endpoints survive. */
export function phoneStoryLayout(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const visible = nodes.filter(node => !node.hidden);
  const primary = visible.filter(node => typeof node.data.semanticPathIndex === "number")
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex! || a.id.localeCompare(b.id));
  const ids = new Set(primary.map(node => node.id));
  const context = visible.filter(node => !ids.has(node.id)).sort((a, b) => a.position.x - b.position.x || a.position.y - b.position.y || a.id.localeCompare(b.id));
  const order = new Map([...primary, ...context].map((node, index) => [node.id, index]));
  return {
    nodes: nodes.map(node => {
      const row = order.get(node.id);
      const anchor = node.data.attributes?.resource_type === "internet_boundary";
      return { ...node, position: row === undefined ? node.position : { x: anchor ? 37 : 56, y: row * ROW },
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
