import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticColumns } from "@/lib/graph-semantic-columns";

/** Portrait presentation only: preserve every supplied node, relationship and
 * verdict. The backend-ranked path owns the spine; context is indented below
 * its recorded owner. Without a path, semantic order does not imply reachability. */
export function graphPortraitLayout(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const visible = nodes.filter(node => !node.hidden), byId = new Map(visible.map(node => [node.id, node]));
  const primary = visible.filter(node => typeof node.data.semanticPathIndex === "number")
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex!).map(node => node.id);
  const path = new Set(primary), columns = semanticColumns(visible, edges, primary);
  const owners = new Map<string, string>();
  for (const node of visible) {
    if (path.has(node.id)) continue;
    const owner = node.data.semanticOwner ?? node.data.readingOwner;
    if (owner && owner !== node.id && byId.has(owner)) { owners.set(node.id, owner); continue; }
    const neighbour = primary.find(id => edges.some(edge => edge.source === id && edge.target === node.id || edge.target === id && edge.source === node.id));
    if (neighbour) owners.set(node.id, neighbour);
  }
  const ordered = [...visible].sort((a, b) => columns.get(a.id)! - columns.get(b.id)! || a.id.localeCompare(b.id));
  const positions = new Map<string, { x: number; y: number }>();
  let y = 0;
  const place = (id: string, context: boolean) => {
    if (positions.has(id)) return;
    const node = byId.get(id)!;
    positions.set(id, { x: context ? 88 : 24, y });
    y += Math.max(156, node.measured?.height ?? 156) + 24;
    for (const child of ordered) if (owners.get(child.id) === id) place(child.id, true);
  };
  for (const id of primary) place(id, false);
  for (const node of ordered) if (!owners.has(node.id)) place(node.id, false);
  for (const node of ordered) place(node.id, false);
  return {
    nodes: nodes.map(node => ({ ...node, position: positions.get(node.id) ?? node.position,
      style: { ...node.style, width: 240, minHeight: 156, "--graph-node-card-width": "240px", "--graph-node-glyph-size": "56px",
        "--graph-context-glyph-size": "56px", "--graph-node-icon-size": "28px", "--graph-context-icon-size": "28px",
        "--graph-node-label-size": "14px", "--graph-node-meta-size": "13px" },
      data: { ...node.data, phoneLayout: true } })),
    edges: edges.map(edge => {
      const from = positions.get(edge.source), to = positions.get(edge.target);
      if (!from || !to) return edge;
      const skippedRow = visible.some(node => {
        const point = positions.get(node.id)!;
        return node.id !== edge.source && node.id !== edge.target && point.y > Math.min(from.y, to.y) && point.y < Math.max(from.y, to.y);
      });
      return { ...edge, sourceHandle: skippedRow ? "phone-left" : from.y > to.y ? "phone-up" : null,
        targetHandle: skippedRow ? "phone-left" : from.y > to.y ? "phone-down" : null,
        data: { ...edge.data, phoneLayout: true } };
    }),
  };
}
