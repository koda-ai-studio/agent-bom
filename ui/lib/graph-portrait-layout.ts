import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticColumns } from "@/lib/graph-semantic-columns";

export const PORTRAIT_CARD_WIDTH = 144;
export const PORTRAIT_COLUMN = 184;
export const PORTRAIT_ROW = 124;

type Point = { x: number; y: number };

/** Rows top to bottom: each spine hop alone on the trunk, then its branches two per row. */
function portraitRows(visible: Node<LineageNodeData>[], edges: Edge[]) {
  const ids = new Set(visible.map(node => node.id));
  const primary = visible.filter(node => typeof node.data.semanticPathIndex === "number")
    .sort((a, b) => a.data.semanticPathIndex! - b.data.semanticPathIndex!).map(node => node.id);
  const spine = new Set(primary), columns = semanticColumns(visible, edges, primary);
  const byColumn = (a: string, b: string) => columns.get(a)! - columns.get(b)! || a.localeCompare(b);
  const out = new Map<string, string[]>(), into = new Map<string, string[]>();
  for (const edge of edges) {
    if (edge.hidden || !ids.has(edge.source) || !ids.has(edge.target) || edge.source === edge.target) continue;
    out.set(edge.source, [...(out.get(edge.source) ?? []), edge.target]);
    into.set(edge.target, [...(into.get(edge.target) ?? []), edge.source]);
  }
  const rows: { ids: string[]; trunk: boolean }[] = [], placed = new Set<string>();
  const branch = (from: string) => {
    const queue = [from];
    for (let i = 0; i < queue.length; i++) {
      const next = [...new Set([...(out.get(queue[i]!) ?? []), ...(into.get(queue[i]!) ?? [])])]
        .filter(id => !placed.has(id) && !spine.has(id)).sort(byColumn);
      for (let j = 0; j < next.length; j += 2) rows.push({ ids: next.slice(j, j + 2), trunk: false });
      next.forEach(id => placed.add(id));
      queue.push(...next);
    }
  };
  for (const id of primary) { rows.push({ ids: [id], trunk: true }); placed.add(id); branch(id); }
  const rest = [...ids].filter(id => !placed.has(id)).sort(byColumn);
  for (const id of rest) {
    if (placed.has(id)) continue;
    rows.push({ ids: [id], trunk: true }); placed.add(id); branch(id);
  }
  return rows;
}

const SINGLE = PORTRAIT_COLUMN / 2;
/** A pair member's side facing the centre gap between the two columns. */
const inner = (point: Point) => point.x < SINGLE ? "phone-right" : "phone-left";

/** Adjacent rows join top to bottom. A link that skips rows runs down the centre
 * gap between the paired columns and enters a pair member from its inner side. */
function handles(from: Point, to: Point, positions: Map<string, Point>): [string | null, string | null] {
  // Opposite paired columns face each other across the centre gap, whatever their rows.
  if (from.y === to.y || (from.x !== SINGLE && to.x !== SINGLE && from.x !== to.x)) return from.x < to.x ? ["phone-right", "phone-left"] : ["phone-left", "phone-right"];
  const down = from.y < to.y;
  if (Math.abs(to.y - from.y) <= PORTRAIT_ROW) return down ? [null, null] : ["phone-up", "phone-down"];
  // Another trunk hop in between: pass it on the glyph side, where branch rows leave room.
  const [top, bottom] = down ? [from.y, to.y] : [to.y, from.y];
  if (from.x === SINGLE && to.x === SINGLE && [...positions.values()].some(p => p.x === SINGLE && p.y > top && p.y < bottom)) return ["phone-left", "phone-left"];
  const source = from.x === SINGLE ? (down ? null : "phone-up") : inner(from);
  const target = to.x === SINGLE ? (down ? null : "phone-down") : inner(to);
  return [source, target];
}

/** Portrait presentation only: preserve every supplied node, relationship and
 * verdict. The backend-ranked path runs top to bottom; branches sit beside
 * each other under the hop they connect to. */
export function graphPortraitLayout(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const visible = nodes.filter(node => !node.hidden);
  const positions = new Map<string, Point>();
  // Trunk hops sit on the centre line; branch rows keep it clear for links that pass them.
  portraitRows(visible, edges).forEach(({ ids, trunk }, index) => ids.forEach((id, slot) =>
    positions.set(id, { x: trunk ? SINGLE : slot * PORTRAIT_COLUMN, y: index * PORTRAIT_ROW })));
  return {
    nodes: nodes.map(node => ({ ...node, position: positions.get(node.id) ?? node.position,
      style: { ...node.style, width: PORTRAIT_CARD_WIDTH, "--graph-node-card-width": `${PORTRAIT_CARD_WIDTH}px`, "--graph-node-glyph-size": "56px",
        "--graph-context-glyph-size": "56px", "--graph-node-icon-size": "28px", "--graph-context-icon-size": "28px",
        "--graph-node-label-size": "15px", "--graph-node-meta-size": "14px" },
      data: { ...node.data, phoneLayout: true } })),
    edges: edges.map((edge): Edge => {
      const from = positions.get(edge.source), to = positions.get(edge.target);
      if (!from || !to) return edge;
      const [sourceHandle, targetHandle] = handles(from, to, positions);
      return { ...edge, sourceHandle, targetHandle, data: { ...edge.data, phoneLayout: true } };
    }),
  };
}
