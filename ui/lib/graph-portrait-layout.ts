import { phoneStoryLayout } from "@/lib/graph-phone-story";
import type { Edge, Node } from "@xyflow/react";
import { withoutFrames } from "@/lib/graph-exposure-spine";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticColumns } from "@/lib/graph-semantic-columns";

export const PORTRAIT_CARD_WIDTH = 144;
export const PORTRAIT_COLUMN = 184;
export const PORTRAIT_ROW = 124;

type Point = { x: number; y: number };

/** A finding id never truncates: on a phone its caption stacks under a glyph centred in its card, right of the trunk line. */
export function stacksOnPhone(label: unknown): boolean {
  return /\b(CVE|GHSA)-/i.test(String(label ?? ""));
}

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
  // A path ending in a finding keeps that last hop right under the asset it was found on; the asset's other
  // branches follow it, so the spine's final link never has to skip past branch cards.
  const terminal = primary.at(-1), endsInFinding = terminal !== undefined && primary.length > 1
    && ["vulnerability", "misconfiguration"].includes(String(visible.find(node => node.id === terminal)?.data.nodeType));
  for (const [index, id] of primary.entries()) {
    if (endsInFinding && id === terminal) continue;
    rows.push({ ids: [id], trunk: true }); placed.add(id);
    if (endsInFinding && index === primary.length - 2) { rows.push({ ids: [terminal!], trunk: true }); placed.add(terminal!); branch(id); branch(terminal!); }
    else branch(id);
  }
  const rest = [...ids].filter(id => !placed.has(id)).sort(byColumn);
  for (const id of rest) {
    if (placed.has(id)) continue;
    rows.push({ ids: [id], trunk: true }); placed.add(id); branch(id);
  }
  // Without a recorded path there is no spine to follow: rows read top to bottom by backend column, so a second
  // entry (another Service in front of the same pod) is read before what it leads to.
  if (!primary.length) {
    const column = (row: { ids: string[] }) => Math.min(...row.ids.map(id => columns.get(id) ?? 0));
    return rows.map((row, index) => ({ row, index })).sort((a, b) => column(a.row) - column(b.row) || a.index - b.index).map(({ row }) => row);
  }
  return rows;
}

/** A trunk card starts where the left column ends, so its glyph (at its left edge) sits on the centre line. */
const SINGLE = PORTRAIT_CARD_WIDTH;
/** A pair member's side facing the centre gap between the two columns. */
const inner = (point: Point) => point.x < SINGLE ? "phone-right" : "phone-left";

/** Adjacent rows join top to bottom. A link that skips rows runs down the centre
 * gap between the paired columns and enters a pair member from its inner side. */
function handles(from: Point, to: Point, positions: Map<string, Point>, stacked: readonly Point[]): [string | null, string | null] {
  // Opposite paired columns face each other across the centre gap, whatever their rows.
  if (from.y === to.y || (from.x !== SINGLE && to.x !== SINGLE && from.x !== to.x)) return from.x < to.x ? ["phone-right", "phone-left"] : ["phone-left", "phone-right"];
  const down = from.y < to.y;
  if (Math.abs(to.y - from.y) <= PORTRAIT_ROW) return down ? [null, null] : ["phone-up", "phone-down"];
  const [top, bottom] = down ? [from.y, to.y] : [to.y, from.y];
  // Past a stacked finding on the trunk, a link to the left column leaves its trunk card from the left, clear of that caption.
  const pastStacked = stacked.some(p => p.y > top && p.y < bottom);
  if (pastStacked && from.x === SINGLE && to.x < SINGLE) return ["phone-left", "phone-right"];
  if (pastStacked && to.x === SINGLE && from.x < SINGLE) return ["phone-right", "phone-left"];
  if (from.x === SINGLE && to.x === SINGLE) {
    const between = [...positions.values()].filter(p => p.y > top && p.y < bottom);
    const left = between.some(p => p.x < SINGLE), right = between.some(p => p.x > SINGLE), trunk = between.some(p => p.x === SINGLE);
    // Pass the cards in between on the side they leave free: the left when a right-column glyph or a trunk hop is in the way.
    if (right && !left) return ["phone-left", "phone-left"];
    if (left && !right && !trunk) return ["phone-right", "phone-right"];
    if (trunk) return ["phone-left", "phone-left"];
  }
  const source = from.x === SINGLE ? (down ? null : "phone-up") : inner(from);
  const target = to.x === SINGLE ? (down ? null : "phone-down") : inner(to);
  return [source, target];
}

/** Portrait presentation only: preserve every supplied node, relationship and
 * verdict. The backend-ranked path runs top to bottom; branches sit beside
 * each other under the hop they connect to. */
export function graphPortraitLayout(nodes: Node<LineageNodeData>[], edges: Edge[]) {
  const cards = nodes.filter(node => !node.hidden && node.type !== "boundaryFrame");
  // Rollups are navigation summaries with counts, not narrow side branches.
  // Give each bounded scope its own full caption column, including unlinked roots.
  if (cards.length > 0 && cards.length <= 24 && cards.every(node => node.data.rollup)) return phoneStoryLayout(nodes, edges);
  if (cards.length <= 24 && cards.some(node => node.data.roomyName) && nodes.some(node => node.type === "boundaryFrame")) return phoneStoryLayout(nodes, edges);
  // A phone stacks one column: the scope is its first card again, not a boundary around it.
  ({ nodes, edges } = withoutFrames(nodes, edges));
  const visible = nodes.filter(node => !node.hidden);
  if (visible.length <= 24 && visible.some(node => node.data.roomyName)) return phoneStoryLayout(nodes, edges);
  const positions = new Map<string, Point>();
  // Trunk hops sit on the centre line; branch rows keep it clear for links that pass them.
  const sides = new Map<string, "trunk" | "left" | "right">();
  const rows = portraitRows(visible, edges);
  const rowOf = new Map(rows.flatMap(({ ids }, index) => ids.map(id => [id, index] as const)));
  const label = new Map(visible.map(node => [node.id, node.data.label]));
  const stackedRows = rows.flatMap(({ ids, trunk }, index) => trunk && stacksOnPhone(label.get(ids[0]!)) ? [index] : []);
  // A lone branch whose link to the trunk skips a stacked finding takes the left column, away from that finding's caption.
  const skipsStacked = (id: string) => edges.some(edge => {
    if (edge.hidden || (edge.source !== id && edge.target !== id)) return false;
    const other = rowOf.get(edge.source === id ? edge.target : edge.source), here = rowOf.get(id)!;
    return other !== undefined && rows[other]!.trunk && stackedRows.some(row => row > Math.min(other, here) && row < Math.max(other, here));
  });
  // Otherwise a lone branch takes the right column: its caption faces right, into the canvas, never off its left edge.
  rows.forEach(({ ids, trunk }, index) => ids.forEach((id, place) => {
    const slot = !trunk && ids.length === 1 ? (skipsStacked(id) ? 0 : 1) : place;
    positions.set(id, { x: trunk ? SINGLE : slot * PORTRAIT_COLUMN, y: index * PORTRAIT_ROW });
    sides.set(id, trunk ? "trunk" : slot ? "right" : "left");
  }));
  const stacked = stackedRows.map(row => positions.get(rows[row]!.ids[0]!)!);
  return {
    nodes: nodes.map(node => ({ ...node, position: positions.get(node.id) ?? node.position,
      style: { ...node.style, width: PORTRAIT_CARD_WIDTH, "--graph-node-card-width": `${PORTRAIT_CARD_WIDTH}px`, "--graph-node-glyph-size": "56px",
        "--graph-context-glyph-size": "56px", "--graph-node-icon-size": "28px", "--graph-context-icon-size": "28px",
        "--graph-node-label-size": "16px", "--graph-node-meta-size": "14px" },
      // Labels face away from the centre line, so links running down it never cross a caption.
      data: { ...node.data, phoneLayout: true, phoneSide: sides.get(node.id) } })),
    edges: edges.map((edge): Edge => {
      const from = positions.get(edge.source), to = positions.get(edge.target);
      if (!from || !to) return edge;
      const [sourceHandle, targetHandle] = handles(from, to, positions, stacked);
      // Captions face away from the centre line, so a link's label sits on its centre-line side.
      const side = sides.get(edge.target) === "trunk" ? sides.get(edge.source) : sides.get(edge.target);
      const labelShift = side === "left" ? 1 : side === "right" ? -1 : 0;
      // Verbs resting on desktop links would sit on a phone column's captions; they read on selection.
      return { ...edge, sourceHandle, targetHandle, data: { ...edge.data, phoneLayout: true, labelShift, restingVerb: undefined } };
    }),
  };
}
