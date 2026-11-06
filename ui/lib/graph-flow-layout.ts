import type { Edge } from "@xyflow/react";
import { flowStep, isFinding, isPrincipal, type FlowNode, type ReadingFlow } from "@/lib/graph-flow-model";

/** Spacing for fixed-width cards whose captions wrap and clamp, so one long label cannot widen a column. */
export const FLOW_COLUMN_GAP = 370;
/** Holds a glyph plus a three-line clamped name and two lines of metadata at the legibility floor. */
const ROW_GAP = 340;
const NARROW_ROW_GAP = 380;
/** A column is 370 wide and a row 340 on a canvas about twice as wide as tall, so wide grids frame best. */
const COLUMNS_PER_ROW = 2.4;
/** One row down costs as much as this many columns across. */
const ROW_COST = 1.5;
const SEVERITY_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
const TERMINAL_WEIGHT: Record<string, number> = { role: 3, dataStore: 2, credential: 1 };

type Cell = { column: number; row: number };

export interface FlowSteps {
  next: Map<string, string[]>;
  previous: Map<string, string[]>;
}

export function collectSteps(flow: ReadingFlow, byId: Map<string, FlowNode>, edges: Edge[]): FlowSteps {
  const next = new Map<string, string[]>(), previous = new Map<string, string[]>();
  const add = (map: Map<string, string[]>, key: string, value: string) => { const list = map.get(key); if (list) list.push(value); else map.set(key, [value]); };
  for (const edge of edges) {
    const source = byId.get(edge.source), target = byId.get(edge.target);
    const step = source && target && edge.source !== edge.target ? flowStep(flow, edge, source, target) : null;
    if (step) { add(next, step[0], step[1]); add(previous, step[1], step[0]); }
  }
  return { next, previous };
}

/** Longest distance from any root, so a shorter second route cannot pull a shared node into an earlier column. */
export function longestRanks(roots: string[], next: Map<string, string[]>): Map<string, number> {
  const state = new Map<string, "open" | "done">(), order: string[] = [], forward = new Map<string, string[]>();
  const visit = (id: string) => {
    state.set(id, "open");
    const onward: string[] = [];
    for (const to of next.get(id) ?? []) {
      if (state.get(to) === "open") continue; // A back edge closes a cycle; it cannot extend a reading order.
      onward.push(to);
      if (!state.has(to)) visit(to);
    }
    forward.set(id, onward);
    state.set(id, "done");
    order.push(id);
  };
  for (const root of roots) if (!state.has(root)) visit(root);
  const ranks = new Map(roots.map(root => [root, 0]));
  for (const id of order.reverse()) for (const to of forward.get(id) ?? []) ranks.set(to, Math.max(ranks.get(to) ?? 0, (ranks.get(id) ?? 0) + 1));
  return ranks;
}

const reachableFrom = (start: string, next: Map<string, string[]>) => {
  const seen = new Set([start]);
  for (const id of seen) for (const to of next.get(id) ?? []) seen.add(to);
  return seen;
};

/** Open on what owns the most, not a package that happens to have the longest dependency chain. */
export function bestStart(roots: string[], steps: FlowSteps, byId: Map<string, FlowNode>): Set<string> | undefined {
  const scored = roots.map(id => ({ id, reach: reachableFrom(id, steps.next), isPackage: byId.get(id)?.data.nodeType === "package" }));
  scored.sort((a, b) => Number(a.isPackage) - Number(b.isPackage) || b.reach.size - a.reach.size || a.id.localeCompare(b.id));
  return scored[0]?.reach;
}

/** Nearest distance from a root, for a map where any chain should read contiguously from its start. */
export function nearestRanks(roots: string[], next: Map<string, string[]>): Map<string, number> {
  const ranks = new Map(roots.map(root => [root, 0]));
  for (const [id, rank] of ranks) for (const to of next.get(id) ?? []) if (!ranks.has(to)) ranks.set(to, rank + 1);
  return ranks;
}

/** The one path a first frame must show: the deepest chain, ending on what the flow is about. */
export function primaryPath(flow: ReadingFlow, ranks: Map<string, number>, steps: FlowSteps, byId: Map<string, FlowNode>, within?: Set<string>): string[] {
  const score = (id: string) => {
    const node = byId.get(id)!;
    const subject = (flow === "vulnerability" || flow === "connections") && isFinding(node) ? 1000 * (SEVERITY_WEIGHT[String(node.data.severity).toLowerCase()] ?? 1) : 0;
    const access = flow === "exposure" ? TERMINAL_WEIGHT[node.data.nodeType] ?? (isPrincipal(node) ? 1 : 0) : 0;
    return subject + (ranks.get(id) ?? 0) * 10 + access;
  };
  const candidates = [...ranks.keys()].filter(id => !within || within.has(id));
  const terminal = candidates.sort((a, b) => score(b) - score(a) || a.localeCompare(b))[0];
  if (terminal === undefined) return [];
  const path = [terminal];
  for (let current = terminal; (ranks.get(current) ?? 0) > 0;) {
    const rank = ranks.get(current)!;
    const earlier = (steps.previous.get(current) ?? []).filter(id => ranks.get(id)! < rank && (!within || within.has(id)));
    // Prefer the immediately earlier column so the path stays contiguous on its row.
    const parent = earlier.sort((a, b) => ranks.get(b)! - ranks.get(a)! || a.localeCompare(b))[0];
    if (!parent) break;
    path.unshift(parent);
    current = parent;
  }
  return path;
}

class SlotGrid {
  private taken = new Set<string>();
  bottom = 0;
  constructor(readonly columns: number, private readonly rowLimit: number) {}
  private free(column: number, row: number) { return !this.taken.has(`${column}:${row}`); }
  place(column: number, row: number, cells: Map<string, Cell>, id: string) {
    this.taken.add(`${column}:${row}`);
    this.bottom = Math.max(this.bottom, row);
    cells.set(id, { column, row });
  }
  belowBranches() { return Math.min(this.bottom + 1, Math.max(1, this.rowLimit)); }
  /** The first free row of this exact column: a ranked node's column is its place in the reading order. */
  inColumn(column: number): Cell {
    for (let row = 1; ; row++) if (this.free(column, row)) return { column, row };
  }
  /** Near the wanted column without running far along a row, so a context edge stays short and clear of captions. */
  nearest(wanted: number, startRow = 1): Cell {
    const target = Math.min(Math.max(wanted, 0), this.columns - 1);
    let best: Cell | null = null, bestCost = Infinity;
    // Rows beyond the limit are only for a grid already full; stacking early would push the map past a legible fit.
    const lastRow = Math.max(this.rowLimit, startRow);
    for (let row = startRow; row <= lastRow; row++) for (let column = 0; column < this.columns; column++) {
      const cost = Math.abs(column - target) + (row - startRow) * ROW_COST;
      if (this.free(column, row) && (cost < bestCost || cost === bestCost && column > best!.column)) { best = { column, row }; bestCost = cost; }
    }
    return best ?? this.nearest(wanted, lastRow + 1);
  }
}

/**
 * Primary path on row zero; other flow nodes under their column; context in the nearest free
 * slot below, keeping every context edge left-to-right. Compact rows are what let a real
 * cluster map fit at a legible zoom.
 */
export function placeFlow({ visible, ranks, primary, steps, edges, narrow, strictColumns = true }: {
  /** A flow's column is its reading order; a plain map can fill free slots to stay compact. */
  strictColumns?: boolean;
  visible: FlowNode[];
  ranks: Map<string, number>;
  primary: string[];
  steps: FlowSteps;
  edges: Edge[];
  narrow: boolean;
}): Map<string, { x: number; y: number }> {
  const cells = new Map<string, Cell>();
  const columns = Math.max(Math.ceil(Math.sqrt(visible.length * COLUMNS_PER_ROW)), ...[...ranks.values()].map(rank => rank + 1));
  const grid = new SlotGrid(columns, Math.ceil(visible.length / columns));
  const onPath = new Set(primary);
  for (const id of primary) grid.place(ranks.get(id)!, 0, cells, id);
  const ranked = [...ranks.keys()].filter(id => !onPath.has(id)).sort((a, b) => ranks.get(a)! - ranks.get(b)! || a.localeCompare(b));
  const meanRow = (id: string) => {
    const rows = (steps.previous.get(id) ?? []).flatMap(from => cells.has(from) ? [cells.get(from)!.row] : []);
    return rows.length ? rows.reduce((total, row) => total + row, 0) / rows.length : Number.MAX_SAFE_INTEGER;
  };
  // Stack each column by its parents' rows so sibling edges do not cross on the way in.
  for (const rank of new Set(ranked.map(id => ranks.get(id)!))) {
    for (const id of ranked.filter(item => ranks.get(item) === rank).sort((a, b) => meanRow(a) - meanRow(b) || a.localeCompare(b))) {
      const slot = strictColumns ? grid.inColumn(rank) : grid.nearest(rank);
      grid.place(slot.column, slot.row, cells, id);
    }
  }
  placeContext(visible, edges, grid, cells);
  const rowGap = narrow ? NARROW_ROW_GAP : ROW_GAP;
  return new Map([...cells].map(([id, cell]) => [id, { x: cell.column * FLOW_COLUMN_GAP, y: cell.row * rowGap }]));
}

function placeContext(visible: FlowNode[], edges: Edge[], grid: SlotGrid, cells: Map<string, Cell>) {
  const neighbours = new Map<string, { other: string; columnDelta: number }[]>();
  const link = (from: string, other: string, columnDelta: number) => {
    const list = neighbours.get(from);
    if (list) list.push({ other, columnDelta }); else neighbours.set(from, [{ other, columnDelta }]);
  };
  for (const edge of edges) { link(edge.target, edge.source, 1); link(edge.source, edge.target, -1); }
  const pending = visible.filter(node => !cells.has(node.id)).sort((a, b) => a.id.localeCompare(b.id));
  while (pending.length) {
    let index = pending.findIndex(node => node.data.readingOwner && cells.has(node.data.readingOwner));
    if (index < 0) index = pending.findIndex(node => neighbours.get(node.id)?.some(item => cells.has(item.other)));
    const connected = index >= 0;
    const node = pending.splice(connected ? index : 0, 1)[0]!;
    const owner = node.data.readingOwner ? cells.get(node.data.readingOwner) : undefined;
    // Anchor to the placed neighbour nearest the path, so a context card sits beside what it explains.
    const anchor = connected && !owner ? neighbours.get(node.id)!.filter(item => cells.has(item.other)).sort((a, b) => cells.get(a.other)!.row - cells.get(b.other)!.row)[0]! : null;
    const wanted = owner ? owner.column + 1 : anchor ? cells.get(anchor.other)!.column + anchor.columnDelta : 0;
    // Unconnected records sit below the branches when there is room, so they are not read as part of one.
    const slot = grid.nearest(wanted, connected ? 1 : grid.belowBranches());
    grid.place(slot.column, slot.row, cells, node.id);
  }
}
