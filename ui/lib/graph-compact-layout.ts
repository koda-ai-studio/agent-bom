/** Positions for the compact attack-path canvas: occupied ranks left to right,
 * the selected path as a straight spine on row zero, and every other branch
 * ordered by its neighbours and fanned evenly around them. Presentation only:
 * ranks come from the caller's backend-derived keys, never from entity types. */

import { blockedLinkCount, type CaptionText, fitZoom, linkArcs } from "@/lib/graph-compact-arcs";

// Cards grow in layout units as Fit all zooms out; these gaps keep the separation
// pass's clear space (24 units) at the zooms graphs of this size fit at, so it does not move placed cards.
export const COMPACT_RANK_GAP = 240;
export const COMPACT_ROW_GAP = 200;
/** Layout-unit width of a compact node box; the name truncates inside it. */
export const COMPACT_NODE_WIDTH = 216;

type Link = { id?: string; source: string; target: string; data?: Record<string, unknown> | undefined };
/** `below`: the room a card needs under its row when more than the row gap (a two-line caption at the largest label size). */
export type PackItem = { id: string; desired: number; fixed?: boolean; below?: number | undefined };
type Point = { x: number; y: number };

/** Clear space between two lanes, and between a lane and a card's row. */
export const COMPACT_LANE_GAP = 48;
export const COMPACT_LANE_CLEARANCE = 170;

/** Ordered items keep their order and a minimum gap, settling as close to
 * their desired rows as the gap allows; a fixed item stays on row zero.
 * `lane` items are link lanes, which need less room than a card. */
export function packRank(items: readonly (PackItem & { lane?: boolean })[], gap: number, forwardOnly = false): Map<string, number> {
  const out = new Map<string, number>();
  type Item = PackItem & { lane?: boolean };
  // `upper` is the card above the pair: its caption decides how much room the pair needs.
  const between = (a: Item | undefined, b: Item | undefined, upper: Item | undefined) =>
    a?.lane && b?.lane ? COMPACT_LANE_GAP : a?.lane || b?.lane ? Math.min(gap, COMPACT_LANE_CLEARANCE) : Math.max(gap, upper?.below ?? 0);
  const spine = items.findIndex(item => item.fixed);
  const spread = (list: readonly Item[], anchor?: Item, upward = false) => {
    const pair = (a: Item | undefined, b: Item | undefined) => between(a, b, upward ? b : a);
    const floor: number[] = [];
    list.forEach((item, i) => floor.push(anchor ? (i ? floor[i - 1]! : 0) + pair(i ? list[i - 1] : anchor, item) : -Infinity));
    const desired = list.map((item, i) => Math.max(item.desired, floor[i]!));
    const forward: number[] = [], backward: number[] = [];
    desired.forEach((d, i) => forward.push(i ? Math.max(d, forward[i - 1]! + pair(list[i - 1], list[i])) : d));
    for (let i = desired.length - 1; i >= 0; i--) backward[i] = i === desired.length - 1 ? desired[i]! : Math.min(desired[i]!, backward[i + 1]! - pair(list[i], list[i + 1]));
    // Forward only: each item keeps its own row unless an earlier one pushes it down; nothing moves up.
    return list.map((item, i) => [item.id, Math.max(forwardOnly ? forward[i]! : (forward[i]! + backward[i]!) / 2, floor[i]!)] as const);
  };
  if (spine < 0) { for (const [id, y] of spread(items)) out.set(id, y); return out; }
  const fixed = items[spine]!;
  out.set(fixed.id, 0);
  for (const [id, y] of spread(items.slice(spine + 1), fixed)) out.set(id, y);
  const above = items.slice(0, spine).reverse().map(item => ({ ...item, desired: -item.desired }));
  for (const [id, y] of spread(above, fixed, true)) out.set(id, y === 0 ? 0 : -y);
  return out;
}

/** Longest-path depth inside each base column, so a same-column link always
 * runs left to right. Back edges of a cycle are ignored deterministically. */
function columnDepths(ids: readonly string[], links: readonly Link[], column: (id: string) => number, containment: CompactInput["containment"]) {
  const out = new Map<string, string[]>();
  for (const link of links) {
    if (column(link.source) !== column(link.target)) continue;
    const pair = containment ? containment(link) : [link.source, link.target] as const;
    if (pair) out.set(pair[0], [...(out.get(pair[0]) ?? []), pair[1]].sort());
  }
  const state = new Map<string, 1 | 2>(), forward: Link[] = [];
  const visit = (id: string) => {
    state.set(id, 1);
    for (const target of out.get(id) ?? []) {
      if (state.get(target) === 1) continue;
      forward.push({ source: id, target });
      if (!state.has(target)) visit(target);
    }
    state.set(id, 2);
  };
  for (const id of [...ids].sort()) if (!state.has(id)) visit(id);
  const depth = new Map(ids.map(id => [id, 0]));
  for (let changed = true, guard = 0; changed && guard <= ids.length; guard++) {
    changed = false;
    for (const { source, target } of forward) if (depth.get(target)! < depth.get(source)! + 1) { depth.set(target, depth.get(source)! + 1); changed = true; }
  }
  return depth;
}

export type CompactInput = {
  ids: readonly string[];
  links: readonly Link[];
  /** Backend column for each id (fractional keys place display nodes between columns). */
  column: (id: string) => number;
  spine: readonly string[];
  /** Leaves that sit level with their parent (findings), rather than fanning around it. */
  levelLeaf?: (id: string) => boolean;
  /** Parent and child of a link inside one column, or null for a peer link that splits no rank. */
  containment?: (link: Link) => readonly [string, string] | null;
  /** Display nodes placed relative to another node's rank: a whole offset joins a later column's rank, a fraction sits between ranks. */
  attached?: ReadonlyMap<string, { to: string; offset: number }>;
  /** The text each card draws under its glyph; links are kept clear of it. */
  caption?: (id: string) => CaptionText;
  /** Layout-unit width of a card's caption box, when wider than the compact default; ranks space apart to fit it. */
  width?: (id: string) => number;
  /** Room a card needs under its row when its caption is taller than one row gap allows. */
  tall?: (id: string) => number | undefined;
};

function rankKeys({ ids, links, column, attached, containment }: CompactInput) {
  const placed = ids.filter(id => !attached?.has(id));
  const depth = columnDepths(placed, links.filter(link => !attached?.has(link.source) && !attached?.has(link.target)), column, containment);
  const key = new Map(placed.map(id => [id, column(id) * 1000 + depth.get(id)!]));
  // Before an anchor: left of the earliest target. After: right of the latest one. Chains resolve in order.
  const pending = new Map(attached ?? []);
  for (let pass = 0; pending.size && pass <= pending.size + 1; pass++) {
    for (const [id, { to, offset }] of pending) {
      const targets = to.split("\n");
      if (targets.some(target => pending.has(target) && target !== id)) continue;
      const base = targets.map(target => key.get(target)).filter((value): value is number => value !== undefined);
      const anchor = base.length ? (offset < 0 ? Math.min(...base) : Math.max(...base)) : 0;
      // A whole-number offset joins the rank of the column that many columns along; a fraction sits between ranks.
      key.set(id, Number.isInteger(offset) ? (Math.floor(anchor / 1000) + offset) * 1000 : anchor + offset);
      pending.delete(id);
    }
  }
  for (const [id, { offset }] of pending) key.set(id, offset);
  const ranks = [...new Set(key.values())].sort((a, b) => a - b);
  return new Map([...key].map(([id, value]) => [id, ranks.indexOf(value)]));
}

function neighbourMap(ids: readonly string[], links: readonly Link[]) {
  const known = new Set(ids), map = new Map(ids.map(id => [id, [] as string[]]));
  for (const { source, target } of links) {
    if (source === target || !known.has(source) || !known.has(target)) continue;
    map.get(source)!.push(target); map.get(target)!.push(source);
  }
  return map;
}

function gridPositions(ids: readonly string[]): Map<string, Point> {
  const columns = Math.max(1, Math.ceil(Math.sqrt(ids.length * 1.6)));
  return new Map([...ids].sort().map((id, i) => [id, { x: (i % columns) * COMPACT_RANK_GAP, y: Math.floor(i / columns) * COMPACT_ROW_GAP }]));
}

/** A tall fan over few ranks gets wider ranks, so its branches leave at a gentle
 * angle; the graph never grows wider than a canvas-shaped frame around its height. */
function rankGap(ranks: number[][]) {
  const span = Math.max(0, ...ranks.map(ys => ys.length ? Math.max(...ys) - Math.min(...ys) : 0));
  if (ranks.length < 2) return COMPACT_RANK_GAP;
  const frame = (2.2 * (span + COMPACT_ROW_GAP)) / (ranks.length - 1);
  return Math.round(Math.max(COMPACT_RANK_GAP, Math.min(span * 0.5, frame, COMPACT_RANK_GAP * 2)));
}

const LANE_SLOT_BUDGET = 4000;


/** A link spanning several ranks reserves a placeholder slot in every rank it crosses.
 * The slots only space the ordering; the link itself is drawn as one curve. */
function laneLinks(links: readonly Link[], rank: Map<string, number>, spine: ReadonlySet<string>) {
  const lanes: Link[] = [], dummies = new Map<string, { rank: number; spine: boolean; ends: [string, string] }>(), chains = new Map<string, string[]>();
  const span = (link: Link) => Math.abs((rank.get(link.source) ?? 0) - (rank.get(link.target) ?? 0)) - 1;
  // Past this many lane slots a map is an overview; its long links draw as plain curves.
  const budgeted = links.reduce((sum, link) => sum + Math.max(0, span(link)), 0) <= LANE_SLOT_BUDGET;
  links.forEach((link, index) => {
    const from = rank.get(link.source), to = rank.get(link.target);
    if (from === undefined || to === undefined || link.source === link.target) return;
    if (!budgeted) { lanes.push(link); return; }
    const [left, right] = from <= to ? [link.source, link.target] : [link.target, link.source];
    const start = Math.min(from, to), end = Math.max(from, to);
    let previous = left;
    const chain: string[] = [];
    if (end - start > 1 && link.id) chains.set(link.id, chain);
    for (let r = start + 1; r < end; r++) {
      const id = `\u0000lane:${link.id ?? `${link.source}\u0000${link.target}:${index}`}:${r}`;
      chain.push(id);
      dummies.set(id, { rank: r, spine: spine.has(link.source) && spine.has(link.target), ends: [link.source, link.target] });
      lanes.push({ source: previous, target: id });
      previous = id;
    }
    lanes.push({ source: previous, target: right });
  });
  return { lanes, dummies, chains };
}

/** Sugiyama-lite: ranks, barycentre ordering sweeps, then gap-preserving rows. */
export function compactPositions(input: CompactInput): Map<string, Point> {
  return compactLayout(input).positions;
}

/** Positions, plus an arc height for each long link whose direct curve would still cross a card. */
export function compactLayout(input: CompactInput): { positions: Map<string, Point>; arcs: Map<string, [number, number]>; behind: Set<string> } {
  const { ids, links, spine } = input;
  const rank = rankKeys(input);
  if (new Set(rank.values()).size === 1 && ids.length > 2 && ![...neighbourMap(ids, links).values()].some(list => list.length)) return { positions: gridPositions(ids), arcs: new Map(), behind: new Set() };
  const onSpine = new Set(spine.filter(id => rank.has(id)));
  const { lanes, dummies } = laneLinks(links, rank, onSpine);
  for (const [id, lane] of dummies) rank.set(id, lane.rank);
  const all = [...ids, ...dummies.keys()];
  const neighbours = neighbourMap(all, lanes);
  const spineRanks = new Set([...onSpine].map(id => rank.get(id)));
  for (const [id, lane] of dummies) if (lane.spine && !spineRanks.has(lane.rank)) { onSpine.add(id); spineRanks.add(lane.rank); }
  const byRank = new Map<number, string[]>();
  for (const id of [...all].sort((a, b) => Number(onSpine.has(b)) - Number(onSpine.has(a)) || a.localeCompare(b))) {
    const members = byRank.get(rank.get(id)!);
    if (members) members.push(id); else byRank.set(rank.get(id)!, [id]);
  }
  const order = [...byRank.keys()].sort((a, b) => a - b);
  const y = new Map<string, number>();
  for (const r of order) byRank.get(r)!.forEach((id, i) => y.set(id, onSpine.has(id) ? 0 : (i + 1) * COMPACT_ROW_GAP));
  const tall = (id: string) => dummies.has(id) ? undefined : input.tall?.(id);
  const mean = (list: string[]) => list.length ? list.reduce((sum, id) => sum + y.get(id)!, 0) / list.length : undefined;
  const placeRank = (r: number, leftToRight: boolean) => {
    const members = byRank.get(r)!;
    const desired = new Map<string, number>(), key = new Map<string, number>();
    for (const id of members) {
      const all = neighbours.get(id)!;
      const lead = all.filter(n => leftToRight ? rank.get(n)! < r : rank.get(n)! > r);
      const trail = all.filter(n => leftToRight ? rank.get(n)! > r : rank.get(n)! < r);
      // A lane slot sits between both of its ends, and is ordered by the end it is heading to,
      // so a long link stays inside their span instead of looping around nodes on the way.
      const lane = dummies.get(id);
      if (!lane) { desired.set(id, mean(lead) ?? mean(trail) ?? y.get(id)!); key.set(id, desired.get(id)!); continue; }
      const [lo, hi] = [y.get(lane.ends[0])!, y.get(lane.ends[1])!].sort((a, b) => a - b);
      const within = (value: number) => Math.min(hi!, Math.max(lo!, value));
      desired.set(id, within(mean(all) ?? y.get(id)!));
      key.set(id, within(mean(trail) ?? desired.get(id)!));
    }
    const spineId = members.find(id => onSpine.has(id));
    // On a tie, a lane sits nearer the spine than a card.
    const towardSpine = (a: string, b: string) => (Number(dummies.has(b)) - Number(dummies.has(a))) * (key.get(a)! < 0 ? -1 : 1);
    const rest = members.filter(id => id !== spineId)
      .sort((a, b) => key.get(a)! - key.get(b)! || towardSpine(a, b) || y.get(a)! - y.get(b)! || a.localeCompare(b));
    let items: (PackItem & { lane?: boolean })[] = rest.map(id => ({ id, desired: desired.get(id)!, lane: dummies.has(id), below: tall(id) }));
    if (spineId) {
      const above: typeof items = [], below: typeof items = [];
      // On a tie the upper side fills first: captions hang below glyphs, so a link rising from the spine meets none.
      for (const item of items) (key.get(item.id)! < 0 || (key.get(item.id) === 0 && !item.lane && above.length <= below.length) ? above : below).push(item);
      items = [...above, { id: spineId, desired: 0, fixed: true, lane: dummies.has(spineId), below: tall(spineId) }, ...below];
    }
    for (const [id, value] of packRank(items, COMPACT_ROW_GAP)) y.set(id, value);
  };
  // Ordering sweeps in both directions, then the final left-to-right row assignment.
  for (const leftToRight of [true, false, true, false, true]) for (const r of leftToRight ? order : [...order].reverse()) placeRank(r, leftToRight);
  const rankIndex = new Map(order.map((r, i) => [r, i]));
  const gap = rankGap(order.map(r => byRank.get(r)!.map(id => y.get(id)!)));
  // Each rank starts far enough right of the previous one for both ranks' widest caption boxes.
  const rankWidth = order.map(r => Math.max(COMPACT_NODE_WIDTH, ...byRank.get(r)!.filter(id => !dummies.has(id)).map(id => input.width?.(id) ?? COMPACT_NODE_WIDTH)));
  const rankX: number[] = [];
  rankWidth.forEach((width, i) => rankX.push(i ? rankX[i - 1]! + Math.max(gap, (rankWidth[i - 1]! + width) / 2 + COMPACT_RANK_GAP - COMPACT_NODE_WIDTH) : 0));
  const point = (id: string) => ({ x: rankX[rankIndex.get(rank.get(id)!)!]!, y: Math.round(y.get(id)!) });
  for (const r of order) transposeRank(byRank.get(r)!.filter(id => !dummies.has(id)), r, rank, neighbours, y, onSpine);
  const positions = new Map(ids.map(id => [id, point(id)]));
  const leaf = (id: string) => Boolean(input.levelLeaf?.(id)) && (neighbours.get(id) ?? []).length > 0 && neighbours.get(id)!.every(n => rank.get(n)! < rank.get(id)!);
  levelLeaves(ids, positions, leaf, neighbours, onSpine, tall);
  // Captions are judged at a fixed zoom a little below the one the starting layout fits at, and the search may not
  // grow the layout past it: what it makes drawable stays drawable at the zoom Fit all then picks.
  const zoom = ids.length <= REFINE_CARDS ? fitZoom(positions, COMPACT_NODE_WIDTH) * ZOOM_BUDGET : undefined;
  if (input.caption && zoom !== undefined) {
    refinePlacement(ids, links, positions, onSpine, input.caption, input.levelLeaf, tall, zoom);
    levelLeaves(ids, positions, leaf, neighbours, onSpine, tall);
  }
  clearLevelLinks(ids, links, positions, tall, onSpine);
  const { arcs, behind } = linkArcs(links, positions, input.caption, COMPACT_NODE_WIDTH, zoom);
  return { positions, arcs, behind };
}

/** Swap neighbouring cards of one rank when that removes crossings with the ranks either side. */
function transposeRank(members: string[], r: number, rank: Map<string, number>, neighbours: Map<string, string[]>, y: Map<string, number>, spine: ReadonlySet<string>) {
  const rows = members.filter(id => !spine.has(id)).sort((a, b) => y.get(a)! - y.get(b)!);
  const crossings = (upper: string, lower: string) => {
    let count = 0;
    for (const side of [-1, 1]) {
      const near = (id: string) => neighbours.get(id)!.filter(n => Math.sign(rank.get(n)! - r) === side).map(n => y.get(n)!);
      for (const a of near(upper)) for (const b of near(lower)) if (a > b) count++;
    }
    return count;
  };
  for (let i = 0; i + 1 < rows.length; i++) {
    const [a, b] = [rows[i]!, rows[i + 1]!];
    if (crossings(b, a) >= crossings(a, b)) continue;
    const ya = y.get(a)!; y.set(a, y.get(b)!); y.set(b, ya);
    rows[i] = b; rows[i + 1] = a;
  }
}

/** Past this many cards the ordering sweeps alone place rows; the search below is for readable investigations. */
const REFINE_CARDS = 24;
const REFINE_STEP = COMPACT_ROW_GAP / 2;

function segmentsCross(a: Point, b: Point, c: Point, d: Point): boolean {
  const side = (p: Point, q: Point, r: Point) => Math.sign((q.x - p.x) * (r.y - p.y) - (q.y - p.y) * (r.x - p.x));
  return side(a, b, c) * side(a, b, d) < 0 && side(c, d, a) * side(c, d, b) < 0;
}

/** Placement cost: a link that cannot be drawn as a plain curve clear of every caption costs most,
 * then crossings between links, then how far links climb or fall. */
function placementCost(links: readonly Link[], positions: ReadonlyMap<string, Point>, caption: (id: string) => CaptionText, zoom: number): number {
  const drawn = links.filter(link => positions.has(link.source) && positions.has(link.target) && link.source !== link.target);
  let crossings = 0, climb = 0;
  drawn.forEach((link, i) => {
    const a = positions.get(link.source)!, b = positions.get(link.target)!;
    climb += Math.abs(a.y - b.y) / COMPACT_ROW_GAP;
    for (const other of drawn.slice(i + 1)) {
      if ([other.source, other.target].some(id => id === link.source || id === link.target)) continue;
      if (segmentsCross(a, b, positions.get(other.source)!, positions.get(other.target)!)) crossings++;
    }
  });
  return blockedLinkCount(drawn, positions, caption, COMPACT_NODE_WIDTH, zoom) * 1000 + crossings * 40 + climb * 4;
}

/** A card with the run of single-link cards leading into it from the left (an entry chain such as
 * Internet, service, workload), which moves with it so the chain stays straight. */
function leadChain(id: string, links: readonly Link[], positions: ReadonlyMap<string, Point>, spine: ReadonlySet<string>): string[] {
  const chain = [id];
  for (let current = id; ;) {
    const here = positions.get(current)!;
    const left = links.filter(link => (link.target === current || link.source === current) && link.source !== link.target)
      .map(link => link.source === current ? link.target : link.source).filter(other => positions.get(other) && positions.get(other)!.x < here.x);
    if (left.length !== 1) return chain;
    const next = left[0]!, degree = links.filter(link => link.source === next || link.target === next).length;
    if (spine.has(next) || chain.includes(next) || degree > 2 || positions.get(next)!.y !== here.y) return chain;
    chain.push(next);
    current = next;
  }
}

/** Moves cards (with their lead chains) to free rows of their own rank, or swaps two cards of a rank,
 * while that lowers the placement cost. The spine never moves; a finding leaf stays on its parent's row. */
/** Searches from the sweep's placement and from its mirror image (branches flipped across the spine), keeping
 * the better result: a greedy search from one start can settle where a link still has no clear curve. */
function refinePlacement(ids: readonly string[], links: readonly Link[], positions: Map<string, Point>, spine: ReadonlySet<string>,
  caption: (id: string) => CaptionText, levelLeaf: ((id: string) => boolean) | undefined, tall: (id: string) => number | undefined, zoom: number) {
  if (ids.length < 3) return;
  // Deterministic restarts: the sweep's placement, its mirror image, and variants with some branches flipped.
  // One evaluation budget across every restart keeps the search to a few tens of milliseconds.
  const budget = { left: SEARCH_BUDGET };
  const flips = (seed: number) => new Map([...positions].map(([id, p]) => [id, spine.has(id) || !flipped(seed, id) ? p : { x: p.x, y: -p.y }]));
  const starts = [positions, ...Array.from({ length: RESTARTS }, (_, seed) => flips(seed))];
  // A restart never begins taller than the sweep's own layout plus one row; moves are bounded by the zoom budget.
  const heightOf = (map: ReadonlyMap<string, Point>) => { const ys = ids.map(id => map.get(id)!.y); return Math.max(...ys) - Math.min(...ys); };
  const maxSpan = heightOf(positions) + COMPACT_ROW_GAP;
  // Restarts run only while every link so far still lacks a clear curve.
  let best: { copy: Map<string, Point>; cost: number } | null = null;
  for (const [i, start] of starts.entries()) {
    if (i > 0 && (!rowsClear(ids, start, tall) || heightOf(start) > maxSpan)) continue;
    const copy = new Map(start), cost = refineRows(ids, links, copy, spine, caption, zoom, levelLeaf, tall, budget);
    if (!best || cost < best.cost - 1e-6) best = { copy, cost };
    if (best.cost < 1000 || budget.left <= 0) break;
  }
  if (!best) return;
  for (const [id, p] of best.copy) positions.set(id, p);
}

const RESTARTS = 8;
/** Placement evaluations one layout may spend searching. */
const SEARCH_BUDGET = 2200;
/** Seed 0 flips every branch (the mirror image); later seeds flip a hashed half of them. */
function flipped(seed: number, id: string): boolean {
  if (seed === 0) return true;
  let hash = seed * 2654435761;
  for (let i = 0; i < id.length; i++) hash = Math.imul(hash ^ id.charCodeAt(i), 16777619);
  return ((hash >>> 0) & 1) === 1;
}

function rowsClear(ids: readonly string[], positions: ReadonlyMap<string, Point>, tall: (id: string) => number | undefined): boolean {
  return ids.every(a => ids.every(b => {
    const pa = positions.get(a)!, pb = positions.get(b)!;
    return a === b || pa.x !== pb.x || pa.y > pb.y || pb.y - pa.y >= Math.max(COMPACT_ROW_GAP, tall(a) ?? 0);
  }));
}

function refineRows(ids: readonly string[], links: readonly Link[], positions: Map<string, Point>, spine: ReadonlySet<string>,
  caption: (id: string) => CaptionText, zoom: number, levelLeaf?: (id: string) => boolean, tall: (id: string) => number | undefined = () => undefined, budget = { left: SEARCH_BUDGET }): number {
  const movable = ids.filter(id => !spine.has(id) && !levelLeaf?.(id)).sort();
  let cost = placementCost(links, positions, caption, zoom);
  const attempt = (moves: [string, number][]) => {
    const before = moves.map(([id]) => [id, positions.get(id)!] as const);
    for (const [id, y] of moves) positions.set(id, { x: positions.get(id)!.x, y });
    const next = budget.left-- > 0 && fitZoom(positions, COMPACT_NODE_WIDTH) >= zoom ? placementCost(links, positions, caption, zoom) : Infinity;
    if (next < cost - 1e-6) { cost = next; return true; }
    for (const [id, point] of before) positions.set(id, point);
    return false;
  };
  const room = (upper: string) => Math.max(COMPACT_ROW_GAP, tall(upper) ?? 0);
  // The spine's own row is taken wherever the spine runs: nothing else may sit on it between its first and last hop.
  const spineXs = [...spine].filter(id => positions.has(id)).map(id => positions.get(id)!.x);
  const onSpineRow = (id: string, y: number) => spineXs.length > 1 && Math.abs(y - positions.get([...spine].find(s => positions.has(s))!)!.y) < COMPACT_ROW_GAP / 2
    && positions.get(id)!.x > Math.min(...spineXs) && positions.get(id)!.x < Math.max(...spineXs);
  const free = (id: string, y: number, ignore: readonly string[]) => !onSpineRow(id, y) && ids.every(other => {
    if (other === id || ignore.includes(other) || positions.get(other)!.x !== positions.get(id)!.x) return true;
    const peer = positions.get(other)!.y;
    return peer < y ? y - peer >= room(other) : peer - y >= room(id);
  });
  for (let pass = 0; pass < 6 && cost > 0; pass++) {
    let improved = false;
    for (const id of movable) {
      const ys = [...positions.values()].map(p => p.y);
      const top = Math.floor((Math.min(...ys) - COMPACT_ROW_GAP) / REFINE_STEP), bottom = Math.ceil((Math.max(...ys) + COMPACT_ROW_GAP) / REFINE_STEP);
      for (let step = top; step <= bottom; step++) {
        const y = step * REFINE_STEP, home = positions.get(id)!.y;
        if (y === home) continue;
        const chain = leadChain(id, links, positions, spine).filter(member => !spine.has(member));
        if (chain.every(member => free(member, y, chain)) && attempt(chain.map(member => [member, y]))) improved = true;
      }
      // Swap with a peer of the same rank.
      for (const other of movable) {
        if (other <= id || positions.get(other)!.x !== positions.get(id)!.x || tall(other) !== tall(id)) continue;
        if (attempt([[id, positions.get(other)!.y], [other, positions.get(id)!.y]])) improved = true;
      }
    }
    // A link no curve can draw yet: also try moving two cards at once, on whole rows.
    if (cost >= 1000 && ids.length <= PAIR_CARDS && pairMoves()) improved = true;
    if (!improved) break;
  }

  return cost;

  function pairMoves(): boolean {
    const ys = [...positions.values()].map(p => p.y);
    const rows: number[] = [];
    for (let y = Math.floor(Math.min(...ys) / COMPACT_ROW_GAP) - 1; y <= Math.ceil(Math.max(...ys) / COMPACT_ROW_GAP) + 1; y++) rows.push(y * COMPACT_ROW_GAP);
    let moved = false;
    for (const [i, a] of movable.entries()) for (const b of movable.slice(i + 1)) {
      const shared = positions.get(a)!.x === positions.get(b)!.x;
      for (const ya of rows) for (const yb of rows) {
        if (!free(a, ya, [b]) || !free(b, yb, [a])) continue;
        if (shared && (ya < yb ? yb - ya < room(a) : ya - yb < room(b))) continue;
        if (attempt([[a, ya], [b, yb]])) moved = true;
      }
    }
    return moved;
  }
}

/** Room the placement search may take: the layout may grow until Fit all zooms this much further out. */
const ZOOM_BUDGET = 0.9;
/** Two-card moves are tried only on small investigations, where they stay cheap. */
const PAIR_CARDS = 16;

/** A finding leaf sits level with its parent (the package or asset it was found on), even in a rank it shares
 * with other cards: each leaf takes its parent's row and the cards after it in the rank move apart to make room. */
function levelLeaves(ids: readonly string[], positions: Map<string, Point>, leaf: (id: string) => boolean,
  neighbours: ReadonlyMap<string, string[]>, spine: ReadonlySet<string>, tall: (id: string) => number | undefined) {
  const ranks = new Map<number, string[]>();
  for (const id of ids) ranks.set(positions.get(id)!.x, [...(ranks.get(positions.get(id)!.x) ?? []), id]);
  for (const members of ranks.values()) {
    if (!members.some(leaf)) continue;
    const target = (id: string) => {
      if (!leaf(id)) return positions.get(id)!.y;
      const parents = neighbours.get(id)!.filter(n => positions.has(n)).map(n => positions.get(n)!.y);
      return parents.length ? parents.reduce((sum, value) => sum + value, 0) / parents.length : positions.get(id)!.y;
    };
    const spineId = members.find(id => spine.has(id));
    const rest = members.filter(id => id !== spineId).sort((a, b) => target(a) - target(b) || Number(leaf(b)) - Number(leaf(a)) || a.localeCompare(b));
    let items: PackItem[] = rest.map(id => ({ id, desired: target(id), below: tall(id) }));
    if (spineId) items = [...items.filter(item => item.desired < 0), { id: spineId, desired: 0, fixed: true, below: tall(spineId) }, ...items.filter(item => item.desired >= 0)];
    for (const [id, value] of packRank(items, COMPACT_ROW_GAP, true)) positions.set(id, { x: positions.get(id)!.x, y: Math.round(value) });
  }
}

/** A card (off the spine) standing on the row of a level link it is not part of (a finding group between a spine hop and the next,
 * or between a role and the data it reaches) would sit on that line: it moves to the nearest free row above. */
function clearLevelLinks(ids: readonly string[], links: readonly Link[], positions: Map<string, Point>, tall: (id: string) => number | undefined, spine: ReadonlySet<string>) {
  const linked = (a: string, b: string) => links.some(link => (link.source === a && link.target === b) || (link.source === b && link.target === a));
  const level = links.filter(link => positions.has(link.source) && positions.has(link.target) && positions.get(link.source)!.y === positions.get(link.target)!.y);
  for (const id of ids) {
    if (spine.has(id)) continue;
    const here = positions.get(id)!;
    // A card in a chain with both ends (A → B → C under A → C) belongs on that row.
    const blocking = level.some(link => link.source !== id && link.target !== id && !(linked(id, link.source) && linked(id, link.target)) && positions.get(link.source)!.y === here.y
      && here.x > Math.min(positions.get(link.source)!.x, positions.get(link.target)!.x) && here.x < Math.max(positions.get(link.source)!.x, positions.get(link.target)!.x));
    if (!blocking) continue;
    const peers = ids.filter(other => other !== id && positions.get(other)!.x === here.x).map(other => ({ y: positions.get(other)!.y, room: Math.max(COMPACT_ROW_GAP, tall(other) ?? 0) }));
    const room = Math.max(COMPACT_ROW_GAP, tall(id) ?? 0);
    for (let step = 1; step < 20; step++) {
      const y = here.y - step * COMPACT_ROW_GAP;
      if (peers.every(peer => peer.y < y ? y - peer.y >= peer.room : peer.y - y >= room)) { positions.set(id, { x: here.x, y }); break; }
    }
  }
}
