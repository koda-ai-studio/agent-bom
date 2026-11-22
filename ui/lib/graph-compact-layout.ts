/** Positions for the compact attack-path canvas: occupied ranks left to right,
 * the selected path as a straight spine on row zero, and every other branch
 * ordered by its neighbours and fanned evenly around them. Presentation only:
 * ranks come from the caller's backend-derived keys, never from entity types. */

// Cards grow in layout units as Fit all zooms out; these gaps keep the separation
// pass's clear space (24 units) at the zooms graphs of this size fit at, so it does not move placed cards.
export const COMPACT_RANK_GAP = 240;
export const COMPACT_ROW_GAP = 180;
/** Layout-unit width of a compact node box; the name truncates inside it. */
export const COMPACT_NODE_WIDTH = 200;

type Link = { id?: string; source: string; target: string };
export type PackItem = { id: string; desired: number; fixed?: boolean };
type Point = { x: number; y: number };

/** Ordered items keep their order and a minimum gap, settling as close to
 * their desired rows as the gap allows; a fixed item stays on row zero. */
export function packRank(items: readonly PackItem[], gap: number): Map<string, number> {
  const out = new Map<string, number>();
  const spine = items.findIndex(item => item.fixed);
  const spread = (list: readonly PackItem[], floor?: (i: number) => number) => {
    const desired = list.map((item, i) => floor ? Math.max(item.desired, floor(i)) : item.desired);
    const forward: number[] = [], backward: number[] = [];
    desired.forEach((d, i) => forward.push(i ? Math.max(d, forward[i - 1]! + gap) : d));
    for (let i = desired.length - 1; i >= 0; i--) backward[i] = i === desired.length - 1 ? desired[i]! : Math.min(desired[i]!, backward[i + 1]! - gap);
    return list.map((item, i) => [item.id, Math.max((forward[i]! + backward[i]!) / 2, floor ? floor(i) : -Infinity)] as const);
  };
  if (spine < 0) { for (const [id, y] of spread(items)) out.set(id, y); return out; }
  out.set(items[spine]!.id, 0);
  for (const [id, y] of spread(items.slice(spine + 1), i => (i + 1) * gap)) out.set(id, y);
  const above = items.slice(0, spine).reverse().map(item => ({ ...item, desired: -item.desired }));
  for (const [id, y] of spread(above, i => (i + 1) * gap)) out.set(id, y === 0 ? 0 : -y);
  return out;
}

/** Longest-path depth inside each base column, so a same-column link always
 * runs left to right. Back edges of a cycle are ignored deterministically. */
function columnDepths(ids: readonly string[], links: readonly Link[], column: (id: string) => number) {
  const out = new Map<string, string[]>();
  for (const link of links) if (column(link.source) === column(link.target)) out.set(link.source, [...(out.get(link.source) ?? []), link.target]);
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
  for (const id of ids) if (!state.has(id)) visit(id);
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
  /** Display nodes placed relative to another node's rank (offset in ranks, may be fractional). */
  attached?: ReadonlyMap<string, { to: string; offset: number }>;
};

function rankKeys({ ids, links, column, attached }: CompactInput) {
  const placed = ids.filter(id => !attached?.has(id));
  const depth = columnDepths(placed, links.filter(link => !attached?.has(link.source) && !attached?.has(link.target)), column);
  const key = new Map(placed.map(id => [id, column(id) * 1000 + depth.get(id)!]));
  for (const [id, { to, offset }] of attached ?? []) {
    const base = to.split("\n").map(target => key.get(target)).filter((value): value is number => value !== undefined);
    key.set(id, (base.length ? Math.min(...base) : 0) + offset);
  }
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

/** A link spanning several ranks reserves a lane slot in every rank it crosses,
 * so its curve never runs through a node standing in between. */
function laneLinks(links: readonly Link[], rank: Map<string, number>, spine: ReadonlySet<string>) {
  const lanes: Link[] = [], dummies = new Map<string, { rank: number; spine: boolean }>(), chains = new Map<string, string[]>();
  links.forEach((link, index) => {
    const from = rank.get(link.source), to = rank.get(link.target);
    if (from === undefined || to === undefined || link.source === link.target) return;
    const [left, right] = from <= to ? [link.source, link.target] : [link.target, link.source];
    const start = Math.min(from, to), end = Math.max(from, to);
    let previous = left;
    const chain: string[] = [];
    if (end - start > 1 && link.id) chains.set(link.id, chain);
    for (let r = start + 1; r < end; r++) {
      const id = `\u0000lane:${index}:${r}`;
      chain.push(id);
      dummies.set(id, { rank: r, spine: spine.has(link.source) && spine.has(link.target) });
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

/** Positions plus, for each link that skips ranks, its lane points from left to right. */
export function compactLayout(input: CompactInput): { positions: Map<string, Point>; lanes: Map<string, Point[]> } {
  const { ids, links, spine } = input;
  const rank = rankKeys(input);
  if (new Set(rank.values()).size === 1 && ids.length > 2 && ![...neighbourMap(ids, links).values()].some(list => list.length)) return { positions: gridPositions(ids), lanes: new Map() };
  const onSpine = new Set(spine.filter(id => rank.has(id)));
  const { lanes, dummies, chains } = laneLinks(links, rank, onSpine);
  for (const [id, lane] of dummies) rank.set(id, lane.rank);
  const all = [...ids, ...dummies.keys()];
  const neighbours = neighbourMap(all, lanes);
  const spineRanks = new Set([...onSpine].map(id => rank.get(id)));
  for (const [id, lane] of dummies) if (lane.spine && !spineRanks.has(lane.rank)) { onSpine.add(id); spineRanks.add(lane.rank); }
  const byRank = new Map<number, string[]>();
  for (const id of [...all].sort((a, b) => Number(onSpine.has(b)) - Number(onSpine.has(a)) || a.localeCompare(b))) byRank.set(rank.get(id)!, [...(byRank.get(rank.get(id)!) ?? []), id]);
  const order = [...byRank.keys()].sort((a, b) => a - b);
  const y = new Map<string, number>();
  for (const r of order) byRank.get(r)!.forEach((id, i) => y.set(id, onSpine.has(id) ? 0 : (i + 1) * COMPACT_ROW_GAP));
  const mean = (list: string[]) => list.length ? list.reduce((sum, id) => sum + y.get(id)!, 0) / list.length : undefined;
  const placeRank = (r: number, leftToRight: boolean) => {
    const members = byRank.get(r)!;
    const desired = new Map(members.map(id => {
      const all = neighbours.get(id)!;
      const lead = all.filter(n => leftToRight ? rank.get(n)! < r : rank.get(n)! > r);
      const trail = all.filter(n => leftToRight ? rank.get(n)! > r : rank.get(n)! < r);
      // A lane slot sits between both of its ends, so a long link climbs a little at each rank.
      if (dummies.has(id)) return [id, mean(all) ?? y.get(id)!];
      return [id, mean(lead) ?? mean(trail) ?? y.get(id)!];
    }));
    const spineId = members.find(id => onSpine.has(id));
    const rest = members.filter(id => id !== spineId)
      .sort((a, b) => desired.get(a)! - desired.get(b)! || y.get(a)! - y.get(b)! || a.localeCompare(b));
    let items: PackItem[] = rest.map(id => ({ id, desired: desired.get(id)! }));
    if (spineId) {
      const above: PackItem[] = [], below: PackItem[] = [];
      for (const item of items) (item.desired < 0 || (item.desired === 0 && above.length < below.length) ? above : below).push(item);
      items = [...above, { id: spineId, desired: 0, fixed: true }, ...below];
    }
    for (const [id, value] of packRank(items, COMPACT_ROW_GAP)) y.set(id, value);
  };
  // Two ordering sweeps, then the final left-to-right row assignment.
  for (const leftToRight of [true, false, true]) for (const r of leftToRight ? order : [...order].reverse()) placeRank(r, leftToRight);
  const rankIndex = new Map(order.map((r, i) => [r, i]));
  const gap = rankGap(order.map(r => byRank.get(r)!.map(id => y.get(id)!)));
  const point = (id: string) => ({ x: rankIndex.get(rank.get(id)!)! * gap, y: Math.round(y.get(id)!) });
  return { positions: new Map(ids.map(id => [id, point(id)])), lanes: new Map([...chains].map(([id, chain]) => [id, chain.map(point)])) };
}
