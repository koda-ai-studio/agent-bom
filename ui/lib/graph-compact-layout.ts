/** Positions for the compact attack-path canvas: occupied ranks left to right,
 * the selected path as a straight spine on row zero, and every other branch
 * ordered by its neighbours and fanned evenly around them. Presentation only:
 * ranks come from the caller's backend-derived keys, never from entity types. */

// Cards grow in layout units as Fit all zooms out; these gaps keep the separation
// pass's clear space (24 units) at the zooms graphs of this size fit at, so it does not move placed cards.
export const COMPACT_RANK_GAP = 240;
export const COMPACT_ROW_GAP = 200;
/** Layout-unit width of a compact node box; the name truncates inside it. */
export const COMPACT_NODE_WIDTH = 200;

type Link = { id?: string; source: string; target: string; data?: Record<string, unknown> | undefined };
export type PackItem = { id: string; desired: number; fixed?: boolean };
type Point = { x: number; y: number };

/** Clear space between two lanes, and between a lane and a card's row. */
export const COMPACT_LANE_GAP = 48;
export const COMPACT_LANE_CLEARANCE = 170;

/** Ordered items keep their order and a minimum gap, settling as close to
 * their desired rows as the gap allows; a fixed item stays on row zero.
 * `lane` items are link lanes, which need less room than a card. */
export function packRank(items: readonly (PackItem & { lane?: boolean })[], gap: number): Map<string, number> {
  const out = new Map<string, number>();
  const between = (a: { lane?: boolean } | undefined, b: { lane?: boolean } | undefined) =>
    a?.lane && b?.lane ? COMPACT_LANE_GAP : a?.lane || b?.lane ? Math.min(gap, COMPACT_LANE_CLEARANCE) : gap;
  const spine = items.findIndex(item => item.fixed);
  const spread = (list: readonly (PackItem & { lane?: boolean })[], anchor?: PackItem & { lane?: boolean }) => {
    const floor: number[] = [];
    list.forEach((item, i) => floor.push(anchor ? (i ? floor[i - 1]! : 0) + between(i ? list[i - 1] : anchor, item) : -Infinity));
    const desired = list.map((item, i) => Math.max(item.desired, floor[i]!));
    const forward: number[] = [], backward: number[] = [];
    desired.forEach((d, i) => forward.push(i ? Math.max(d, forward[i - 1]! + between(list[i - 1], list[i])) : d));
    for (let i = desired.length - 1; i >= 0; i--) backward[i] = i === desired.length - 1 ? desired[i]! : Math.min(desired[i]!, backward[i + 1]! - between(list[i], list[i + 1]));
    return list.map((item, i) => [item.id, Math.max((forward[i]! + backward[i]!) / 2, floor[i]!)] as const);
  };
  if (spine < 0) { for (const [id, y] of spread(items)) out.set(id, y); return out; }
  const fixed = items[spine]!;
  out.set(fixed.id, 0);
  for (const [id, y] of spread(items.slice(spine + 1), fixed)) out.set(id, y);
  const above = items.slice(0, spine).reverse().map(item => ({ ...item, desired: -item.desired }));
  for (const [id, y] of spread(above, fixed)) out.set(id, y === 0 ? 0 : -y);
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
  /** Parent and child of a link inside one column, or null for a peer link that splits no rank. */
  containment?: (link: Link) => readonly [string, string] | null;
  /** Display nodes placed relative to another node's rank (offset in ranks, may be fractional). */
  attached?: ReadonlyMap<string, { to: string; offset: number }>;
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
      key.set(id, (base.length ? (offset < 0 ? Math.min(...base) : Math.max(...base)) : 0) + offset);
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
/** Layout units a card occupies above and below its row: half a glyph above, glyph and caption below. */
const CARD_ABOVE = 60, CARD_BELOW = 130;

/** A link spanning several ranks reserves a lane slot in every rank it crosses,
 * so its curve never runs through a node standing in between. */
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
  for (const id of [...all].sort((a, b) => Number(onSpine.has(b)) - Number(onSpine.has(a)) || a.localeCompare(b))) {
    const members = byRank.get(rank.get(id)!);
    if (members) members.push(id); else byRank.set(rank.get(id)!, [id]);
  }
  const order = [...byRank.keys()].sort((a, b) => a - b);
  const y = new Map<string, number>();
  for (const r of order) byRank.get(r)!.forEach((id, i) => y.set(id, onSpine.has(id) ? 0 : (i + 1) * COMPACT_ROW_GAP));
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
    let items: (PackItem & { lane?: boolean })[] = rest.map(id => ({ id, desired: desired.get(id)!, lane: dummies.has(id) }));
    if (spineId) {
      const above: typeof items = [], below: typeof items = [];
      for (const item of items) (key.get(item.id)! < 0 || (key.get(item.id) === 0 && !item.lane && above.length < below.length) ? above : below).push(item);
      items = [...above, { id: spineId, desired: 0, fixed: true, lane: dummies.has(spineId) }, ...below];
    }
    for (const [id, value] of packRank(items, COMPACT_ROW_GAP)) y.set(id, value);
  };
  // Ordering sweeps in both directions, then the final left-to-right row assignment.
  for (const leftToRight of [true, false, true, false, true]) for (const r of leftToRight ? order : [...order].reverse()) placeRank(r, leftToRight);
  const rankIndex = new Map(order.map((r, i) => [r, i]));
  const gap = rankGap(order.map(r => byRank.get(r)!.map(id => y.get(id)!)));
  const point = (id: string) => ({ x: rankIndex.get(rank.get(id)!)! * gap, y: Math.round(y.get(id)!) });
  const cards = new Map(order.map(r => [r, byRank.get(r)!.filter(id => !dummies.has(id)).map(id => y.get(id)!)]));
  return { positions: new Map(ids.map(id => [id, point(id)])), lanes: new Map([...chains].map(([id, chain]) => [id, keptSlots(chain).map(point)])) };

  /** A slot the packer pushed outside its link's two ends would draw a loop. Drop such slots
   * when the direct curve across their ranks clears every card there; otherwise keep the lane. */
  function keptSlots(chain: string[]) {
    const [a, b] = dummies.get(chain[0]!)!.ends;
    const ends = [y.get(a!)!, y.get(b!)!], lo = Math.min(...ends) - 1, hi = Math.max(...ends) + 1;
    const kept = chain.filter(slot => y.get(slot)! >= lo && y.get(slot)! <= hi);
    if (kept.length === chain.length) return chain;
    const [left, right] = rank.get(a!)! <= rank.get(b!)! ? [a!, b!] : [b!, a!];
    const route = [left, ...kept, right];
    const clear = chain.every(slot => {
      if (kept.includes(slot)) return true;
      const r = rank.get(slot)!;
      const after = route.findIndex(id => rank.get(id)! > r), p = route[after - 1]!, q = route[after]!;
      // Sample the curve across the card's width in this rank, not only at its centre.
      const span = rank.get(q)! - rank.get(p)!;
      return [-0.4, 0, 0.4].every(offset => {
        const t = Math.min(1, Math.max(0, (r + offset - rank.get(p)!) / span)), ease = t * t * (3 - 2 * t);
        const at = y.get(p)! + (y.get(q)! - y.get(p)!) * ease;
        // A card's glyph sits on its row; its caption hangs below it.
        return cards.get(r)!.every(cardY => at < cardY - CARD_ABOVE || at > cardY + CARD_BELOW);
      });
    });
    return clear ? kept : chain;
  }
}
