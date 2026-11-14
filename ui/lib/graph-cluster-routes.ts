/**
 * Orthogonal bundle routing and label placement for the grouped map.
 *
 * Cards sit in column slots, and slots may wrap into bands stacked top to
 * bottom. Every bundle leaves its left card's right side and enters its right
 * card's left side, so the map reads in one direction (a bundle whose
 * relationship points backwards keeps the route and draws its arrow at the
 * start). Vertical runs only use the gaps between slots, which line up across
 * bands: all bundles leaving one card share one lane in the gap after it, and
 * every corridor bundle entering a card shares one lane in the gap before it.
 * Bundles that skip slots or change band cross in the corridor between bands,
 * never through a card. Each label sits centred on a straight run of its own
 * route where it touches no card and no other label; a label that fits
 * nowhere is hidden and shown on hover instead.
 */

export interface Point { x: number; y: number }
export interface Box { x: number; y: number; width: number; height: number }
export interface RouteCard extends Box { id: string; column: number; band: number; slot: number }
export interface RouteBand { top: number; bottom: number }
export interface RouteBundle { id: string; source: string; target: string; label: string | null }
export interface RouteLabel extends Box { text: string; placed: boolean }
export interface BundleRoute { id: string; points: Point[]; reversed: boolean; label: RouteLabel | null }

const GUTTER = 44;
const LANE_MARGIN = 16;
const CORRIDOR = 56;
const LABEL_H = 18;
const LABEL_PAD = 8;
/** Clear space between two visible labels, so neighbouring bundles' labels never read as one block. */
export const LABEL_GAP = 10;
/** Clear space between a visible label and any card or frame. */
export const LABEL_CARD_GAP = 6;
/** Average glyph advance of the 12px label font; a slight over-estimate keeps placement conservative. */
const LABEL_CHAR_W = 7;

export const labelWidth = (text: string) => Math.ceil(text.length * LABEL_CHAR_W) + LABEL_PAD;

export function boxesIntersect(a: Box, b: Box, inflate = 0): boolean {
  return a.x - inflate < b.x + b.width && a.x + a.width + inflate > b.x && a.y - inflate < b.y + b.height && a.y + a.height + inflate > b.y;
}

const right = (card: Box): Point => ({ x: card.x + card.width, y: card.y + card.height / 2 });
const left = (card: Box): Point => ({ x: card.x, y: card.y + card.height / 2 });

type Kind = "same-down" | "adjacent" | "corridor";
interface Plan { bundle: RouteBundle; a: RouteCard; b: RouteCard; reversed: boolean; kind: Kind; corridor: number }

/** Free horizontal band of each slot gap: gap k lies after slot k (k = -1 is the left gutter). */
function slotGaps(cards: RouteCard[]) {
  const slots = new Map<number, { left: number; right: number }>();
  for (const card of cards) {
    const current = slots.get(card.slot);
    slots.set(card.slot, current ? { left: Math.min(current.left, card.x), right: Math.max(current.right, card.x + card.width) } : { left: card.x, right: card.x + card.width });
  }
  const keys = [...slots.keys()].sort((p, q) => p - q);
  return (k: number) => {
    const after = keys.filter(key => key <= k).at(-1), before = keys.find(key => key > k);
    return {
      left: after === undefined ? slots.get(keys[0]!)!.left - GUTTER : slots.get(after)!.right,
      right: before === undefined ? slots.get(keys.at(-1)!)!.right + GUTTER : slots.get(before)!.left,
    };
  };
}

/** Corridor c runs above band c (c = bands.length is below the last band). */
function corridorSpan(bands: RouteBand[], c: number) {
  if (c <= 0) return { top: bands[0]!.top - CORRIDOR, bottom: bands[0]!.top };
  if (c >= bands.length) return { top: bands.at(-1)!.bottom, bottom: bands.at(-1)!.bottom + CORRIDOR };
  return { top: bands[c - 1]!.bottom, bottom: bands[c]!.top };
}

function plan(bundles: RouteBundle[], byId: Map<string, RouteCard>, bands: RouteBand[]): Plan[] {
  const plans: Plan[] = [];
  for (const bundle of bundles) {
    const s = byId.get(bundle.source), t = byId.get(bundle.target);
    if (!s || !t || s.id === t.id) continue;
    const reversed = s.column > t.column;
    const [a, b] = reversed ? [t, s] : [s, t];
    // Stacked in one slot (one tier, or anything on a phone): the lane beside the stack.
    if (a.slot === b.slot && a.band === b.band) {
      const down = b.y >= a.y;
      plans.push({ bundle, a: down ? a : b, b: down ? b : a, reversed: down ? reversed : !reversed, kind: "same-down", corridor: 0 });
      continue;
    }
    if (a.band === b.band && b.slot === a.slot + 1) { plans.push({ bundle, a, b, reversed, kind: "adjacent", corridor: 0 }); continue; }
    // Into a later band: the corridor just above it. Within one band: the corridor between it and its neighbour.
    const corridor = b.band > a.band ? b.band : bands.length > 1 ? (a.band < bands.length - 1 ? a.band + 1 : a.band) : 0;
    plans.push({ bundle, a, b, reversed, kind: "corridor", corridor });
  }
  return plans;
}

/** Spread keys, in the given order, evenly across a span. */
function spread(ordered: string[], from: number, to: number) {
  const usable = Math.max(to - from - 2 * LANE_MARGIN, 4);
  return new Map(ordered.map((key, index) => [key, from + LANE_MARGIN + (usable * (index + 0.5)) / ordered.length]));
}

/** A vertical lane: where stubs join it from the left and where they leave it to the right. */
interface Lane { key: string; fromLeft: number[]; toRight: number[] }

const span = (lane: Lane) => { const ys = [...lane.fromLeft, ...lane.toRight]; return [Math.min(...ys), Math.max(...ys)] as const; };
const within = (y: number, [lo, hi]: readonly [number, number]) => y > lo + 0.5 && y < hi - 0.5;

/** Crossings when lane `l` sits left of lane `r`: r's left stubs pass l's run, l's right stubs pass r's run. */
function pairCost(l: Lane, r: Lane): number {
  const sl = span(l), sr = span(r);
  return r.fromLeft.filter(y => within(y, sl)).length + l.toRight.filter(y => within(y, sr)).length;
}

/** Lane order with the fewest crossings: start from height order, then swap neighbours while it helps. */
export function orderLanes(lanes: Lane[]): string[] {
  const order = [...lanes].sort((a, b) => span(a)[0] - span(b)[0] || a.key.localeCompare(b.key));
  for (let pass = 0, improved = true; improved && pass < order.length * order.length; pass++) {
    improved = false;
    for (let i = 0; i + 1 < order.length; i++) {
      if (pairCost(order[i + 1]!, order[i]!) < pairCost(order[i]!, order[i + 1]!)) { [order[i], order[i + 1]] = [order[i + 1]!, order[i]!]; improved = true; }
    }
  }
  return order.map(lane => lane.key);
}

function labelCandidates(points: Point[]): Point[] {
  const out: Point[] = [];
  for (let i = 0; i + 1 < points.length; i++) {
    const p = points[i]!, q = points[i + 1]!;
    if (Math.abs(q.x - p.x) + Math.abs(q.y - p.y) < 24) continue;
    for (const f of [0.5, 0.3, 0.7, 0.15, 0.85]) out.push({ x: p.x + (q.x - p.x) * f, y: p.y + (q.y - p.y) * f });
  }
  return out;
}

/** Routes for every bundle whose ends are drawn, with collision-free labels for as many as fit. */
export function routeBundles(cards: RouteCard[], bundles: RouteBundle[], obstacles: Box[] = cards, bandsIn?: RouteBand[]): BundleRoute[] {
  if (!cards.length) return [];
  const byId = new Map(cards.map(card => [card.id, card]));
  const bands = bandsIn?.length ? bandsIn : [{ top: Math.min(...cards.map(c => c.y)), bottom: Math.max(...cards.map(c => c.y + c.height)) }];
  const gap = slotGaps(cards);
  const plans = plan(bundles, byId, bands);

  // Corridor heights first (ordered left to right by where they start), then lanes ordered to cross least.
  // A corridor is a lane turned on its side: drops arrive from the band above and leave for the band below.
  const corridorKeys = new Map<number, Map<string, Lane>>();
  const mid = (k: number) => { const band = gap(k); return (band.left + band.right) / 2; };
  for (const p of plans) if (p.kind === "corridor") {
    const keys = corridorKeys.get(p.corridor) ?? new Map<string, Lane>();
    const lane = keys.get(p.a.id) ?? { key: p.a.id, fromLeft: [], toRight: [] };
    const above = (card: RouteCard) => card.y < corridorSpan(bands, p.corridor).top + 1;
    for (const [card, x] of [[p.a, mid(p.a.slot)], [p.b, mid(p.b.slot - 1)]] as const) (above(card) ? lane.fromLeft : lane.toRight).push(x);
    keys.set(p.a.id, lane);
    corridorKeys.set(p.corridor, keys);
  }
  const corridors = new Map<string, number>();
  for (const [c, keys] of corridorKeys) {
    const range = corridorSpan(bands, c);
    for (const [key, y] of spread(orderLanes([...keys.values()]), range.top, range.bottom)) corridors.set(`${c}|${key}`, y);
  }
  const laneSets = new Map<number, Map<string, Lane>>();
  const want = (k: number, key: string, fromLeft: number[], toRight: number[]) => {
    const keys = laneSets.get(k) ?? new Map<string, Lane>();
    const lane = keys.get(key) ?? { key, fromLeft: [], toRight: [] };
    lane.fromLeft.push(...fromLeft);
    lane.toRight.push(...toRight);
    keys.set(key, lane);
    laneSets.set(k, keys);
  };
  for (const p of plans) {
    const ay = right(p.a).y, by = left(p.b).y;
    if (p.kind === "same-down") want(p.a.slot, `sd:${p.a.id}`, [ay, by], []);
    else if (p.kind === "adjacent") want(p.a.slot, `out:${p.a.id}`, [ay], [by]);
    else {
      const cy = corridors.get(`${p.corridor}|${p.a.id}`)!;
      want(p.a.slot, `out:${p.a.id}`, [ay], [cy]);
      want(p.b.slot - 1, `in:${p.b.id}`, [cy], [by]);
    }
  }
  const lanes = new Map<string, number>();
  for (const [k, keys] of laneSets) { const band = gap(k); for (const [key, x] of spread(orderLanes([...keys.values()]), band.left, band.right)) lanes.set(`${k}|${key}`, x); }
  const lane = (k: number, key: string) => lanes.get(`${k}|${key}`)!;

  const placed: Box[] = [];
  const routes = new Map<string, BundleRoute>();
  for (const p of [...plans].sort((x, y) => Number(Boolean(y.bundle.label)) - Number(Boolean(x.bundle.label)))) {
    let points: Point[];
    if (p.kind === "same-down") {
      const x = lane(p.a.slot, `sd:${p.a.id}`);
      points = [right(p.a), { x, y: right(p.a).y }, { x, y: right(p.b).y }, right(p.b)];
    } else if (p.kind === "adjacent") {
      const x = lane(p.a.slot, `out:${p.a.id}`);
      points = [right(p.a), { x, y: right(p.a).y }, { x, y: left(p.b).y }, left(p.b)];
    } else {
      const x1 = lane(p.a.slot, `out:${p.a.id}`), x2 = lane(p.b.slot - 1, `in:${p.b.id}`);
      const y = corridors.get(`${p.corridor}|${p.a.id}`)!;
      points = [right(p.a), { x: x1, y: right(p.a).y }, { x: x1, y }, { x: x2, y }, { x: x2, y: left(p.b).y }, left(p.b)];
    }
    let label: RouteLabel | null = null;
    if (p.bundle.label) {
      const width = labelWidth(p.bundle.label);
      const candidates = labelCandidates(points).map(c => ({ x: c.x - width / 2, y: c.y - LABEL_H / 2, width, height: LABEL_H }));
      const fit = candidates.find(box => !obstacles.some(card => boxesIntersect(box, card, LABEL_CARD_GAP)) && !placed.some(other => boxesIntersect(box, other, LABEL_GAP / 2)));
      const box = fit ?? candidates[0] ?? { x: points[0]!.x, y: points[0]!.y - LABEL_H / 2, width, height: LABEL_H };
      if (fit) placed.push(fit);
      label = { ...box, text: p.bundle.label, placed: Boolean(fit) };
    }
    routes.set(p.bundle.id, { id: p.bundle.id, points, reversed: p.reversed, label });
  }
  return bundles.flatMap(bundle => routes.get(bundle.id) ?? []);
}

/** An orthogonal path through `points` with rounded corners. */
export function roundedPath(points: Point[], radius = 8): string {
  if (points.length < 2) return "";
  let d = `M ${points[0]!.x} ${points[0]!.y}`;
  for (let i = 1; i < points.length - 1; i++) {
    const prev = points[i - 1]!, at = points[i]!, next = points[i + 1]!;
    const r = Math.min(radius, Math.hypot(at.x - prev.x, at.y - prev.y) / 2, Math.hypot(next.x - at.x, next.y - at.y) / 2);
    const inDir = { x: Math.sign(at.x - prev.x), y: Math.sign(at.y - prev.y) };
    const outDir = { x: Math.sign(next.x - at.x), y: Math.sign(next.y - at.y) };
    d += ` L ${at.x - inDir.x * r} ${at.y - inDir.y * r} Q ${at.x} ${at.y} ${at.x + outDir.x * r} ${at.y + outDir.y * r}`;
  }
  const end = points.at(-1)!;
  return `${d} L ${end.x} ${end.y}`;
}

/** Whether any straight run of `points` passes through the interior of `box`. */
export function pathCrossesBox(points: Point[], box: Box, inset = 1): boolean {
  const x0 = box.x + inset, x1 = box.x + box.width - inset, y0 = box.y + inset, y1 = box.y + box.height - inset;
  for (let i = 0; i + 1 < points.length; i++) {
    const p = points[i]!, q = points[i + 1]!;
    if (Math.max(p.x, q.x) > x0 && Math.min(p.x, q.x) < x1 && Math.max(p.y, q.y) > y0 && Math.min(p.y, q.y) < y1) return true;
  }
  return false;
}

/** Distance from a label's centre to the nearest straight run of its route. */
export function labelDistance(label: Box, points: Point[]): number {
  const cx = label.x + label.width / 2, cy = label.y + label.height / 2;
  let best = Number.POSITIVE_INFINITY;
  for (let i = 0; i + 1 < points.length; i++) {
    const p = points[i]!, q = points[i + 1]!;
    const x = Math.max(Math.min(p.x, q.x), Math.min(cx, Math.max(p.x, q.x))), y = Math.max(Math.min(p.y, q.y), Math.min(cy, Math.max(p.y, q.y)));
    best = Math.min(best, Math.hypot(cx - x, cy - y));
  }
  return best;
}
