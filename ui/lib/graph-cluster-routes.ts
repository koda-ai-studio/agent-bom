/**
 * Orthogonal bundle routing and label placement for the grouped map.
 *
 * Cards sit in columns; every bundle leaves its left card's right side and
 * enters its right card's left side, so the map reads in one direction (a
 * bundle whose relationship points backwards keeps the same route and draws
 * its arrow at the start). Vertical runs only use the gaps between columns:
 * all bundles leaving one card share one lane in the gap after it, and every
 * long bundle entering one card shares one lane in the gap before it.
 * Bundles that skip columns cross over the top or bottom of the map, never
 * through a card. Labels go where they touch no card and no other label;
 * a label that fits nowhere is hidden and shown on hover or focus instead.
 */

export interface Point { x: number; y: number }
export interface Box { x: number; y: number; width: number; height: number }
export interface RouteCard extends Box { id: string; column: number }
export interface RouteBundle { id: string; source: string; target: string; label: string | null }
export interface RouteLabel extends Box { text: string; placed: boolean }
export interface BundleRoute { id: string; points: Point[]; reversed: boolean; label: RouteLabel | null }

const GUTTER = 48;
const LANE_MARGIN = 20;
const BUS_GAP = 26;
const BUS_STEP = 10;
const LABEL_H = 16;
const LABEL_PAD = 8;
/** Average glyph advance of the 11px label font; a slight over-estimate keeps placement conservative. */
const LABEL_CHAR_W = 6.4;

export const labelWidth = (text: string) => Math.ceil(text.length * LABEL_CHAR_W) + LABEL_PAD;

export function boxesIntersect(a: Box, b: Box, inflate = 0): boolean {
  return a.x - inflate < b.x + b.width && a.x + a.width + inflate > b.x && a.y - inflate < b.y + b.height && a.y + a.height + inflate > b.y;
}

const right = (card: Box): Point => ({ x: card.x + card.width, y: card.y + card.height / 2 });
const left = (card: Box): Point => ({ x: card.x, y: card.y + card.height / 2 });

interface Plan { bundle: RouteBundle; a: RouteCard; b: RouteCard; reversed: boolean; kind: "same-down" | "same-up" | "adjacent" | "long"; bus?: "top" | "bottom" }

function columnExtents(cards: RouteCard[]) {
  const columns = new Map<number, { left: number; right: number }>();
  for (const card of cards) {
    const current = columns.get(card.column);
    columns.set(card.column, current ? { left: Math.min(current.left, card.x), right: Math.max(current.right, card.x + card.width) } : { left: card.x, right: card.x + card.width });
  }
  return columns;
}

/** The free band after column `k` (k = -1 is the left gutter). */
function gapBand(columns: Map<number, { left: number; right: number }>, k: number) {
  const keys = [...columns.keys()].sort((p, q) => p - q);
  const first = columns.get(keys[0]!)!, last = columns.get(keys.at(-1)!)!;
  const after = keys.filter(key => key <= k).at(-1);
  const before = keys.find(key => key > k);
  return {
    left: after === undefined ? first.left - GUTTER : columns.get(after)!.right,
    right: before === undefined ? last.right + GUTTER : columns.get(before)!.left,
  };
}

function plan(bundles: RouteBundle[], byId: Map<string, RouteCard>, midY: number): Plan[] {
  const plans: Plan[] = [];
  for (const bundle of bundles) {
    const s = byId.get(bundle.source), t = byId.get(bundle.target);
    if (!s || !t || s.id === t.id) continue;
    const reversed = s.column > t.column;
    const [a, b] = reversed ? [t, s] : [s, t];
    if (a.column === b.column) plans.push({ bundle, a, b, reversed: false, kind: b.y >= a.y ? "same-down" : "same-up" });
    else if (b.column === a.column + 1) plans.push({ bundle, a, b, reversed, kind: "adjacent" });
    else plans.push({ bundle, a, b, reversed, kind: "long", bus: (a.y + b.y + a.height / 2 + b.height / 2) / 2 < midY ? "top" : "bottom" });
  }
  return plans;
}

/** One lane per key inside a gap, spread across it and ordered by the anchor card's height so lanes cross less. */
function assignLanes(requests: Array<{ gap: number; key: string; y: number }>, columns: Map<number, { left: number; right: number }>) {
  const byGap = new Map<number, Map<string, number>>();
  for (const { gap, key, y } of requests) {
    const keys = byGap.get(gap) ?? new Map<string, number>();
    keys.set(key, Math.min(keys.get(key) ?? Number.POSITIVE_INFINITY, y));
    byGap.set(gap, keys);
  }
  const lanes = new Map<string, number>();
  for (const [gap, keys] of byGap) {
    const band = gapBand(columns, gap);
    const ordered = [...keys.entries()].sort((p, q) => p[1] - q[1] || p[0].localeCompare(q[0]));
    const usable = Math.max(band.right - band.left - 2 * LANE_MARGIN, 4);
    ordered.forEach(([key], index) => lanes.set(`${gap}|${key}`, band.left + LANE_MARGIN + (usable * (index + 0.5)) / ordered.length));
  }
  return lanes;
}

function labelCandidates(points: Point[]): Point[] {
  const out: Point[] = [];
  for (let i = 0; i + 1 < points.length; i++) {
    const p = points[i]!, q = points[i + 1]!;
    const length = Math.abs(q.x - p.x) + Math.abs(q.y - p.y);
    if (length < 24) continue;
    for (const f of [0.5, 0.3, 0.7, 0.15, 0.85]) out.push({ x: p.x + (q.x - p.x) * f, y: p.y + (q.y - p.y) * f });
  }
  return out;
}

/** Routes for every bundle whose ends are drawn, with collision-free labels for as many as fit. */
export function routeBundles(cards: RouteCard[], bundles: RouteBundle[], obstacles: Box[] = cards): BundleRoute[] {
  if (!cards.length) return [];
  const byId = new Map(cards.map(card => [card.id, card]));
  const columns = columnExtents(cards);
  const top = Math.min(...cards.map(card => card.y)), bottom = Math.max(...cards.map(card => card.y + card.height));
  const plans = plan(bundles, byId, (top + bottom) / 2);

  const requests: Array<{ gap: number; key: string; y: number }> = [];
  const busKeys = { top: new Map<string, number>(), bottom: new Map<string, number>() };
  for (const p of plans) {
    if (p.kind === "same-down") requests.push({ gap: p.a.column, key: `sd:${p.a.id}`, y: p.a.y });
    else if (p.kind === "same-up") requests.push({ gap: p.a.column - 1, key: `su:${p.a.id}`, y: p.a.y });
    else if (p.kind === "adjacent") requests.push({ gap: p.a.column, key: `out:${p.a.id}`, y: p.a.y });
    else {
      requests.push({ gap: p.a.column, key: `out:${p.a.id}`, y: p.a.y }, { gap: p.b.column - 1, key: `in:${p.b.id}`, y: p.b.y });
      const bus = busKeys[p.bus!];
      if (!bus.has(p.a.id)) bus.set(p.a.id, bus.size);
    }
  }
  const lanes = assignLanes(requests, columns);
  const lane = (gap: number, key: string) => lanes.get(`${gap}|${key}`)!;

  const placed: Box[] = [];
  const order = [...plans].sort((p, q) => Number(Boolean(q.bundle.label)) - Number(Boolean(p.bundle.label)));
  const routes = new Map<string, BundleRoute>();
  for (const p of order) {
    let points: Point[];
    if (p.kind === "same-down") {
      const x = lane(p.a.column, `sd:${p.a.id}`);
      points = [right(p.a), { x, y: right(p.a).y }, { x, y: right(p.b).y }, right(p.b)];
    } else if (p.kind === "same-up") {
      const x = lane(p.a.column - 1, `su:${p.a.id}`);
      points = [left(p.a), { x, y: left(p.a).y }, { x, y: left(p.b).y }, left(p.b)];
    } else if (p.kind === "adjacent") {
      const x = lane(p.a.column, `out:${p.a.id}`);
      points = [right(p.a), { x, y: right(p.a).y }, { x, y: left(p.b).y }, left(p.b)];
    } else {
      const x1 = lane(p.a.column, `out:${p.a.id}`), x2 = lane(p.b.column - 1, `in:${p.b.id}`);
      const step = busKeys[p.bus!].get(p.a.id)! * BUS_STEP;
      const y = p.bus === "top" ? top - BUS_GAP - step : bottom + BUS_GAP + step;
      points = [right(p.a), { x: x1, y: right(p.a).y }, { x: x1, y }, { x: x2, y }, { x: x2, y: left(p.b).y }, left(p.b)];
    }
    let label: RouteLabel | null = null;
    if (p.bundle.label) {
      const width = labelWidth(p.bundle.label);
      const candidates = labelCandidates(points).map(c => ({ x: c.x - width / 2, y: c.y - LABEL_H / 2, width, height: LABEL_H }));
      const fit = candidates.find(box => !obstacles.some(card => boxesIntersect(box, card, 3)) && !placed.some(other => boxesIntersect(box, other, 2)));
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
    const minX = Math.min(p.x, q.x), maxX = Math.max(p.x, q.x), minY = Math.min(p.y, q.y), maxY = Math.max(p.y, q.y);
    if (maxX > x0 && minX < x1 && maxY > y0 && minY < y1) return true;
  }
  return false;
}
