/** Every link on the compact canvas is one smooth cubic. When its plain curve
 * (horizontal tangents at both ends) would cross a card, its two control points
 * are raised or lowered so the single curve bends around the cards in its way. */

type Point = { x: number; y: number };
type Link = { id?: string; source: string; target: string };

/** Horizontal reach of each control point, as a share of the link's horizontal span. */
export const ARC_REACH = 0.45;
/** A card around its row: a narrow glyph on the row and a wider caption hanging below it. */
const CARD_ABOVE = 60, GLYPH_BELOW = 28, GLYPH_HALF_WIDTH = 50, CARD_BELOW = 185, CARD_HALF_WIDTH = 112;
const MAX_DETOUR = 1.58;
/** How far a bent link may leave the rows of its own two cards: up to their glyph tops, down to their captions. */
const SPAN_ABOVE = 100, SPAN_BELOW = 200;
/** Search budget: at most this many control heights per link, and no bending past overview size. */
const MAX_LEVELS = 30, MAX_CARDS = 160;
/** Past this many cards a map fits at low zoom, where cards grow and may be re-spaced after layout:
 * links are not bent, and any that come near a card are drawn faint behind it. */
const DENSE_CARDS = 40, DENSE_MARGIN = 1.4;

function cubic(p0: Point, p3: Point, c1y: number, c2y: number): Point[] {
  const dx = p3.x - p0.x;
  const c1 = { x: p0.x + ARC_REACH * dx, y: c1y }, c2 = { x: p3.x - ARC_REACH * dx, y: c2y };
  return Array.from({ length: 33 }, (_, i) => {
    const t = i / 32, u = 1 - t;
    return { x: u ** 3 * p0.x + 3 * u * u * t * c1.x + 3 * u * t * t * c2.x + t ** 3 * p3.x,
      y: u ** 3 * p0.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y + t ** 3 * p3.y };
  });
}

function detour(points: Point[]): number {
  const drawn = points.slice(1).reduce((sum, p, i) => sum + Math.hypot(p.x - points[i]!.x, p.y - points[i]!.y), 0);
  const chord = Math.hypot(points.at(-1)!.x - points[0]!.x, points.at(-1)!.y - points[0]!.y);
  return chord ? drawn / chord : 1;
}

function inCaption(p: Point, card: Point, scale = 1): boolean {
  const dx = Math.abs(p.x - card.x) / scale, dy = (p.y - card.y) / scale;
  return dx < CARD_HALF_WIDTH && dy >= GLYPH_BELOW && dy < CARD_BELOW;
}

/** Whether a sampled curve crosses another card, or the caption under one of its own two cards. */
function blocked(points: Point[], cards: Point[], scale = 1, ends: Point[] = []): boolean {
  return points.some(p => ends.some(end => inCaption(p, end, scale)) || cards.some(card => {
    const dx = Math.abs(p.x - card.x) / scale, dy = (p.y - card.y) / scale;
    return (dx < GLYPH_HALF_WIDTH && dy > -CARD_ABOVE && dy < GLYPH_BELOW) || inCaption(p, card, scale);
  }));
}

/** Control-point heights, relative to the source row, for each link whose plain curve would cross a card. */
export function linkArcs(links: readonly Link[], positions: ReadonlyMap<string, Point>): { arcs: Map<string, [number, number]>; behind: Set<string> } {
  const arcs = new Map<string, [number, number]>(), behind = new Set<string>();
  const all = [...positions.entries()];
  if (all.length > MAX_CARDS) return { arcs, behind };
  for (const link of links) {
    const from = positions.get(link.source), to = positions.get(link.target);
    if (!link.id || !from || !to || from.x === to.x) continue;
    const [left, right] = from.x < to.x ? [from, to] : [to, from];
    const cards = all.filter(([id, p]) => id !== link.source && id !== link.target && p.x > left.x - CARD_HALF_WIDTH && p.x < right.x + CARD_HALF_WIDTH).map(([, p]) => p);
    const dense = all.length > DENSE_CARDS;
    if (!blocked(cubic(left, right, left.y, right.y), cards, dense ? DENSE_MARGIN : 1, [left, right])) continue;
    if (dense) { behind.add(link.id); continue; }
    // Keep the bend within its own two cards' height, so it never reads as a loop around the graph.
    const low = Math.min(left.y, right.y) - SPAN_ABOVE, high = Math.max(left.y, right.y) + SPAN_BELOW;
    const levels: number[] = [], lowest = low - 3 * SPAN_ABOVE, highest = high + 2 * SPAN_BELOW;
    const step = Math.max(40, (highest - lowest) / (MAX_LEVELS - 1));
    for (let level = lowest; level <= highest; level += step) levels.push(level);
    let best: { c1: number; c2: number; cost: number } | null = null;
    for (const c1 of levels) for (const c2 of levels) {
      const cost = Math.abs(c1 - left.y) + Math.abs(c2 - right.y);
      if (best && cost >= best.cost) continue;
      const points = cubic(left, right, c1, c2);
      if (points.some(p => p.y < low || p.y > high) || detour(points) > MAX_DETOUR || blocked(points, cards, 1, [left, right])) continue;
      best = { c1, c2, cost };
    }
    // No single curve clears every card: the link is drawn faint, passing behind them.
    if (!best) { behind.add(link.id); continue; }
    // Stored in drawing order: the source's control point first.
    const [first, second] = from.x < to.x ? [best.c1, best.c2] : [best.c2, best.c1];
    arcs.set(link.id, [first - from.y, second - from.y]);
  }
  return { arcs, behind };
}
