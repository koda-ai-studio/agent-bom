/** Every link on the compact canvas is one smooth cubic. When its plain curve
 * (horizontal tangents at both ends) would cross a card, its two control points
 * are raised or lowered so the single curve bends around the cards in its way. */

import { COMPACT_GLYPH_SCALE } from "@/lib/graph-compact-glyph";
import { captionGeometry, type CaptionGeometry, NAME_LINES } from "@/lib/graph-caption-geometry";

type Point = { x: number; y: number };
type Link = { id?: string; source: string; target: string };
/** The caption under a glyph, in layout units around the glyph centre, with its obstacle test. */
export type CaptionExtent = CaptionGeometry;
/** The text a card draws under its glyph: its name (wrapping between words) and its one-line type. */
export type CaptionText = { name: string; typeLine: string; box?: number };
type Card = Point & { g: CaptionExtent };

/** Horizontal reach of each control point, as a share of the link's horizontal span. */
export const ARC_REACH = 0.45;
/** A card around its row: a narrow glyph on the row and a wider caption hanging below it. */
/** The glyph obstacle grows with the drawn glyph (sized for the original 0.7 scale), so routing clears what is painted. */
const GLYPH_GROWTH = COMPACT_GLYPH_SCALE / 0.7;
const CARD_ABOVE = Math.round(60 * GLYPH_GROWTH), GLYPH_BELOW = Math.round(28 * GLYPH_GROWTH), GLYPH_HALF_WIDTH = Math.round(50 * GLYPH_GROWTH),
  CARD_BELOW = 185, CARD_HALF_WIDTH = 112;
const MAX_DETOUR = 1.58;
/** How far a bent link may leave the rows of its own two cards: up to their glyph tops, down to their captions. */
const SPAN_ABOVE = 100, SPAN_BELOW = 200;
/** Search budget: at most this many control heights per link, and no bending past overview size. */
const MAX_LEVELS = 30, MAX_CARDS = 160;
/** Past this many cards a map fits at low zoom, where cards grow and may be re-spaced after layout:
 * links are not bent, and any that come near a card are drawn faint behind it. */
const DENSE_CARDS = 40, DENSE_MARGIN = 1.4;

function cubic(from: Point, to: Point, c1y: number, c2y: number, inset = 0): Point[] {
  // Side handles sit on the glyph's rim, not its centre.
  const p0 = { x: from.x + inset, y: from.y }, p3 = { x: to.x - inset, y: to.y };
  const dx = p3.x - p0.x;
  const c1 = { x: p0.x + ARC_REACH * dx, y: c1y }, c2 = { x: p3.x - ARC_REACH * dx, y: c2y };
  return Array.from({ length: 33 }, (_, i) => {
    const t = i / 32, u = 1 - t;
    return { x: u ** 3 * p0.x + 3 * u * u * t * c1.x + 3 * u * t * t * c2.x + t ** 3 * p3.x,
      y: u ** 3 * p0.y + 3 * u * u * t * c1.y + 3 * u * t * t * c2.y + t ** 3 * p3.y };
  });
}

/** Typical control heights: level at either end, through the middle, or bowed just above or below both cards. */
function canonicalLevels(left: Card, right: Card): number[] {
  return [left.y, right.y, (left.y + right.y) / 2, Math.min(left.y, right.y) - SPAN_ABOVE / 2, Math.max(left.y + left.g.depth, right.y + right.g.depth)];
}

/** A link that climbs or falls bends only between its two rows, so it never reads as an S;
 * a level link may bow just above or below the cards between its ends. */
function allowedLevel(level: number, left: Point, right: Point): boolean {
  if (Math.abs(right.y - left.y) < SLOPED) return true;
  return level >= Math.min(left.y, right.y) - OVERSHOOT && level <= Math.max(left.y, right.y) + OVERSHOOT;
}
const SLOPED = 80;

/** Captions hang under glyphs, so a link leaves a card it falls from, and enters a card it climbs to, level:
 * it never dives through its own end's caption. */
function levelAtCaptionEnd(c1: number, c2: number, left: Point, right: Point): boolean {
  if (right.y - left.y >= SLOPED && Math.abs(c1 - left.y) > 0.5) return false;
  if (left.y - right.y >= SLOPED && Math.abs(c2 - right.y) > 0.5) return false;
  return true;
}
/** A sloped link may overshoot its end row slightly, to come into a glyph more level and clear its caption. */
const OVERSHOOT = 60;

function detour(points: Point[]): number {
  const drawn = points.slice(1).reduce((sum, p, i) => sum + Math.hypot(p.x - points[i]!.x, p.y - points[i]!.y), 0);
  const chord = Math.hypot(points.at(-1)!.x - points[0]!.x, points.at(-1)!.y - points[0]!.y);
  return chord ? drawn / chord : 1;
}

/** On-screen type and glyph sizes (CSS px); the canvas divides them by zoom, so in layout units they grow as Fit all zooms out. */
const NAME_PX = 14 * 0.88, META_PX = 12, NAME_CHAR = 0.54, META_CHAR = 0.55, LINE = 1.15;
const GLYPH_PX = 52 * COMPACT_GLYPH_SCALE, SMALL_GLYPH_PX = 66 * COMPACT_GLYPH_SCALE, SMALL_GRAPH = 12;
/** The canvas a laptop fits an investigation into beside the open navigation, less Fit all's padding: the smallest common frame, so a larger one only gains room. */
const DEFAULT_FRAME = { width: 1120 * 0.85, height: 500 * 0.85 };
/** Share of a measured canvas the fitted graph is assumed to use, after Fit all's padding and the controls' reserve. */
const MEASURED_SHARE = 0.8;
let FRAME = { ...DEFAULT_FRAME };
/** Canvas sizes are bucketed so a resize only re-places the graph when the room really changed. */
const FRAME_BUCKET = 80;
let frameKey = "default";
let bucket: { w: number; h: number } | null = null;

/** Places later layouts for the canvas actually measured (less Fit all's padding). Returns the bucket key, which
 * callers add to their layout memo so a real resize re-places the graph. */
export function setLayoutFrame(width: number, height: number): string {
  if (!(width > 0 && height > 0)) { FRAME = { ...DEFAULT_FRAME }; frameKey = "default"; bucket = null; return frameKey; }
  // The canvas height follows the placed graph, so a size keeps its bucket until it moves a whole bucket away:
  // on a bucket edge, rounding alone would flip the bucket, re-place the graph and resize the canvas on every render.
  const snap = (value: number, current: number | undefined) => current !== undefined && Math.abs(value - current) < FRAME_BUCKET ? current : Math.round(value / FRAME_BUCKET) * FRAME_BUCKET;
  const w = snap(width, bucket?.w), h = snap(height, bucket?.h);
  bucket = { w, h };
  // The measured canvas only ever makes the caption model more cautious: a larger canvas keeps the laptop frame.
  FRAME = { width: Math.min(DEFAULT_FRAME.width, w * MEASURED_SHARE), height: Math.min(DEFAULT_FRAME.height, h * MEASURED_SHARE) };
  frameKey = `${w}x${h}`;
  return frameKey;
}

/** The bucket the next layout is placed for. */
export function layoutFrameKey(): string { return frameKey; }

/** A wide desktop canvas fits the same graph at up to this much more zoom than a laptop's. */
const WIDER_SCREEN = 1.6;

/** The zoom Fit all will choose for these card positions, estimated from their extent and a caption under the lowest row. */
export function fitZoom(positions: ReadonlyMap<string, Point>, box: number, frame: { width: number; height: number } = FRAME): number {
  const points = [...positions.values()];
  if (!points.length) return 1;
  const xs = points.map(p => p.x), ys = points.map(p => p.y);
  const width = Math.max(...xs) - Math.min(...xs) + box, height = Math.max(...ys) - Math.min(...ys) + 200;
  return Math.min(1, Math.max(0.02, Math.min(frame.width / width, frame.height / height)));
}

/** How much room a caption's rendered text takes at a zoom, in layout units, with the card's glyph:
 * names break as the card breaks them (see `captionGeometry`), the type line is one line. */
export function captionExtent({ name, typeLine, box: own }: CaptionText, fallbackBox: number, zoom: number, small = false): CaptionExtent {
  const near = Math.min(1, zoom * WIDER_SCREEN), radius = (small ? SMALL_GLYPH_PX : GLYPH_PX) / 2;
  // A wider screen draws the same graph closer (up to `near`), where the name may wrap differently.
  return captionGeometry({ name, typeLine, box: own ?? fallbackBox, nameChar: NAME_PX * NAME_CHAR, metaChar: META_PX * META_CHAR,
    nameLine: LINE * NAME_PX, metaLine: LINE * META_PX, maxLines: NAME_LINES, zoom, near, firstTop: radius + 0.3 * NAME_PX, above: (radius + 4) / zoom, pad: 4 / zoom, glyph: GLYPH_RECT });
}

/** The glyph's solid area on another card, in layout units around its centre. */
const GLYPH_RECT = { left: -GLYPH_HALF_WIDTH, right: GLYPH_HALF_WIDTH, top: -CARD_ABOVE, bottom: GLYPH_BELOW };
const DEFAULT_EXTENT: CaptionExtent = captionGeometry({ measured: [{ left: -CARD_HALF_WIDTH, right: CARD_HALF_WIDTH, top: GLYPH_BELOW, bottom: CARD_BELOW }], glyph: GLYPH_RECT, above: CARD_ABOVE });

/** Caption extents for every card at the zoom these positions will fit at, or the generic card when no text is known. */
/** Each link's blocked verdict for one set of extents, keyed by its ends and the cards in its span. */
const VERDICT_CACHE = new WeakMap<Map<string, CaptionExtent>, Map<string, boolean>>();
const EXTENT_CACHE = new WeakMap<(id: string) => CaptionText, Map<string, Map<string, CaptionExtent>>>();

function extents(positions: ReadonlyMap<string, Point>, text: ((id: string) => CaptionText) | undefined, box: number, fixedZoom?: number) {
  if (!text) return { extent: () => DEFAULT_EXTENT, inset: 0, verdicts: new Map<string, boolean>() };
  const zoom = fixedZoom ?? fitZoom(positions, box), small = positions.size <= SMALL_GRAPH;
  // Extents depend only on the text, box and zoom, so one layout's placement search reuses them across evaluations.
  const byText = EXTENT_CACHE.get(text) ?? EXTENT_CACHE.set(text, new Map()).get(text)!;
  const key = `${box}|${zoom}|${small}`;
  const cache = byText.get(key) ?? byText.set(key, new Map()).get(key)!;
  const verdicts = VERDICT_CACHE.get(cache) ?? VERDICT_CACHE.set(cache, new Map()).get(cache)!;
  return { extent: (id: string) => cache.get(id) ?? cache.set(id, captionExtent(text(id), box, zoom, small)).get(id)!,
    inset: (small ? SMALL_GLYPH_PX : GLYPH_PX) / 2 / zoom, verdicts };
}

/** Whether a sampled curve crosses another card (solid from its glyph's top to its last caption line),
 * or the caption text under one of its own two cards. */
function blocked(points: Point[], cards: Card[], scale = 1, ends: Card[] = []): boolean {
  return points.some(p => ends.some(end => end.g.hits((p.x - end.x) / scale, (p.y - end.y) / scale, "caption"))
    || cards.some(card => card.g.hits((p.x - card.x) / scale, (p.y - card.y) / scale, "card")));
}

/** The gentlest pair of control heights whose curve clears every card and both end captions, or null. */
function bestBend(left: Card, right: Card, cards: Card[], inset: number): { c1: number; c2: number } | null {
  // Keep the bend within its own two cards' height, so it never reads as a loop around the graph.
  const low = Math.min(left.y, right.y) - SPAN_ABOVE, high = Math.max(left.y + left.g.depth, right.y + right.g.depth) + SPAN_BELOW / 4;
  const levels: number[] = [], lowest = low - 3 * SPAN_ABOVE, highest = high + 2 * SPAN_BELOW;
  const step = Math.max(40, (highest - lowest) / (MAX_LEVELS - 1));
  for (let level = lowest; level <= highest; level += step) levels.push(level);
  levels.push(...canonicalLevels(left, right));
  let best: { c1: number; c2: number; cost: number } | null = null;
  for (const c1 of levels) for (const c2 of levels) {
    if (!allowedLevel(c1, left, right) || !allowedLevel(c2, left, right) || !levelAtCaptionEnd(c1, c2, left, right)) continue;
    // A bend against the link's own direction reads as an S; it costs more than a deeper bend the same way.
    const fall = Math.sign(right.y - left.y);
    const against = (value: number, from: number) => fall !== 0 && Math.sign(value - from) === -fall ? 3 : 1;
    const cost = Math.abs(c1 - left.y) * against(c1, left.y) + Math.abs(c2 - right.y) * against(c2, right.y);
    if (best && cost >= best.cost) continue;
    const points = cubic(left, right, c1, c2, inset);
    if (points.some(p => p.y < low || p.y > high) || detour(points) > MAX_DETOUR || blocked(points, cards, 1, [left, right])) continue;
    best = { c1, c2, cost };
  }
  return best;
}

/** Control-point heights, relative to the source row, for each link whose plain curve would cross a card. */
export function linkArcs(links: readonly Link[], positions: ReadonlyMap<string, Point>, text?: (id: string) => CaptionText, box = CARD_HALF_WIDTH * 2, zoom?: number): { arcs: Map<string, [number, number]>; behind: Set<string> } {
  const arcs = new Map<string, [number, number]>(), behind = new Set<string>();
  const { extent, inset } = extents(positions, text, box, zoom);
  const all = [...positions.entries()].map(([id, p]) => [id, { x: p.x, y: p.y, g: extent(id) }] as const);
  if (all.length > MAX_CARDS) return { arcs, behind };
  for (const link of links) {
    const fromPoint = positions.get(link.source), toPoint = positions.get(link.target);
    if (!link.id || !fromPoint || !toPoint || fromPoint.x === toPoint.x) continue;
    const from: Card = { x: fromPoint.x, y: fromPoint.y, g: extent(link.source) }, to: Card = { x: toPoint.x, y: toPoint.y, g: extent(link.target) };
    const [left, right] = from.x < to.x ? [from, to] : [to, from];
    const cards = all.filter(([id, p]) => id !== link.source && id !== link.target && p.x > left.x - p.g.half && p.x < right.x + p.g.half).map(([, p]) => p);
    const dense = all.length > DENSE_CARDS;
    if (!blocked(cubic(left, right, left.y, right.y, inset), cards, dense ? DENSE_MARGIN : 1, [left, right])) continue;
    if (dense) { behind.add(link.id); continue; }
    const best = bestBend(left, right, cards, inset);
    // No single curve clears every card: the link is drawn faint, passing behind them.
    if (!best) { behind.add(link.id); continue; }
    // Stored in drawing order: the source's control point first.
    const [first, second] = from.x < to.x ? [best.c1, best.c2] : [best.c2, best.c1];
    arcs.set(link.id, [first - from.y, second - from.y]);
  }
  return { arcs, behind };
}

/** How many links have no simple curve clear of every card and caption: the placement search keeps this at zero where it can. */
export function blockedLinkCount(links: readonly Link[], positions: ReadonlyMap<string, Point>, text: (id: string) => CaptionText, box: number, zoom?: number): number {
  const { extent, inset, verdicts } = extents(positions, text, box, zoom);
  const all = [...positions.entries()].map(([id, p]) => [id, { x: p.x, y: p.y, g: extent(id) }, `\u0000${id},${p.x},${p.y}`] as const);
  let count = 0;
  for (const link of links) {
    const a = positions.get(link.source), b = positions.get(link.target);
    if (!a || !b || a.x === b.x) continue;
    const from: Card = { x: a.x, y: a.y, g: extent(link.source) }, to: Card = { x: b.x, y: b.y, g: extent(link.target) };
    const [left, right] = from.x < to.x ? [from, to] : [to, from];
    const span = all.filter(([id, p]) => id !== link.source && id !== link.target && p.x > left.x - p.g.half && p.x < right.x + p.g.half);
    const cards = span.map(([, p]) => p);
    // A link's verdict depends only on its ends and the cards in its span: a search move re-judges only the links it touched.
    let key = `${link.source}\u0000${link.target}\u0000${a.x},${a.y},${b.x},${b.y}`;
    for (const entry of span) key += entry[2];
    const known = verdicts.get(key);
    if (known !== undefined) { if (known) count++; continue; }
    // A few typical bends stand in for the full search: level, rise early, rise late, or through the middle.
    // Most links are clear as plain curves; only a blocked one tries the typical bends.
    const plain = cubic(left, right, left.y, right.y, inset);
    if (detour(plain) <= MAX_DETOUR && !blocked(plain, cards, 1, [left, right])) { verdicts.set(key, false); continue; }
    const levels = canonicalLevels(left, right).filter(level => allowedLevel(level, left, right));
    const clear = levels.some(c1 => levels.some(c2 => {
      if (!levelAtCaptionEnd(c1, c2, left, right)) return false;
      const points = cubic(left, right, c1, c2, inset);
      return detour(points) <= MAX_DETOUR && !blocked(points, cards, 1, [left, right]);
    }));
    verdicts.set(key, !clear);
    if (!clear) count++;
  }
  return count;
}

/** Cards whose glyph a link's plain curve would run through (never its own two ends). */
export function glyphsOnCurve(link: Link, positions: ReadonlyMap<string, Point>): string[] {
  const a = positions.get(link.source), b = positions.get(link.target);
  if (!a || !b || a.x === b.x) return [];
  const [left, right] = a.x < b.x ? [a, b] : [b, a];
  const points = cubic(left, right, left.y, right.y, 0);
  return [...positions].filter(([id, p]) => id !== link.source && id !== link.target && p.x > left.x && p.x < right.x
    && points.some(q => Math.abs(q.x - p.x) < GLYPH_HALF_WIDTH && q.y - p.y > -CARD_ABOVE && q.y - p.y < GLYPH_BELOW)).map(([id]) => id);
}
