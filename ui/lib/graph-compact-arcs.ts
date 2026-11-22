/** Every link on the compact canvas is one smooth cubic. When its plain curve
 * (horizontal tangents at both ends) would cross a card, its two control points
 * are raised or lowered so the single curve bends around the cards in its way. */

type Point = { x: number; y: number };
type Link = { id?: string; source: string; target: string };
/** The caption under a glyph, in layout units: each text line's half width and its span below the row,
 * plus the widest half and the deepest line for quick checks. */
export type CaptionLine = { half: number; top: number; bottom: number };
export type CaptionExtent = { half: number; top: number; depth: number; lines: CaptionLine[]; above: number };
/** The text a card draws under its glyph: its name (wrapping between words) and its one-line type. */
export type CaptionText = { name: string; typeLine: string; box?: number };
type Card = Point & CaptionExtent;

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
  return [left.y, right.y, (left.y + right.y) / 2, Math.min(left.y, right.y) - SPAN_ABOVE / 2, Math.max(left.y + left.depth, right.y + right.depth)];
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
const GLYPH_PX = 52 * 0.7, SMALL_GLYPH_PX = 66 * 0.7, SMALL_GRAPH = 12;
/** The canvas a laptop fits an investigation into beside the open navigation, less Fit all's padding: the smallest common frame, so a larger one only gains room. */
const FRAME = { width: 1120 * 0.85, height: 500 * 0.85 };

/** A wide desktop canvas fits the same graph at up to this much more zoom than a laptop's. */
const WIDER_SCREEN = 1.6;

/** The zoom Fit all will choose for these card positions, estimated from their extent and a caption under the lowest row. */
export function fitZoom(positions: ReadonlyMap<string, Point>, box: number): number {
  const points = [...positions.values()];
  if (!points.length) return 1;
  const xs = points.map(p => p.x), ys = points.map(p => p.y);
  const width = Math.max(...xs) - Math.min(...xs) + box, height = Math.max(...ys) - Math.min(...ys) + 200;
  return Math.min(1, Math.max(0.02, Math.min(FRAME.width / width, FRAME.height / height)));
}

/** How much room a caption's rendered text takes at a zoom, in layout units. Names wrap between
 * words inside the card box (a single long word is cut at the box); the type line is one line. */
export function captionExtent({ name, typeLine, box: own }: CaptionText, fallbackBox: number, zoom: number, small = false): CaptionExtent {
  const box = own ?? fallbackBox;
  const width = (text: string, px: number, char: number) => (text.length * px * char) / zoom;
  // Names wrap between words inside the card box, as the browser wraps them.
  const wrap = (char: number) => {
    const lines: string[] = [];
    for (const word of name.split(" ")) {
      const joined = lines.length ? `${lines.at(-1)} ${word}` : word;
      if (lines.length && width(joined, NAME_PX, char) <= box) lines[lines.length - 1] = joined; else lines.push(word);
    }
    return lines.slice(0, 2);
  };
  const shown = wrap(NAME_CHAR);
  const near = Math.min(1, zoom * WIDER_SCREEN), radius = (small ? SMALL_GLYPH_PX : GLYPH_PX) / 2;
  // Each line spans from where it starts at the closest zoom (a larger screen) to where it ends at the farthest.
  let offset = radius + 0.3 * NAME_PX;
  const lines: CaptionLine[] = [...shown.map(line => ({ text: line, px: NAME_PX, char: NAME_CHAR })), { text: typeLine, px: META_PX, char: META_CHAR }].map(({ text, px, char }) => {
    const line = { half: Math.min(box, width(text, px, char)) / 2 + 4 / zoom, top: offset / near, bottom: (offset + LINE * px) / zoom };
    offset += LINE * px;
    return line;
  });
  return { half: Math.max(...lines.map(line => line.half)), top: lines[0]!.top, depth: lines.at(-1)!.bottom, lines, above: (radius + 4) / zoom };
}

const DEFAULT_EXTENT: CaptionExtent = { half: CARD_HALF_WIDTH, top: GLYPH_BELOW, depth: CARD_BELOW, lines: [{ half: CARD_HALF_WIDTH, top: GLYPH_BELOW, bottom: CARD_BELOW }], above: CARD_ABOVE };

/** Caption extents for every card at the zoom these positions will fit at, or the generic card when no text is known. */
function extents(positions: ReadonlyMap<string, Point>, text: ((id: string) => CaptionText) | undefined, box: number, fixedZoom?: number) {
  if (!text) return { extent: () => DEFAULT_EXTENT, inset: 0 };
  const zoom = fixedZoom ?? fitZoom(positions, box), small = positions.size <= SMALL_GRAPH;
  const cache = new Map<string, CaptionExtent>();
  return { extent: (id: string) => cache.get(id) ?? cache.set(id, captionExtent(text(id), box, zoom, small)).get(id)!,
    inset: (small ? SMALL_GLYPH_PX : GLYPH_PX) / 2 / zoom };
}

function inCaption(p: Point, card: Card, scale = 1): boolean {
  const dx = Math.abs(p.x - card.x) / scale, dy = (p.y - card.y) / scale;
  return dx < card.half && dy >= card.top && dy < card.depth && card.lines.some(line => dx < line.half && dy >= line.top && dy < line.bottom);
}

/** Whether a sampled curve crosses another card, or the caption under one of its own two cards. */
function blocked(points: Point[], cards: Card[], scale = 1, ends: Card[] = []): boolean {
  return points.some(p => ends.some(end => inCaption(p, end, scale)) || cards.some(card => {
    const dx = Math.abs(p.x - card.x) / scale, dy = (p.y - card.y) / scale;
    // Another card is solid from its glyph's top to its last caption line, as wide as its widest line.
    return (dx < GLYPH_HALF_WIDTH && dy > -CARD_ABOVE && dy < GLYPH_BELOW) || (dx < card.half && dy > -card.above && dy < card.depth);
  }));
}

/** Control-point heights, relative to the source row, for each link whose plain curve would cross a card. */
export function linkArcs(links: readonly Link[], positions: ReadonlyMap<string, Point>, text?: (id: string) => CaptionText, box = CARD_HALF_WIDTH * 2, zoom?: number): { arcs: Map<string, [number, number]>; behind: Set<string> } {
  const arcs = new Map<string, [number, number]>(), behind = new Set<string>();
  const { extent, inset } = extents(positions, text, box, zoom);
  const all = [...positions.entries()].map(([id, p]) => [id, { ...p, ...extent(id) }] as const);
  if (all.length > MAX_CARDS) return { arcs, behind };
  for (const link of links) {
    const fromPoint = positions.get(link.source), toPoint = positions.get(link.target);
    if (!link.id || !fromPoint || !toPoint || fromPoint.x === toPoint.x) continue;
    const from: Card = { ...fromPoint, ...extent(link.source) }, to: Card = { ...toPoint, ...extent(link.target) };
    const [left, right] = from.x < to.x ? [from, to] : [to, from];
    const cards = all.filter(([id, p]) => id !== link.source && id !== link.target && p.x > left.x - p.half && p.x < right.x + p.half).map(([, p]) => p);
    const dense = all.length > DENSE_CARDS;
    if (!blocked(cubic(left, right, left.y, right.y, inset), cards, dense ? DENSE_MARGIN : 1, [left, right])) continue;
    if (dense) { behind.add(link.id); continue; }
    // Keep the bend within its own two cards' height, so it never reads as a loop around the graph.
    const low = Math.min(left.y, right.y) - SPAN_ABOVE, high = Math.max(left.y + left.depth, right.y + right.depth) + SPAN_BELOW / 4;
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
  const { extent, inset } = extents(positions, text, box, zoom);
  const all = [...positions.entries()].map(([id, p]) => [id, { ...p, ...extent(id) }] as const);
  let count = 0;
  for (const link of links) {
    const a = positions.get(link.source), b = positions.get(link.target);
    if (!a || !b || a.x === b.x) continue;
    const from: Card = { ...a, ...extent(link.source) }, to: Card = { ...b, ...extent(link.target) };
    const [left, right] = from.x < to.x ? [from, to] : [to, from];
    const cards = all.filter(([id, p]) => id !== link.source && id !== link.target && p.x > left.x - p.half && p.x < right.x + p.half).map(([, p]) => p);
    // A few typical bends stand in for the full search: level, rise early, rise late, or through the middle.
    const levels = canonicalLevels(left, right).filter(level => allowedLevel(level, left, right));
    const clear = levels.some(c1 => levels.some(c2 => {
      if (!levelAtCaptionEnd(c1, c2, left, right)) return false;
      const points = cubic(left, right, c1, c2, inset);
      return detour(points) <= MAX_DETOUR && !blocked(points, cards, 1, [left, right]);
    }));
    if (!clear) count++;
  }
  return count;
}
