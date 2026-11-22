/** Lines a name may take before it is clamped: under its glyph on a desktop card, beside it on a phone. The card's
 * clamp, the layout's room under each card and the curve model's caption all read these. */
export const NAME_LINES = 4;
export const PHONE_NAME_LINES = 3;

/** A rectangle relative to a card's glyph centre (or, for the browser gate, in screen pixels). */
export type CaptionRect = { left: number; right: number; top: number; bottom: number };

export type CaptionGeometryInput = {
  /** Modelled text: the name wraps inside `box`; the type line is one line. */
  name?: string;
  typeLine?: string;
  box?: number;
  /** On-screen px one name or type character takes, and one line's height; divided by `zoom` into layout units. */
  nameChar?: number;
  metaChar?: number;
  nameLine?: number;
  metaLine?: number;
  /** The zoom the text is judged at (its wrap and clamp), and the closest zoom it may be drawn at: the obstacle covers both and between. */
  zoom?: number;
  near?: number;
  /** Lines the name may take before it is clamped. */
  maxLines?: number;
  /** Where the first name line starts below the glyph centre (px), and how far the card reaches above it (layout units). */
  firstTop?: number;
  above?: number;
  /** Extra clear space beside each modelled line. */
  pad?: number;
  /** Measured geometry instead of modelled text (the browser gate). */
  measured?: CaptionRect[];
  glyph?: CaptionRect;
  /** Points this close to a rect's edge do not count as inside it. */
  inset?: number;
};

export type NamePiece = { text: string; breakAfter: boolean; protect: boolean };

export type CaptionGeometry = {
  /** Each word of the name as break pieces: a piece may end a line only when `breakAfter`. */
  words: NamePiece[][];
  /** The name's lines as drawn, and whether more text was cut by the clamp or the box. */
  nameLines: string[];
  clamped: boolean;
  lines: CaptionRect[];
  glyph: CaptionRect | undefined;
  half: number;
  top: number;
  depth: number;
  above: number;
  /** Whether a point falls on the caption text, the glyph, or anywhere on the card (glyph top to last line). */
  hits(x: number, y: number, part: "caption" | "glyph" | "card"): boolean;
};

/** Name breaks, caption size and the obstacle test in one function. It is self-contained (no imports and no
 * outer references) because the browser gate injects its source with `toString()`; layout spacing, curve routing
 * and the gate all read captions through it.
 *
 * Names wrap between words, and inside an ordinary word only after a hyphen or underscore. A CVE/GHSA/CWE id,
 * a hex digest, or an `@version` tail is one piece that never breaks. */
export function captionGeometry(input: CaptionGeometryInput): CaptionGeometry {
  const inset = input.inset ?? 0;
  const finish = (words: NamePiece[][], nameLines: string[], clamped: boolean, lines: CaptionRect[], glyph: CaptionRect | undefined, above: number): CaptionGeometry => {
    const half = lines.length ? Math.max(...lines.map(line => Math.max(-line.left, line.right))) : 0;
    const top = lines.length ? Math.min(...lines.map(line => line.top)) : 0;
    const depth = lines.length ? Math.max(...lines.map(line => line.bottom)) : 0;
    // Plain numbers, so the test stays cheap inside the curve search's inner loop.
    const gl = glyph ? glyph.left + inset : NaN, gr = glyph ? glyph.right - inset : NaN, gt = glyph ? glyph.top + inset : NaN, gb = glyph ? glyph.bottom - inset : NaN;
    const cl = -half + inset, cr = half - inset, ct = -above + inset, cb = depth - inset;
    const count = lines.length, edges = new Float64Array(count * 4);
    lines.forEach((line, i) => { edges[i * 4] = line.left + inset; edges[i * 4 + 1] = line.right - inset; edges[i * 4 + 2] = line.top + inset; edges[i * 4 + 3] = line.bottom - inset; });
    return {
      words, nameLines, clamped, lines, glyph, half, top, depth, above,
      hits(x, y, part) {
        const onGlyph = x > gl && x < gr && y >= gt && y < gb;
        if (part === "glyph") return onGlyph;
        if (part === "card") return onGlyph || (x > cl && x < cr && y >= ct && y < cb);
        if (y < top || y >= depth) return false;
        for (let i = 0; i < count * 4; i += 4) if (x > edges[i]! && x < edges[i + 1]! && y >= edges[i + 2]! && y < edges[i + 3]!) return true;
        return false;
      },
    };
  };
  if (input.measured) return finish([], [], false, input.measured, input.glyph, input.above ?? 0);

  const name = input.name ?? "", box = input.box ?? Infinity, maxLines = input.maxLines ?? 2;
  const zoom = input.zoom ?? 1, near = Math.max(zoom, input.near ?? zoom);
  // Break rules: each word splits into pieces; a piece may end a line only after its hyphen or underscore, or its path slash when it has neither.
  const pieces = (word: string): NamePiece[] => {
    if (/^(CVE|GHSA|CWE)-|^[0-9a-f]{8,}$/i.test(word)) return [{ text: word, breakAfter: false, protect: true }];
    const at = word.indexOf("@", 1);
    const base = at > 0 ? word.slice(0, at) : word, version = at > 0 ? word.slice(at) : "";
    // A path slash is a break only in a name with no hyphen or underscore to break at (deploy/values.yaml).
    const parts = (/[-_]/.test(base) ? base.match(/[^-_]+[-_]*|[-_]+/g) : base.match(/[^/]+\/*|\/+/g)) ?? [base];
    const out = parts.map((text, index) => ({ text, breakAfter: /[-_/]$/.test(text) && index < parts.length - 1, protect: false }));
    if (version) out.push({ text: version, breakAfter: false, protect: true });
    return out;
  };
  // Units that never break inside: a word's pieces up to each break, joined with a space only at a word start.
  const units: { text: string; space: boolean }[] = [];
  const words = name.split(" ").filter(Boolean).map(pieces);
  words.forEach((word, w) => {
    let text = "", space = w > 0;
    for (const piece of word) {
      text += piece.text;
      if (piece.breakAfter) { units.push({ text, space }); text = ""; space = false; }
    }
    if (text) units.push({ text, space });
  });
  const wrap = (char: number) => {
    const all: string[] = [];
    let cut = false;
    for (const unit of units) {
      const last = all.at(-1);
      const joined = last === undefined ? unit.text : `${last}${unit.space ? " " : ""}${unit.text}`;
      if (last !== undefined && joined.length * char <= box) all[all.length - 1] = joined;
      else { all.push(unit.text); if (unit.text.length * char > box) cut = true; }
    }
    return { all, cut };
  };
  const nameChar = input.nameChar ?? 1, metaChar = input.metaChar ?? nameChar;
  const pad = input.pad ?? 0, nameLine = input.nameLine ?? 0, metaLine = input.metaLine ?? nameLine;
  // The name is judged at `zoom`; it may be drawn at any zoom up to `near`, where it can wrap differently (a wider
  // first line, or one line instead of two). The obstacle is every line at every zoom in that range.
  const linesAt = (z: number) => {
    const { all, cut } = wrap(nameChar / z);
    const shown = all.slice(0, maxLines), out: CaptionRect[] = [];
    let offset = input.firstTop ?? 0;
    for (const [text, char, height] of [...shown.map(line => [line, nameChar, nameLine] as const), [input.typeLine ?? "", metaChar, metaLine] as const]) {
      const half = Math.min(box, (text.length * char) / z) / 2 + pad;
      out.push({ left: -half, right: half, top: offset / z, bottom: (offset + height) / z });
      offset += height;
    }
    return { shown, clamped: cut || all.length > maxLines, out };
  };
  const judged = linesAt(zoom);
  const nameLines = judged.shown, clamped = judged.clamped;
  const steps = near > zoom ? 4 : 0;
  const lines = [...judged.out, ...Array.from({ length: steps }, (_, k) => linesAt(zoom * (near / zoom) ** ((k + 1) / steps)).out).flat()];
  return finish(words, nameLines, clamped, lines, input.glyph, input.above ?? 0);
}
