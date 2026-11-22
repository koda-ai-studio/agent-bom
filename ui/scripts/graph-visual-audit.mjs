/** Runs inside Playwright's page context against actual rendered SVG curves. */
export function auditRenderedGraph({ edges }) {
  const byId = new Map(edges.map(edge => [edge.id, edge]));
  const curves = [...document.querySelectorAll(".react-flow__edge")].map(element => {
    const edge = byId.get(element.getAttribute("data-id"));
    const path = element.querySelector(".react-flow__edge-path");
    const matrix = path?.getScreenCTM();
    if (!edge || !matrix) return null;
    const length = path.getTotalLength();
    const points = Array.from({ length: 65 }, (_, i) => {
      const point = path.getPointAtLength(length * i / 64);
      return { x: matrix.a * point.x + matrix.c * point.y + matrix.e, y: matrix.b * point.x + matrix.d * point.y + matrix.f };
    });
    return { edge, points };
  }).filter(Boolean);
  const side = (a, b, c) => (b.x - a.x) * (c.y - a.y) - (b.y - a.y) * (c.x - a.x);
  const crossings = [];
  for (let i = 0; i < curves.length; i++) {
    for (let j = i + 1; j < curves.length; j++) {
      const a = curves[i], b = curves[j];
      if ([a.edge.source, a.edge.target].some(id => id === b.edge.source || id === b.edge.target)) continue;
      let crossed = false;
      for (let m = 1; m < a.points.length && !crossed; m++) {
        for (let n = 1; n < b.points.length; n++) {
          const p = a.points[m - 1], q = a.points[m], r = b.points[n - 1], s = b.points[n];
          if (side(p, q, r) * side(p, q, s) < -0.01 && side(r, s, p) * side(r, s, q) < -0.01) {
            crossed = true;
            break;
          }
        }
      }
      if (crossed) crossings.push([a.edge.id, b.edge.id]);
    }
  }
  const logos = [...document.querySelectorAll(".react-flow__node [data-graph-source-badge] img")].map(img => {
    // OpenAI's source asset has intrinsic whitespace and is scaled inside an
    // overflow-hidden badge. Audit its painted clip, not the offscreen box.
    const raw = img.getBoundingClientRect();
    const clip = img.parentElement.getBoundingClientRect();
    const badge = { left: Math.max(raw.left, clip.left), right: Math.min(raw.right, clip.right), top: Math.max(raw.top, clip.top), bottom: Math.min(raw.bottom, clip.bottom) };
    badge.width = badge.right - badge.left;
    badge.height = badge.bottom - badge.top;
    const glyph = img.closest(".graph-entity-glyph")?.querySelector(":scope > svg")?.getBoundingClientRect();
    const caption = img.closest("[data-graph-entity]")?.querySelector(":scope > p");
    const captionRects = [...(caption?.querySelectorAll("span") ?? [])].map(span => span.getBoundingClientRect());
    return {
      overlapsCaption: captionRects.some(rect => clip.left < rect.right && clip.right > rect.left && clip.top < rect.bottom && clip.bottom > rect.top),
      source: img.parentElement.getAttribute("data-agent-source"),
      loaded: img.complete && img.naturalWidth > 0,
      size: Math.min(badge.width, badge.height),
      overlapsGlyph: Boolean(glyph && badge.left < glyph.right && badge.right > glyph.left && badge.top < glyph.bottom && badge.bottom > glyph.top),
    };
  });
  const glyphs = new Map([...document.querySelectorAll(".react-flow__node")].map(node => [node.getAttribute("data-id"), node.querySelector(".graph-entity-glyph")?.getBoundingClientRect()]));
  const misalignedHandles = curves.flatMap(({ edge, points }) => [[edge.source, points[0]], [edge.target, points.at(-1)]].flatMap(([id, point]) => {
    const glyph = glyphs.get(id);
    return glyph && Math.abs(point.y - (glyph.top + glyph.height / 2)) > 2 ? [{ edge: edge.id, node: id, offset: point.y - (glyph.top + glyph.height / 2) }] : [];
  }));
  return { renderedEdges: curves.length, crossings, logos, misalignedHandles };
}

function straightRuns(points) {
  const runs = [];
  for (let index = 1; index < points.length; index++) {
    const a = points[index - 1], b = points[index];
    const axis = Math.abs(a.y - b.y) <= 0.5 && Math.abs(a.x - b.x) > 0.5 ? "h" : Math.abs(a.x - b.x) <= 0.5 && Math.abs(a.y - b.y) > 0.5 ? "v" : null;
    if (!axis) continue;
    const at = axis === "h" ? (a.y + b.y) / 2 : (a.x + b.x) / 2;
    const [from, to] = axis === "h" ? [Math.min(a.x, b.x), Math.max(a.x, b.x)] : [Math.min(a.y, b.y), Math.max(a.y, b.y)];
    const last = runs.at(-1);
    if (last && last.axis === axis && Math.abs(last.at - at) <= 0.5 && Math.abs(last.to - from) <= 0.5) last.to = Math.max(last.to, to);
    else runs.push({ axis, at, from, to });
  }
  return runs;
}

/**
 * Pairs of lines of different relationship types drawn along one straight run
 * (within `tolerance` screen pixels, over at least `minRun`), where their dashes
 * would interleave into one ambiguous line. One type may bundle on a shared trunk.
 */
export function sharedRelationshipRuns(curves, { tolerance = 3, minRun = 8 } = {}) {
  const runs = curves.map(curve => straightRuns(curve.points));
  const shared = [];
  for (let i = 0; i < curves.length; i++) {
    for (let j = i + 1; j < curves.length; j++) {
      if (curves[i].relationship === curves[j].relationship) continue;
      let length = 0;
      for (const left of runs[i]) for (const right of runs[j]) {
        if (left.axis !== right.axis || Math.abs(left.at - right.at) > tolerance) continue;
        length += Math.max(0, Math.min(left.to, right.to) - Math.max(left.from, right.from));
      }
      if (length >= minRun) shared.push({ edges: [curves[i].id, curves[j].id], length: Math.round(length) });
    }
  }
  return shared;
}

/** Runs inside Playwright's page context: every drawn relationship line, in screen pixels, with its type. */
export function renderedRelationshipCurves() {
  return [...document.querySelectorAll(".react-flow__edge")].flatMap(element => {
    const path = element.querySelector(".react-flow__edge-path");
    const matrix = path?.getScreenCTM();
    const relationship = element.querySelector("[data-relationship]")?.getAttribute("data-relationship");
    if (!path || !matrix || !relationship) return [];
    const length = path.getTotalLength();
    const steps = Math.max(2, Math.ceil(length / 2));
    const points = Array.from({ length: steps + 1 }, (_, i) => {
      const point = path.getPointAtLength(length * i / steps);
      return { x: matrix.a * point.x + matrix.c * point.y + matrix.e, y: matrix.b * point.x + matrix.d * point.y + matrix.f };
    });
    return [{ id: element.getAttribute("data-id"), relationship, points }];
  });
}

/**
 * Runs inside Playwright's page context: the agreed graph grammar, measured on the first frame.
 * Returns only violations; an empty object means the frame passes.
 */
export function auditGraphGrammar({ margin = 48, minGlyph = 32, minFill = 0.6, maxDetour = 1.6, maxLength = 2.5 } = {}) {
  const canvas = document.querySelector(".react-flow")?.getBoundingClientRect();
  if (!canvas) return {};
  const nodes = [...document.querySelectorAll(".react-flow__node")].filter(node => getComputedStyle(node).visibility !== "hidden")
    .map(node => ({ id: node.getAttribute("data-id"), box: node.getBoundingClientRect(), glyph: node.querySelector(".graph-entity-glyph")?.getBoundingClientRect() }));
  const inside = (box, p, pad = 0) => p.x >= box.left - pad && p.x <= box.right + pad && p.y >= box.top - pad && p.y <= box.bottom + pad;
  const overlaps = (a, b) => a.left < b.right && a.right > b.left && a.top < b.bottom && a.bottom > b.top;
  const nearest = p => nodes.reduce((best, node) => {
    const dx = Math.max(node.box.left - p.x, 0, p.x - node.box.right), dy = Math.max(node.box.top - p.y, 0, p.y - node.box.bottom);
    const d = Math.hypot(dx, dy);
    return d < best.d ? { node, d } : best;
  }, { node: null, d: Infinity }).node;
  const violations = {};
  const add = (key, item) => (violations[key] ??= []).push(item);
  // Rendered caption text (names and type lines), measured line by line: a line must never cross label text.
  const captions = [...document.querySelectorAll(".react-flow__node")].filter(node => getComputedStyle(node).visibility !== "hidden").flatMap(node =>
    [...node.querySelectorAll("[data-semantic-name], [data-entity-role]")].flatMap(element => {
      // Each text run, cut to what its overflow-clipping ancestors (an ellipsis box) actually paint.
      const walker = document.createTreeWalker(element, NodeFilter.SHOW_TEXT);
      const out = [];
      for (let text = walker.nextNode(); text; text = walker.nextNode()) {
        if (text.parentElement?.closest(".sr-only")) continue;
        const range = document.createRange();
        range.selectNodeContents(text);
        const clips = [];
        for (let el = text.parentElement; el && el !== node; el = el.parentElement) if (getComputedStyle(el).overflow !== "visible") clips.push(el.getBoundingClientRect());
        for (const raw of range.getClientRects()) {
          const rect = clips.reduce((r, c) => ({ left: Math.max(r.left, c.left), right: Math.min(r.right, c.right), top: Math.max(r.top, c.top), bottom: Math.min(r.bottom, c.bottom) }),
            { left: raw.left, right: raw.right, top: raw.top, bottom: raw.bottom });
          if (rect.right - rect.left > 1 && rect.bottom - rect.top > 1) out.push({ id: node.getAttribute("data-id"), rect });
        }
      }
      return out;
    }));
  // A caption the frame shows only part of reads as a different name ("e Runbook Agent"): text is either whole in frame or wholly outside it.
  const clipped = [...new Set(captions.filter(({ rect }) => rect.right > canvas.left && rect.left < canvas.right && rect.bottom > canvas.top && rect.top < canvas.bottom
    && (rect.left < canvas.left - 0.5 || rect.right > canvas.right + 0.5 || rect.top < canvas.top - 0.5 || rect.bottom > canvas.bottom + 0.5)).map(caption => caption.id))];
  // The zoom controls sit over the canvas: a caption under them is as hidden as one off the edge.
  const controls = [...document.querySelectorAll(".react-flow__controls")].map(element => element.getBoundingClientRect()).filter(rect => rect.width && rect.height);
  const covered = captions.filter(({ rect }) => controls.some(c => rect.left < c.right && rect.right > c.left && rect.top < c.bottom && rect.bottom > c.top)).map(caption => caption.id);
  const hidden = [...new Set([...clipped, ...covered])];
  if (hidden.length) add("clippedCaptions", hidden);
  // A finding id is the key fact on its card: it is never cut short with an ellipsis.
  const truncatedIds = [...document.querySelectorAll(".react-flow__node")].filter(node => getComputedStyle(node).visibility !== "hidden").flatMap(node =>
    [...node.querySelectorAll("[data-semantic-name]")].filter(name => /\b(CVE|GHSA)-/i.test(name.textContent ?? "")
      && (name.scrollHeight > name.clientHeight + 1 || [name, ...name.querySelectorAll("*")].some(el => el.scrollWidth > el.clientWidth + 1 && /\b(CVE|GHSA)-/i.test(el.textContent ?? ""))))
      .map(() => node.getAttribute("data-id")));
  if (truncatedIds.length) add("truncatedIds", truncatedIds);
  const diagnosticChips = [...document.querySelectorAll(".react-flow__node *")].filter(el => el.children.length === 0 && /semantic layer unavailable/i.test(el.textContent ?? ""));
  if (diagnosticChips.length) add("diagnosticChips", diagnosticChips.length);
  for (const element of document.querySelectorAll(".react-flow__edge")) {
    const path = element.querySelector(".react-flow__edge-path");
    const matrix = path?.getScreenCTM();
    if (!path || !matrix) continue;
    const length = path.getTotalLength();
    const points = Array.from({ length: 49 }, (_, i) => {
      const q = path.getPointAtLength(length * i / 48);
      return { x: matrix.a * q.x + matrix.c * q.y + matrix.e, y: matrix.b * q.x + matrix.d * q.y + matrix.f };
    });
    const id = element.getAttribute("data-id");
    const source = nearest(points[0]), target = nearest(points.at(-1));
    if (!source || !target) continue;
    const span = { left: Math.min(source.box.left, target.box.left), right: Math.max(source.box.right, target.box.right),
      top: Math.min(source.box.top, target.box.top), bottom: Math.max(source.box.bottom, target.box.bottom) };
    if (points.some(p => !inside(span, p, margin))) add("loops", id);
    const through = nodes.filter(node => node !== source && node !== target && node.glyph
      && points.some(p => inside({ left: node.glyph.left + 4, right: node.glyph.right - 4, top: node.glyph.top + 4, bottom: node.glyph.bottom - 4 }, p)));
    if (through.length) add("throughNodes", `${id} through ${through.map(node => node.id).join(",")}`);
    const steps = Math.max(2, Math.ceil(length / 3));
    const fine = Array.from({ length: steps + 1 }, (_, i) => {
      const q = path.getPointAtLength(length * i / steps);
      return { x: matrix.a * q.x + matrix.c * q.y + matrix.e, y: matrix.b * q.x + matrix.d * q.y + matrix.f };
    });
    const crossed = [...new Set(captions.filter(({ rect }) => fine.some(p => p.x > rect.left + 1 && p.x < rect.right - 1 && p.y > rect.top + 1 && p.y < rect.bottom - 1)).map(caption => caption.id))];
    if (crossed.length) add("throughCaptions", `${id} through ${crossed.join(",")}`);
    if (points.some(p => inside(canvas, p)) && ![source, target].every(node => overlaps(node.box, canvas))) add("offscreenEndpoints", id);
    // Drawn length against the straight distance between the endpoints: a detour or loop-back inflates it.
    const drawn = points.slice(1).reduce((sum, p, i) => sum + Math.hypot(p.x - points[i].x, p.y - points[i].y), 0);
    const chord = Math.hypot(points.at(-1).x - points[0].x, points.at(-1).y - points[0].y);
    if (chord > 24 && drawn / chord > maxDetour) add("detours", `${id}:${(drawn / chord).toFixed(2)}`);
    // A link is one smooth curve: never routed through lanes or gutters that multiply its length.
    if (chord > 0 && drawn / chord > maxLength) add("longLinks", `${id}:${(drawn / chord).toFixed(2)}`);
    // Across columns a line leaves the left node's right side and enters the right node's left side.
    const [left, right] = (source.box.left + source.box.right) / 2 <= (target.box.left + target.box.right) / 2 ? [source, target] : [target, source];
    const leftEnd = left === source ? points[0] : points.at(-1), rightEnd = left === source ? points.at(-1) : points[0];
    const separated = right.box.left - left.box.right > 24;
    if (separated && (leftEnd.x < (left.box.left + left.box.right) / 2 || rightEnd.x > (right.box.left + right.box.right) / 2)) add("wrongSide", id);
  }
  const visible = nodes.filter(node => overlaps(node.box, canvas));
  const small = visible.filter(node => node.glyph && Math.min(node.glyph.width, node.glyph.height) < minGlyph - 0.5);
  if (small.length) add("smallGlyphs", small.map(node => `${node.id}:${Math.round(Math.min(node.glyph.width, node.glyph.height))}px`));
  if (visible.length >= 3) {
    const left = Math.min(...visible.map(n => n.box.left)), right = Math.max(...visible.map(n => n.box.right));
    const top = Math.min(...visible.map(n => n.box.top)), bottom = Math.max(...visible.map(n => n.box.bottom));
    if ((right - left) / canvas.width < minFill && (bottom - top) / canvas.height < minFill) add("underfilled", `${Math.round((right - left) / canvas.width * 100)}% x ${Math.round((bottom - top) / canvas.height * 100)}%`);
    const centers = visible.map(n => (n.box.left + n.box.right) / 2);
    if (Math.max(...centers) - Math.min(...centers) < 8 && canvas.width > 640) add("singleColumn", visible.length);
  }
  if (nodes.length > visible.length && visible.length <= 1) add("loneNode", `${visible.length} of ${nodes.length}`);
  return violations;
}
