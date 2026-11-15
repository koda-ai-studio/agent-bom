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
