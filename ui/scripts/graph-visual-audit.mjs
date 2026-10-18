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
    return {
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
