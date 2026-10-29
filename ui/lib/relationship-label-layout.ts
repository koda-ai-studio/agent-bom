// One placement pass per canvas, batched after React Flow renders the edges.
const pending = new WeakSet<HTMLElement>();
const moving = new WeakMap<HTMLElement, ReturnType<typeof setTimeout>>();
// Captions keep clear of the canvas border so none is drawn flush or cut.
const CANVAS_INSET = 4;
const MOVE_SETTLE_MS = 120;
type Box = { left: number; right: number; top: number; bottom: number };
type Point = { x: number; y: number };
const intersects = (a: Box, b: Box) => a.left < b.right + 2 && a.right > b.left - 2
  && a.top < b.bottom + 2 && a.bottom > b.top - 2;

/**
 * A pan keeps the zoom, so captions placed for the previous viewport can
 * straddle the new canvas edge. Re-place them once the camera settles rather
 * than on every animation frame of the move.
 */
export function scheduleRelationshipLabelLayoutAfterMove(label: HTMLElement | null) {
  const canvas = label?.closest<HTMLElement>(".react-flow");
  if (!canvas) return;
  clearTimeout(moving.get(canvas));
  moving.set(canvas, setTimeout(() => {
    moving.delete(canvas);
    scheduleRelationshipLabelLayout(label);
  }, MOVE_SETTLE_MS));
}

export function scheduleRelationshipLabelLayout(label: HTMLElement | null) {
  const canvas = label?.closest<HTMLElement>(".react-flow");
  if (!canvas || pending.has(canvas)) return;
  pending.add(canvas);
  requestAnimationFrame(() => {
    pending.delete(canvas);
    if (!canvas.isConnected) return;
    const nodeElements = [...canvas.querySelectorAll(".react-flow__node")];
    // Dense estates use the bounded investigation view for readable labels.
    if (nodeElements.length > 80 || canvas.querySelectorAll(".graph-relationship-label").length > 160) return;
    const nodes = nodeElements.flatMap(node => {
      const card = node.querySelector<HTMLElement>("[data-graph-entity]");
      if (!card) return [node.getBoundingClientRect()];
      // Circular cards reserve a wide rectangular footprint for their names.
      // Empty space beside the glyph must not push an edge's caption off its
      // line. Avoid the visible glyph/ring and each actual content row instead.
      return [...card.children].flatMap(child => {
        const box = child.getBoundingClientRect();
        if (box.width <= 0 || box.height <= 0) return [];
        // Outline and shadow scale with the glyph; a fixed screen-space margin
        // overstates them at overview zoom and detaches short-link captions.
        const layoutWidth = (child as HTMLElement).offsetWidth;
        const glyphScale = layoutWidth > 0 ? box.width / layoutWidth : 1;
        const ring = child.classList.contains("graph-entity-glyph") ? 8 * glyphScale : 0;
        return [{ left: box.left - ring, right: box.right + ring,
          top: box.top - ring, bottom: box.bottom + ring }];
      });
    });
    // Sampled screen-space points of every drawn relationship, bucketed on a
    // coarse grid, so a caption is not parked on top of a different line.
    const CELL = 32;
    const grid = new Map<string, { id: string; x: number; y: number }[]>();
    for (const edge of canvas.querySelectorAll<SVGGElement>(".react-flow__edge[data-id]")) {
      const path = edge.querySelector<SVGPathElement>(".react-flow__edge-path");
      const matrix = path?.getScreenCTM?.();
      if (!path?.getTotalLength || !matrix) continue;
      const id = edge.getAttribute("data-id")!, length = path.getTotalLength();
      const samples = Math.min(120, Math.max(12, Math.ceil(length / 8)));
      for (let index = 0; index <= samples; index += 1) {
        const point = path.getPointAtLength(length * index / samples);
        const x = matrix.a * point.x + matrix.c * point.y + matrix.e, y = matrix.b * point.x + matrix.d * point.y + matrix.f;
        const key = `${Math.floor(x / CELL)}:${Math.floor(y / CELL)}`;
        grid.set(key, [...(grid.get(key) ?? []), { id, x, y }]);
      }
    }
    const onForeignEdge = (box: Box, edgeId: string) => {
      for (let cx = Math.floor((box.left - 2) / CELL); cx <= Math.floor((box.right + 2) / CELL); cx += 1) {
        for (let cy = Math.floor((box.top - 2) / CELL); cy <= Math.floor((box.bottom + 2) / CELL); cy += 1) {
          if (grid.get(`${cx}:${cy}`)?.some(({ id, x, y }) => id !== edgeId
            && x > box.left - 2 && x < box.right + 2 && y > box.top - 2 && y < box.bottom + 2)) return true;
        }
      }
      return false;
    };
    // A caption pushed past the canvas edge is clipped; never place one there.
    const frame = canvas.getBoundingClientRect();
    const sized = frame.width > 0 && frame.height > 0;
    const inner = { left: frame.left + CANVAS_INSET, right: frame.right - CANVAS_INSET,
      top: frame.top + CANVAS_INSET, bottom: frame.bottom - CANVAS_INSET };
    const insideCanvas = (box: Box) => !sized
      || (box.left >= inner.left && box.right <= inner.right && box.top >= inner.top && box.bottom <= inner.bottom);
    // With no clear spot on its line, a caption the canvas edge would cut is
    // moved wholly inside; one whose link is panned out of view stays put.
    const shiftInside = (low: number, high: number, min: number, max: number) =>
      low < min ? min - low : high > max ? max - high : 0;
    const keepInside = ({ point, box }: { point: Point; box: Box }, scaleX: number, scaleY: number): Point => {
      const visible = box.right > frame.left && box.left < frame.right && box.bottom > frame.top && box.top < frame.bottom;
      if (insideCanvas(box) || !visible) return point;
      return { x: point.x + shiftInside(box.left, box.right, inner.left, inner.right) / scaleX,
        y: point.y + shiftInside(box.top, box.bottom, inner.top, inner.bottom) / scaleY };
    };
    const labels = [...canvas.querySelectorAll<HTMLElement>(".graph-relationship-label[data-edge-id]")].flatMap(element => {
      const edge = canvas.querySelector(`.react-flow__edge[data-id="${CSS.escape(element.dataset.edgeId!)}"]`);
      const path = edge?.querySelector<SVGPathElement>(".react-flow__edge-path");
      if (!path?.getTotalLength || !path.getScreenCTM) return [];
      const matrix = path.getScreenCTM();
      if (!matrix) return [];
      const length = path.getTotalLength();
      const bounds = element.getBoundingClientRect();
      const preferred = { x: Number(element.dataset.labelX), y: Number(element.dataset.labelY) };
      const boxAt = ({ x, y }: Point): Box => {
        const centerX = matrix.a * x + matrix.c * y + matrix.e;
        const centerY = matrix.b * x + matrix.d * y + matrix.f;
        return { left: centerX - bounds.width / 2, right: centerX + bounds.width / 2,
          top: centerY - bounds.height / 2, bottom: centerY + bounds.height / 2 };
      };
      const fallback = { point: preferred, box: boxAt(preferred) };
      const scale = { x: Math.abs(matrix.a) || 1, y: Math.abs(matrix.d) || 1 };
      const byDistance = (a: Point, b: Point) => ((a.x - preferred.x) ** 2 + (a.y - preferred.y) ** 2)
        - ((b.x - preferred.x) ** 2 + (b.y - preferred.y) ** 2);
      const clearOfNodes = ({ box }: { box: Box }) => insideCanvas(box) && !nodes.some(node => intersects(box, node));
      const onPath = [preferred, ...Array.from({ length: 199 }, (_, index) => path.getPointAtLength(length * (index + 1) / 200))]
        .sort(byDistance);
      let nodeClear = onPath.map(point => ({ point, box: boxAt(point) })).filter(clearOfNodes);
      if (!nodeClear.length) {
        // A short link can lie wholly inside its endpoint cards: nudge the
        // caption off the line, nearest the midpoint first, in growing steps.
        const scaleX = scale.x, scaleY = scale.y;
        const nudges = onPath.slice(0, 24).flatMap(({ x, y }) => [4, 16, 32, 56].flatMap(gap => {
          const dx = (bounds.width / 2 + gap) / scaleX, dy = (bounds.height / 2 + gap) / scaleY;
          return [{ x, y: y - dy }, { x, y: y + dy }, { x: x - dx, y }, { x: x + dx, y }];
        }));
        // Wrapped labels and evidence badges make endpoint cards taller than
        // fixed nudges anticipate. Try their measured boundaries while keeping
        // the caption inside the canvas, rather than restoring an overlap.
        const centerX = (fallback.box.left + fallback.box.right) / 2;
        const centerY = (fallback.box.top + fallback.box.bottom) / 2;
        const boundaries = sized ? nodes.filter(node => intersects(fallback.box, node)).flatMap(node => [
          { x: preferred.x, y: preferred.y + (node.top - 4 - bounds.height / 2 - centerY) / scaleY },
          { x: preferred.x, y: preferred.y + (node.bottom + 4 + bounds.height / 2 - centerY) / scaleY },
          { x: preferred.x + (node.left - 4 - bounds.width / 2 - centerX) / scaleX, y: preferred.y },
          { x: preferred.x + (node.right + 4 + bounds.width / 2 - centerX) / scaleX, y: preferred.y },
        ]) : [];
        nodeClear = [...nudges, ...boundaries].sort(byDistance).map(point => ({ point, box: boxAt(point) })).filter(clearOfNodes);
      }
      const clearOfEdges = nodeClear.filter(({ box }) => !onForeignEdge(box, element.dataset.edgeId!));
      const candidates = clearOfEdges.length ? clearOfEdges : nodeClear;
      return [{ element, length, candidates, fallback, scale }];
    }).sort((a, b) => a.candidates.length - b.candidates.length || a.length - b.length
      || a.element.dataset.edgeId!.localeCompare(b.element.dataset.edgeId!));
    type Placement = { point: Point; box: Box };
    const chosen: Placement[] = [];
    let attempts = 0;
    // Small investigations can resolve mutually constrained labels together.
    // Bound the search; larger views use the same candidates in one greedy pass.
    function place(index: number): boolean {
      if (index === labels.length) return true;
      for (const candidate of labels[index]!.candidates) {
        if (++attempts > 20_000) return false;
        if (chosen.some(other => intersects(candidate.box, other.box))) continue;
        chosen.push(candidate);
        if (place(index + 1)) return true;
        chosen.pop();
      }
      return false;
    }
    if (labels.length > 24 || !place(0)) {
      chosen.length = 0;
      for (const item of labels) {
        chosen.push(item.candidates.find(candidate => !chosen.some(other => intersects(candidate.box, other.box))) ?? item.fallback);
      }
    }
    // Finish all measurements before writing styles. Never hide a label when a
    // crowded graph has no collision-free position.
    labels.forEach(({ element, scale }, index) => {
      const { x, y } = keepInside(chosen[index]!, scale.x, scale.y);
      element.style.transform = `translate(-50%, -50%) translate(${x}px, ${y}px)`;
    });
  });
}
