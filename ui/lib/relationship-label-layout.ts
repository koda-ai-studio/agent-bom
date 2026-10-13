// One placement pass per canvas, batched after React Flow renders the edges.
const pending = new WeakSet<HTMLElement>();
type Box = { left: number; right: number; top: number; bottom: number };
type Point = { x: number; y: number };
const intersects = (a: Box, b: Box) => a.left < b.right + 2 && a.right > b.left - 2
  && a.top < b.bottom + 2 && a.bottom > b.top - 2;

export function scheduleRelationshipLabelLayout(label: HTMLElement | null) {
  const canvas = label?.closest<HTMLElement>(".react-flow");
  if (!canvas || pending.has(canvas)) return;
  pending.add(canvas);
  requestAnimationFrame(() => {
    pending.delete(canvas);
    if (!canvas.isConnected) return;
    const nodes = [...canvas.querySelectorAll(".react-flow__node")].map(node => node.getBoundingClientRect());
    // Dense estates use the bounded investigation view for readable labels.
    if (nodes.length > 80 || canvas.querySelectorAll(".graph-relationship-label").length > 160) return;
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
      const candidates = [preferred, ...Array.from({ length: 199 }, (_, index) => path.getPointAtLength(length * (index + 1) / 200))]
        .sort((a, b) => ((a.x - preferred.x) ** 2 + (a.y - preferred.y) ** 2)
          - ((b.x - preferred.x) ** 2 + (b.y - preferred.y) ** 2))
        .map(point => ({ point, box: boxAt(point) }))
        .filter(({ box }) => !nodes.some(node => intersects(box, node)));
      return [{ element, length, candidates, fallback }];
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
    labels.forEach(({ element }, index) => {
      const { x, y } = chosen[index]!.point;
      element.style.transform = `translate(-50%, -50%) translate(${x}px, ${y}px)`;
    });
  });
}
