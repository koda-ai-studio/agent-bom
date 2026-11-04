/** Runs in the browser so test-driver scheduling is not counted as graph rendering. */
export function installGraphPaintMeasurement() {
  const target = window as Window & { graphPaintReadyAt?: number };
  let stableFrames = 0;
  const sample = () => {
    const frame = document.querySelector<HTMLElement>("[data-graph-adaptive-frame]");
    const canvas = frame?.querySelector(".react-flow");
    const nodes = canvas ? [...canvas.querySelectorAll<HTMLElement>(".react-flow__node")] : [];
    const glyph = canvas?.querySelector<HTMLElement>(".graph-entity-glyph");
    const edges = canvas ? [...canvas.querySelectorAll<SVGElement>(".react-flow__edge")] : [];
    const visible = (element: Element) => {
      const bounds = element.getBoundingClientRect(), style = getComputedStyle(element);
      return bounds.width > 0 && bounds.height > 0 && style.visibility !== "hidden" && style.display !== "none";
    };
    let ready = frame?.dataset.graphCameraSettled === "true" && Boolean(canvas && glyph && visible(glyph))
      && nodes.length === 5 && canvas!.querySelectorAll(".react-flow__node-serverNode").length === 3
      && edges.length === 4 && visible(edges[0]!) && canvas!.querySelectorAll(".graph-relationship-label").length === 0;
    if (ready) {
      const bounds = canvas!.getBoundingClientRect(), boxes = nodes.map(node => node.getBoundingClientRect());
      ready = nodes.every(visible) && boxes.every(box => box.left >= bounds.left && box.right <= bounds.right
        && box.top >= bounds.top && box.bottom <= bounds.bottom);
      const center = (Math.min(...boxes.map(box => box.top)) + Math.max(...boxes.map(box => box.bottom))) / 2;
      ready = ready && Math.abs(center - (bounds.top + bounds.height / 2)) / bounds.height < 0.1;
    }
    stableFrames = ready ? stableFrames + 1 : 0;
    // Readiness plus two subsequent animation frames, rechecked on each frame.
    if (stableFrames >= 3) target.graphPaintReadyAt = performance.now();
    else requestAnimationFrame(sample);
  };
  requestAnimationFrame(sample);
}
