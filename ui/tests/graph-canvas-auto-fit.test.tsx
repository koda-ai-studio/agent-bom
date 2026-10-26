import { act, cleanup, render } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const flow = vi.hoisted(() => ({
  initialized: true,
  fitView: vi.fn().mockResolvedValue(true),
  getNodes: vi.fn(() => [{ id: "asset", position: { x: 0, y: 0 }, data: {} }]),
  getEdges: vi.fn(() => []),
  getNodesBounds: vi.fn<(nodes?: Array<{ id: string }>) => { x: number; y: number; width: number; height: number }>(() => ({ x: 0, y: 0, width: 800, height: 1000 })),
  frame: null as HTMLElement | null,
  zoom: 0.4,
  width: 900,
}));
vi.mock("@xyflow/react", () => ({
  Panel: () => null,
  useNodesInitialized: () => flow.initialized,
  useReactFlow: () => flow,
  useStore: (select: (state: unknown) => unknown) => select({ width: flow.width, height: 400, domNode: flow.frame }),
  getViewportForBounds: () => ({ x: 0, y: 0, zoom: flow.zoom }),
}));
import { GraphCanvasAutoFit } from "@/components/graph-canvas-auto-fit";

afterEach(() => { flow.zoom = 0.4; flow.width = 900; cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.clearAllMocks(); flow.fitView.mockResolvedValue(true); flow.initialized = true; flow.getNodes.mockReturnValue([{ id: "asset", position: { x: 0, y: 0 }, data: {} }]); flow.getNodesBounds.mockReturnValue({ x: 0, y: 0, width: 800, height: 1000 }); });

it("ignores snapshot notice height when a late resize measures the pinned frame", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  let measure!: () => void;
  vi.stubGlobal("ResizeObserver", class { constructor(callback: () => void) { measure = callback; } observe() {} disconnect() {} });
  vi.stubGlobal("innerHeight", 1000);
  const main = document.createElement("main");
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  const mount = document.createElement("div");
  main.append(flow.frame, mount);
  const bounds = vi.spyOn(flow.frame, "getBoundingClientRect").mockReturnValue({ top: 300 } as DOMRect);
  render(<GraphCanvasAutoFit enabled layoutKey="pinned" inspector preserveViewport={false} onLayoutAspect={vi.fn()} />, { container: mount });
  await act(() => vi.advanceTimersByTimeAsync(100));
  const height = flow.frame.style.getPropertyValue("--graph-adaptive-height");
  const fits = flow.fitView.mock.calls.length;
  const notice = document.createElement("aside");
  notice.setAttribute("aria-label", "Saved snapshot updates");
  notice.style.marginBottom = "12px";
  vi.spyOn(notice, "getBoundingClientRect").mockReturnValue({ height: 60 } as DOMRect);
  main.prepend(notice);
  bounds.mockReturnValue({ top: 372 } as DOMRect);
  await act(async () => { measure(); await vi.advanceTimersByTimeAsync(100); });
  expect(flow.frame.style.getPropertyValue("--graph-adaptive-height")).toBe(height);
  expect(flow.fitView).toHaveBeenCalledTimes(fits);
});

it("does not replace a manual camera when virtualized nodes reinitialize", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  const onLayoutAspect = vi.fn();
  const view = (layoutKey: string) => <GraphCanvasAutoFit enabled layoutKey={layoutKey} inspector={false} preserveViewport={false} onLayoutAspect={onLayoutAspect} />;
  const rendered = render(view("first"));
  await act(() => vi.advanceTimersByTimeAsync(50));
  expect(flow.fitView).toHaveBeenCalledTimes(2);
  // Zooming or panning can unmount virtualized nodes, then initialize them.
  flow.initialized = false;
  rendered.rerender(view("first"));
  flow.initialized = true;
  rendered.rerender(view("first"));
  await act(() => vi.advanceTimersByTimeAsync(50));
  expect(flow.fitView).toHaveBeenCalledTimes(2);
  rendered.rerender(view("changed-layout"));
  await act(() => vi.advanceTimersByTimeAsync(50));
  expect(flow.fitView).toHaveBeenCalledTimes(4);
});

it("finishes camera settling when measurement restarts during an initial fit", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  let finishFirst!: (value: boolean) => void;
  flow.fitView.mockImplementationOnce(() => new Promise<boolean>(resolve => { finishFirst = resolve; }));
  const onLayoutAspect = vi.fn();
  const view = () => <GraphCanvasAutoFit enabled layoutKey="settling" inspector={false} preserveViewport={false} onLayoutAspect={onLayoutAspect} />;
  const rendered = render(view());
  await act(() => vi.advanceTimersByTimeAsync(50));
  expect(flow.fitView).toHaveBeenCalledTimes(1);
  flow.initialized = false;
  rendered.rerender(view());
  flow.initialized = true;
  rendered.rerender(view());
  await act(() => vi.advanceTimersByTimeAsync(50));
  expect(flow.fitView).toHaveBeenCalledTimes(3);
  await act(async () => { finishFirst(true); await vi.advanceTimersByTimeAsync(50); });
  expect(flow.fitView).toHaveBeenCalledTimes(3);
});

it("refits when zoom-dependent dimensions arrive after the second camera fit", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  flow.fitView.mockResolvedValueOnce(true).mockImplementationOnce(async () => {
    // Readable glyphs resize after zoom; React Flow receives that measurement
    // on a later frame, even though all nodes remain initialized.
    setTimeout(() => flow.getNodesBounds.mockReturnValue({ x: 0, y: 0, width: 800, height: 1100 }), 1);
    return true;
  });
  render(<GraphCanvasAutoFit enabled layoutKey="late-measurement" inspector={false} preserveViewport={false} onLayoutAspect={vi.fn()} />);
  await act(() => vi.advanceTimersByTimeAsync(100));
  expect(flow.fitView).toHaveBeenCalledTimes(3);
});

it("keeps canvas height within the page when measured after a control scrolls into view", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  vi.stubGlobal("scrollY", 100);
  vi.stubGlobal("innerHeight", 768);
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  vi.spyOn(flow.frame, "getBoundingClientRect").mockReturnValue({ top: 300 } as DOMRect);
  render(<GraphCanvasAutoFit enabled layoutKey="scrolled-measurement" inspector={false} preserveViewport={false} onLayoutAspect={vi.fn()} />);
  await act(() => vi.advanceTimersByTimeAsync(100));
  // The document offset is 400px, regardless of the temporary 100px scroll.
  expect(flow.frame.style.getPropertyValue("--graph-adaptive-height")).toBe("344px");
});

it("settles the fitted root even when its size changes inside a stable graph envelope", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  flow.getNodes.mockReturnValue([
    { id: "asset", position: { x: 0, y: 0 }, data: {} },
    { id: "distant", position: { x: 4000, y: 1000 }, data: {} },
  ]);
  let rootWidth = 220;
  flow.getNodesBounds.mockImplementation(nodes => nodes?.length === 1
    ? { x: 0, y: 0, width: rootWidth, height: 180 }
    : { x: 0, y: 0, width: 4220, height: 1180 });
  flow.fitView.mockResolvedValueOnce(true).mockImplementationOnce(async () => {
    setTimeout(() => { rootWidth = 300; }, 1);
    return true;
  });
  render(<GraphCanvasAutoFit enabled layoutKey="root-settling" anchorId="asset" inspector={false} preserveViewport={false} onLayoutAspect={vi.fn()} />);
  await act(() => vi.advanceTimersByTimeAsync(100));
  // The camera frames the whole envelope; a card resizing inside it moves nothing.
  expect(flow.fitView).toHaveBeenCalledTimes(2);
  expect(flow.fitView.mock.calls.every(([options]) => (options as { nodes?: unknown }).nodes === undefined)).toBe(true);
});

it("reclaims canvas space when an expanded investigation removes a control row", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  vi.stubGlobal("innerHeight", 768);
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  const bounds = vi.spyOn(flow.frame, "getBoundingClientRect");
  bounds.mockReturnValue({ top: 400 } as DOMRect);
  const onLayoutAspect = vi.fn();
  const view = (layoutKey: string) => <GraphCanvasAutoFit enabled layoutKey={layoutKey} inspector={false} preserveViewport={false} onLayoutAspect={onLayoutAspect} />;
  const rendered = render(view("partial"));
  await act(() => vi.advanceTimersByTimeAsync(100));
  expect(flow.frame.style.getPropertyValue("--graph-adaptive-height")).toBe("344px");
  // The last page removes Show more connections. The canvas itself has not
  // resized yet, so its ResizeObserver cannot discover the reclaimed space.
  bounds.mockReturnValue({ top: 378 } as DOMRect);
  rendered.rerender(view("complete"));
  await act(() => vi.advanceTimersByTimeAsync(100));
  expect(flow.frame.style.getPropertyValue("--graph-adaptive-height")).toBe("366px");
});


it("fits every loaded node on load, never a neighbourhood or a lone card, with a legible zoom cap", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  flow.getNodes.mockReturnValue(Array.from({ length: 11 }, (_, index) => ({ id: `n${index}`, position: { x: index * 300, y: 0 }, data: {} })));
  flow.getEdges.mockReturnValue([{ source: "n0", target: "n1" }] as never);
  render(<GraphCanvasAutoFit enabled layoutKey="eleven" anchorId="n0" inspector={false} preserveViewport={false} onLayoutAspect={vi.fn()} />);
  await act(() => vi.advanceTimersByTimeAsync(100));
  const options = flow.fitView.mock.calls[0]![0] as { nodes?: unknown; maxZoom: number; minZoom: number };
  expect(options.nodes).toBeUndefined();
  expect(options.maxZoom).toBe(1);
  expect(options.minZoom).toBeLessThanOrEqual(0.1);
});

it("opens a graph too dense to read whole on the anchor's neighbourhood, never a lone card", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  flow.getNodes.mockReturnValue(Array.from({ length: 60 }, (_, index) => ({ id: `n${index}`, position: { x: index * 300, y: 0 }, data: {} })));
  flow.getEdges.mockReturnValue([{ source: "n0", target: "n1" }, { source: "n0", target: "n2" }] as never);
  flow.zoom = 0.1;
  render(<GraphCanvasAutoFit enabled layoutKey="dense" anchorId="n0" inspector={false} preserveViewport={false} onLayoutAspect={vi.fn()} />);
  await act(() => vi.advanceTimersByTimeAsync(100));
  const options = flow.fitView.mock.calls[0]![0] as { nodes?: { id: string }[]; maxZoom: number };
  expect(options.nodes!.map(node => node.id).sort()).toEqual(["n0", "n1", "n2"]);
  expect(options.maxZoom).toBeLessThanOrEqual(1);
});

it("refits the whole graph when the data changes", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  const view = (layoutKey: string) => <GraphCanvasAutoFit enabled layoutKey={layoutKey} inspector={false} preserveViewport={false} onLayoutAspect={vi.fn()} />;
  const rendered = render(view("before"));
  await act(() => vi.advanceTimersByTimeAsync(100));
  const before = flow.fitView.mock.calls.length;
  rendered.rerender(view("after"));
  await act(() => vi.advanceTimersByTimeAsync(100));
  expect(flow.fitView.mock.calls.length).toBeGreaterThan(before);
  expect((flow.fitView.mock.calls.at(-1)![0] as { nodes?: unknown }).nodes).toBeUndefined();
});

it("does not restart an exhausted settling budget when virtualized measurements toggle", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  let height = 1000;
  flow.getNodesBounds.mockImplementation(() => ({ x: 0, y: 0, width: 800, height }));
  flow.fitView.mockImplementation(async () => {
    // Readability-dependent captions can alternate around a zoom threshold.
    height = height === 1000 ? 1100 : 1000;
    return true;
  });
  const onLayoutAspect = vi.fn();
  const view = () => <GraphCanvasAutoFit enabled layoutKey="bounded-settling" inspector preserveViewport={false} onLayoutAspect={onLayoutAspect} />;
  const rendered = render(view());
  await act(() => vi.advanceTimersByTimeAsync(100));
  expect(flow.fitView).toHaveBeenCalledTimes(4);
  flow.initialized = false;
  rendered.rerender(view());
  flow.initialized = true;
  rendered.rerender(view());
  await act(() => vi.advanceTimersByTimeAsync(100));
  expect(flow.fitView).toHaveBeenCalledTimes(4);
});


it("reports camera settling until the asynchronous fit and measurements finish", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  let finish!: (value: boolean) => void;
  flow.fitView.mockImplementationOnce(() => new Promise<boolean>(resolve => { finish = resolve; }));
  render(<GraphCanvasAutoFit enabled layoutKey="pending" inspector preserveViewport={false} onLayoutAspect={vi.fn()} />);
  await act(() => vi.advanceTimersByTimeAsync(100));
  expect(flow.frame).toHaveAttribute("data-graph-camera-settled", "false");
  await act(async () => { finish(true); await vi.advanceTimersByTimeAsync(100); });
  expect(flow.frame).toHaveAttribute("data-graph-camera-settled", "true");
});

it("sizes a phone's focus frame from the anchor's layout cell, not its zoom-inflated measurement", async () => {
  vi.useFakeTimers();
  vi.stubGlobal("requestAnimationFrame", (callback: () => void) => setTimeout(callback, 0));
  vi.stubGlobal("cancelAnimationFrame", clearTimeout);
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
  vi.stubGlobal("innerHeight", 844);
  flow.width = 356;
  flow.zoom = 0.25;
  // Before the first fit, zoom-compensated captions inflate the measured card past its layout cell.
  flow.getNodes.mockReturnValue([{ id: "agent", position: { x: 0, y: 0 }, style: { minHeight: 360 }, measured: { width: 220, height: 640 }, data: {} }] as never);
  flow.getNodesBounds.mockReturnValue({ x: 0, y: 0, width: 1450, height: 1360 });
  flow.frame = document.createElement("div");
  flow.frame.setAttribute("data-graph-adaptive-frame", "");
  vi.spyOn(flow.frame, "getBoundingClientRect").mockReturnValue({ top: 514 } as DOMRect);
  render(<GraphCanvasAutoFit enabled layoutKey="phone" anchorId="agent" inspector={false} preserveViewport={false} onLayoutAspect={vi.fn()} />);
  await act(() => vi.advanceTimersByTimeAsync(100));
  expect(flow.frame.style.getPropertyValue("--graph-adaptive-height")).toBe("331px");
  expect(flow.fitView).toHaveBeenCalledWith(expect.objectContaining({ nodes: [{ id: "agent" }], minZoom: 0.85 }));
});
