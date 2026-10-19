import { act, cleanup, render } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const flow = vi.hoisted(() => ({
  initialized: true,
  fitView: vi.fn().mockResolvedValue(true),
  getNodes: vi.fn(() => [{ id: "asset", position: { x: 0, y: 0 }, data: {} }]),
  getEdges: vi.fn(() => []),
  getNodesBounds: vi.fn<(nodes?: Array<{ id: string }>) => { x: number; y: number; width: number; height: number }>(() => ({ x: 0, y: 0, width: 800, height: 1000 })),
  frame: null as HTMLElement | null,
}));
vi.mock("@xyflow/react", () => ({
  Panel: () => null,
  useNodesInitialized: () => flow.initialized,
  useReactFlow: () => flow,
  useStore: (select: (state: unknown) => unknown) => select({ width: 900, height: 400, domNode: flow.frame }),
  getViewportForBounds: () => ({ x: 0, y: 0, zoom: 0.4 }),
}));
import { GraphCanvasAutoFit } from "@/components/graph-canvas-auto-fit";

afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.clearAllMocks(); flow.fitView.mockResolvedValue(true); flow.initialized = true; flow.getNodes.mockReturnValue([{ id: "asset", position: { x: 0, y: 0 }, data: {} }]); flow.getNodesBounds.mockReturnValue({ x: 0, y: 0, width: 800, height: 1000 }); });

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
  expect(flow.fitView).toHaveBeenCalledTimes(3);
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
