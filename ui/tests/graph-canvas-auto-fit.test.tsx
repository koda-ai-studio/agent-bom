import { act, cleanup, render } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";

const flow = vi.hoisted(() => ({
  initialized: true,
  fitView: vi.fn().mockResolvedValue(true),
  getNodes: vi.fn(() => [{ id: "asset", position: { x: 0, y: 0 }, data: {} }]),
  getEdges: vi.fn(() => []),
  getNodesBounds: vi.fn(() => ({ x: 0, y: 0, width: 800, height: 1000 })),
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

afterEach(() => { cleanup(); vi.useRealTimers(); vi.unstubAllGlobals(); vi.clearAllMocks(); flow.initialized = true; });

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
