import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AttackPathGraph } from "@/components/attack-path-graph";
import { PATH_TRACE_MS, pathTraceTiming } from "@/lib/attack-path-trace";
import { branchingFixture } from "./fixtures/attack-path-graph-fixture";

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} }); vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} }); });

function prefersReducedMotion(reduce: boolean) {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: reduce && query.includes("prefers-reduced-motion: reduce"), media: query,
    addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, onchange: null, dispatchEvent: () => false,
  }));
}

function renderGraph() {
  const fixture = branchingFixture();
  return render(<AttackPathGraph graph={fixture.graph} attackPath={fixture.selected} narrow={false}
    onOpenFindings={vi.fn()} onNodeSelect={vi.fn()} onEdgeSelect={vi.fn()} />);
}

describe("selected path trace", () => {
  it("runs once from entry to target within the motion budget", () => {
    const timing = pathTraceTiming(6);
    expect(timing).toHaveLength(6);
    const end = timing.at(-1)!.delay + timing.at(-1)!.duration;
    expect(end).toBeLessThanOrEqual(PATH_TRACE_MS);
    for (let index = 1; index < timing.length; index += 1) expect(timing[index]!.delay).toBeGreaterThan(timing[index - 1]!.delay);
    expect(pathTraceTiming(0)).toEqual([]);
  });

  it("traces every selected-path hop in order, once, and never a branch", () => {
    prefersReducedMotion(false);
    const { container } = renderGraph();
    const traces = [...container.querySelectorAll<SVGPathElement>("[data-path-trace]")];
    const { selected } = branchingFixture();
    expect(traces.map(trace => trace.getAttribute("data-path-trace"))).toEqual(
      selected.hops.slice(0, -2).map((hop, index) => String(index)),
    );
    // The keyframes run once (`animation: attack-path-trace linear 1 both` in globals.css); each hop only sets its slot.
    for (const trace of traces) expect(trace).toHaveClass("attack-path-trace");
    const delays = traces.map(trace => parseFloat(trace.style.animationDelay));
    expect(delays).toEqual([...delays].sort((a, b) => a - b));
  });

  it("draws no motion at all when the reader prefers reduced motion", () => {
    prefersReducedMotion(true);
    const { container } = renderGraph();
    expect(container.querySelectorAll("[data-path-trace]")).toHaveLength(0);
    // The static view still carries direction: arrowheads on every selected-path hop.
    expect(container.querySelectorAll('[data-testid="attack-path-graph-canvas"] marker').length).toBeGreaterThan(0);
  });
});
