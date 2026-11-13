import { act, renderHook } from "@testing-library/react";
import type { Node } from "@xyflow/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { LAYOUT_MOTION_MS, layoutFrame, useAnimatedLayout } from "@/hooks/use-animated-layout";

const node = (id: string, x: number, y: number): Node => ({ id, position: { x, y }, data: {} });

function prefersReducedMotion(reduce: boolean) {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: reduce && query.includes("prefers-reduced-motion: reduce"), media: query,
    addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, onchange: null, dispatchEvent: () => false,
  }));
}

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers(); });

describe("animated layout transitions", () => {
  it("moves a node from where it was toward its new place and fades a new one in", () => {
    const from = new Map([["a", { x: 0, y: 0 }]]);
    const start = layoutFrame(from, [node("a", 100, 40), node("b", 300, 0)], 0);
    expect(start[0]!.position).toEqual({ x: 0, y: 0 });
    expect(start[1]!.style?.opacity).toBe(0);
    const middle = layoutFrame(from, [node("a", 100, 40), node("b", 300, 0)], 0.5);
    expect(middle[0]!.position.x).toBeGreaterThan(0);
    expect(middle[0]!.position.x).toBeLessThan(100);
    const end = layoutFrame(from, [node("a", 100, 40), node("b", 300, 0)], 1);
    expect(end[0]!.position).toEqual({ x: 100, y: 40 });
    expect(end[1]!.style?.opacity).toBe(1);
    expect(LAYOUT_MOTION_MS).toBeLessThanOrEqual(300);
  });

  it("jumps straight to the new layout when the reader prefers reduced motion", () => {
    prefersReducedMotion(true);
    const first = [node("a", 0, 0)];
    const { result, rerender } = renderHook(({ nodes }) => useAnimatedLayout(nodes), { initialProps: { nodes: first } });
    expect(result.current.nodes).toBe(first);
    expect(result.current.animating).toBe(false);
    const moved = [node("a", 500, 500), node("b", 10, 10)];
    rerender({ nodes: moved });
    expect(result.current.nodes).toBe(moved);
  });

  it("animates a layout change once and settles on the exact new positions", () => {
    prefersReducedMotion(false);
    vi.useFakeTimers({ toFake: ["requestAnimationFrame", "cancelAnimationFrame", "performance"] });
    const { result, rerender } = renderHook(({ nodes }) => useAnimatedLayout(nodes), { initialProps: { nodes: [node("a", 0, 0)] } });
    const moved = [node("a", 200, 0)];
    rerender({ nodes: moved });
    expect(result.current.nodes[0]!.position.x).toBeLessThan(200);
    expect(result.current.animating).toBe(true);
    act(() => { vi.advanceTimersByTime(LAYOUT_MOTION_MS + 50); });
    expect(result.current.nodes).toBe(moved);
  });
});
