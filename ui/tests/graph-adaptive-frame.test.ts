import { expect, it } from "vitest";
import { graphAdaptiveFrame } from "@/lib/graph-adaptive-frame";

it("sizes by measured shape and available space, without a node-count cutoff", () => {
  const base = { width: 800, availableHeight: 700, inspector: true };
  const short = graphAdaptiveFrame({ ...base, bounds: { x: 0, y: 0, width: 600, height: 160 } });
  const tall = graphAdaptiveFrame({ ...base, bounds: { x: 0, y: 0, width: 800, height: 640 } });
  expect(short.height).toBeLessThan(tall.height);
  expect(short.height).toBeGreaterThanOrEqual(400);
  expect(tall.height).toBeLessThanOrEqual(700);
  expect(tall.fitAll).toBe(true);
});

it("adapts to a short window and keeps a dense context readable", () => {
  const bounds = { x: 0, y: 0, width: 4000, height: 2200 };
  const frame = graphAdaptiveFrame({ width: 700, availableHeight: 340, inspector: false, bounds });
  expect(frame.height).toBeLessThanOrEqual(340);
  expect(frame.fitAll).toBe(false);
});

it("reports the available aspect independently of the chosen canvas height", () => {
  const base = { availableHeight: 600, inspector: true, bounds: { x: 0, y: 0, width: 1000, height: 700 } };
  expect(graphAdaptiveFrame({ ...base, width: 600 }).layoutAspect).toBe(1);
  expect(graphAdaptiveFrame({ ...base, width: 1200 }).layoutAspect).toBe(2);
});
