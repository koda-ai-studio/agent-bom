import { expect, it } from "vitest";
import { GRAPH_PHONE_FOCUS_MIN_ZOOM, graphAdaptiveFrame, legibleFitZoom } from "@/lib/graph-adaptive-frame";

it("asks a phone for a closer legible fit than a desktop", () => {
  expect(legibleFitZoom(1134)).toBe(0.4);
  expect(legibleFitZoom(358)).toBe(0.7);
});

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

it("keeps a phone's focused card whole when page chrome leaves less room than the card", () => {
  // Measured at 390x844: ten reference-lab cards, 306px left below the chrome, 360px anchor card.
  const bounds = { x: 0, y: 0, width: 1450, height: 1360 };
  const frame = graphAdaptiveFrame({ width: 356, availableHeight: 306, inspector: false, bounds, focusHeight: 360 });
  expect(frame.fitAll).toBe(false);
  expect(frame.height / (1 + 0.08)).toBeGreaterThanOrEqual(360 * GRAPH_PHONE_FOCUS_MIN_ZOOM);
  const roomy = graphAdaptiveFrame({ width: 356, availableHeight: 306, inspector: false, bounds, focusHeight: 360, focusPadding: 0.25 });
  expect(roomy.height / (1 + 0.25)).toBeGreaterThanOrEqual(360 * GRAPH_PHONE_FOCUS_MIN_ZOOM);
  expect(roomy.height).toBeLessThan(400);
});

it("does not grow a desktop or whole-graph frame for a focus card", () => {
  const dense = { x: 0, y: 0, width: 4000, height: 2200 };
  expect(graphAdaptiveFrame({ width: 900, availableHeight: 306, inspector: false, bounds: dense, focusHeight: 360 }).height).toBeLessThanOrEqual(306);
  const compact = { x: 0, y: 0, width: 300, height: 200 };
  const whole = graphAdaptiveFrame({ width: 356, availableHeight: 306, inspector: false, bounds: compact, focusHeight: 360 });
  expect(whole.fitAll).toBe(true);
  expect(whole.height).toBeLessThanOrEqual(306);
});
