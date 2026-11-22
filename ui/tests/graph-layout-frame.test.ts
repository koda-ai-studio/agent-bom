import { afterEach, expect, it } from "vitest";
import { layoutFrameKey, setLayoutFrame } from "@/lib/graph-compact-arcs";

afterEach(() => { setLayoutFrame(0, 0); });

it("keeps its size bucket while a canvas sits on a bucket edge, so the layout and the frame height cannot feed each other", () => {
  // The canvas height follows the placed graph's aspect; near a bucket edge, rounding alone flips 480 and 560
  // on every render and re-places the graph after Fit all.
  expect(setLayoutFrame(1322, 515)).toBe("1360x480");
  expect(setLayoutFrame(1322, 525)).toBe("1360x480");
  expect(setLayoutFrame(1322, 515)).toBe("1360x480");
  expect(layoutFrameKey()).toBe("1360x480");
});

it("re-places for a real resize, a full bucket away", () => {
  expect(setLayoutFrame(1322, 515)).toBe("1360x480");
  expect(setLayoutFrame(846, 515)).toBe("880x480");
  expect(setLayoutFrame(846, 570)).toBe("880x560");
  expect(setLayoutFrame(0, 0)).toBe("default");
});
