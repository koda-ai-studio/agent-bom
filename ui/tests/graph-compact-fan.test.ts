import { expect, it } from "vitest";
import { linkEndFans } from "@/lib/graph-compact-fan";

it("spreads the ends of links that meet one side of a glyph, ordered by the far card's row", () => {
  const positions = new Map([["a", { x: 0, y: -200 }], ["b", { x: 0, y: 200 }], ["t", { x: 240, y: 0 }], ["back", { x: 480, y: 0 }]]);
  const fans = linkEndFans([
    { id: "a-t", source: "a", target: "t" }, { id: "b-t", source: "b", target: "t" }, { id: "back-t", source: "back", target: "t" },
  ], positions);
  expect(fans.get("a-t")!.targetFan).toBeLessThan(0);
  expect(fans.get("b-t")!.targetFan).toBeGreaterThan(0);
  // A back link enters through the side handle and is not part of the fan; a lone source end does not spread.
  expect(fans.has("back-t")).toBe(false);
  expect(fans.get("a-t")!.sourceFan).toBeUndefined();
});
