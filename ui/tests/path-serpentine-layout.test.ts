import { describe, expect, it } from "vitest";
import { serpentinePositions } from "@/lib/path-serpentine-layout";

describe("serpentinePositions", () => {
  it("alternates row direction so each turn stays on one side", () => {
    const positions = serpentinePositions(["a", "b", "c", "d", "e"], 2, { column: 340, row: 280 });
    const at = (id: string) => positions.get(id)!;
    expect([at("a").reverse, at("c").reverse, at("e").reverse]).toEqual([false, true, false]);
    expect(at("b").x).toBe(at("c").x);
    expect(at("d").x).toBe(at("e").x);
    expect(at("a").x).toBeLessThan(at("b").x);
    expect(at("c").y).toBeGreaterThan(at("b").y);
  });
});
