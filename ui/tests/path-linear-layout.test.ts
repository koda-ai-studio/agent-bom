import { describe, expect, it } from "vitest";
import { linearPathLayout } from "@/lib/path-linear-layout";

const nodes = ["g", "b", "a", "d", "c", "f", "e"].map(id => ({ id, position: { x: 0, y: 0 }, data: {} }));
const hops = ["a", "b", "c", "d", "e", "f", "g"];
describe("readable linear investigation paths", () => {
  it("keeps all seven hops in left-to-right order with no reversed row", () => {
    const result = linearPathLayout(nodes, hops, 808)!;
    const ordered = hops.map(id => result.nodes.find(node => node.id === id)!);
    expect(new Set(ordered.map(node => node.position.y)).size).toBe(1);
    for (let i = 1; i < ordered.length; i++) expect(ordered[i]!.position.x).toBeGreaterThan(ordered[i - 1]!.position.x);
    expect(result.width).toBeGreaterThan(808);
    expect(result.nodes.map(node => node.id)).toEqual(nodes.map(node => node.id));
  });
  it("shows all seven hops in a full-width desktop canvas without horizontal scrolling", () => {
    const result = linearPathLayout(nodes, hops, 1280)!;
    expect(result.width).toBe(1280);
    const xs = result.nodes.map(node => node.position.x);
    expect((Math.max(...xs) - Math.min(...xs) + 220) * 0.7 + 96).toBeLessThanOrEqual(1280);
  });
  it("fits short paths without forcing extra horizontal scrolling", () => {
    expect(linearPathLayout(nodes.slice(0, 2), ["g", "b"], 1200)!.width).toBe(1200);
  });
  it("leaves expanded context and incomplete paths on their evidence layout", () => {
    expect(linearPathLayout(nodes, hops.slice(0, 3), 808)).toBeNull();
    expect(linearPathLayout(nodes, [...hops, "missing"], 808)).toBeNull();
  });
});
