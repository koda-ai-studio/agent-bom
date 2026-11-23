import { describe, expect, it } from "vitest";
import { pathEdgeHandles } from "@/lib/attack-path-graph-handles";
import { sideArcPath } from "@/components/attack-path-graph-edge";
import type { AttackPathLayout } from "@/lib/attack-path-graph-layout";

const layout = (positions: Record<string, { x: number; y: number }>, direction: "LR" | "TB" = "LR") =>
  ({ direction, positions: new Map(Object.entries(positions)) }) as unknown as AttackPathLayout;

describe("a link between two cards of one column on a row layout", () => {
  it("leaves and enters on the right rims, never right-out and left-in (which hooks round the column)", () => {
    const rows = layout({ cred: { x: 732, y: 376 }, tool: { x: 732, y: 40 }, server: { x: 532, y: 208 }, pkg: { x: 932, y: 208 } });
    expect(pathEdgeHandles(rows, "cred", "tool")).toEqual({ sourceHandle: "side", targetHandle: "context" });
    // Forward and backward links keep their usual handles.
    expect(pathEdgeHandles(rows, "server", "pkg")).toEqual({ sourceHandle: null, targetHandle: null });
    expect(pathEdgeHandles(rows, "pkg", "server")).toEqual({ sourceHandle: "context", targetHandle: "context" });
  });

  it("meets the upper card low on its rim when a forward link changes row, so it never runs along that card's path line", () => {
    const rows = layout({ agent: { x: 532, y: 40 }, server: { x: 732, y: 208 }, runbook: { x: 532, y: 208 }, hop: { x: 932, y: 40 } });
    expect(pathEdgeHandles(rows, "agent", "server")).toEqual({ sourceHandle: "branch", targetHandle: null });
    expect(pathEdgeHandles(rows, "server", "hop")).toEqual({ sourceHandle: null, targetHandle: "branch" });
    expect(pathEdgeHandles(rows, "runbook", "server")).toEqual({ sourceHandle: null, targetHandle: null });
  });

  it("draws one C-curve that bows right of both cards and turns back only once", () => {
    const d = sideArcPath({ x: 788, y: 410 }, { x: 788, y: 74 });
    const numbers = d.match(/-?\d+(\.\d+)?/g)!.map(Number);
    expect(d.startsWith("M")).toBe(true);
    expect((d.match(/C/g) ?? []).length).toBe(1);
    const [sx, sy, c1x, c1y, c2x, c2y, tx, ty] = numbers;
    expect([sx, sy, tx, ty]).toEqual([788, 410, 788, 74]);
    // Both control points sit to the right of the rims at the end rows: the bulge clears the captions under each glyph.
    expect(c1x! - sx!).toBeGreaterThanOrEqual(80);
    expect(c2x! - tx!).toBeGreaterThanOrEqual(80);
    expect([c1y, c2y]).toEqual([sy, ty]);
  });
});
