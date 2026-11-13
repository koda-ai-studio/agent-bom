import { Position } from "@xyflow/react";
import { describe, expect, it } from "vitest";

import { mcpBranchPath } from "@/lib/graph-mcp-routing";
import { anchoredLabelPoint, relationshipPath } from "@/lib/relationship-routing";

const lr = { source: "a", target: "b", sourcePosition: Position.Right, targetPosition: Position.Left };
const curved = /[CcSsTt]/;

describe("one relationship line style", () => {
  it("draws every routed relationship as straight runs with rounded corners, never a sweeping curve", () => {
    const cases: [string, Parameters<typeof relationshipPath>][] = [
      ["level", [{ ...lr, sourceX: 72, sourceY: 36, targetX: 672, targetY: 36 }, []]],
      ["diagonal", [{ ...lr, sourceX: 72, sourceY: 300, targetX: 672, targetY: 0 }, []]],
      ["detour", [{ ...lr, sourceX: 72, sourceY: 36, targetX: 672, targetY: 36 }, [{ id: "mid", x: 260, y: 0, width: 220, height: 180 }]]],
      ["serpentine", [{ ...lr, targetPosition: Position.Right, sourceX: 300, sourceY: 0, targetX: 300, targetY: 400 },
        [{ id: "a", x: 100, y: -40, width: 220, height: 180 }, { id: "b", x: 100, y: 360, width: 220, height: 180 }]]],
      ["vertical", [{ ...lr, sourcePosition: Position.Bottom, targetPosition: Position.Top, sourceX: 100, sourceY: 0, targetX: 400, targetY: 300 }, []]],
    ];
    for (const [name, args] of cases) expect(relationshipPath(...args)[0], name).not.toMatch(curved);
  });

  it("draws an MCP evidence branch in the same style", () => {
    const branch = mcpBranchPath({ sourceX: 260, sourceY: 40, targetX: 640, targetY: 300 },
      { x: 0, y: 0, width: 260, height: 188 }, { x: 640, y: 260, width: 260, height: 188 });
    expect(branch).not.toBeNull();
    expect(branch![0]).not.toMatch(curved);
  });
});

describe("grouped relationship captions", () => {
  const link = { ...lr, sourceX: 100, sourceY: 50, targetX: 700, targetY: 400 };
  it("sit beside the source port where a fan-out splits", () => {
    const point = anchoredLabelPoint(link, "source");
    expect(point.y).toBe(link.sourceY);
    expect(point.x).toBeGreaterThan(link.sourceX);
    expect(point.x - link.sourceX).toBeLessThanOrEqual(80);
  });
  it("sit beside the target port where a fan-in joins", () => {
    const point = anchoredLabelPoint(link, "target");
    expect(point.y).toBe(link.targetY);
    expect(link.targetX - point.x).toBeLessThanOrEqual(80);
    expect(point.x).toBeLessThan(link.targetX);
  });
});
