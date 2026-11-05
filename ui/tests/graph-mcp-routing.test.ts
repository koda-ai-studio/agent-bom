import { expect, it } from "vitest";
import { mcpBranchPath } from "@/lib/graph-mcp-routing";

const source = { x: 0, y: 96, width: 260, height: 188 };
const target = { x: 368, y: 320, width: 260, height: 188 };
const edge = { sourceX: 166, sourceY: 132, targetX: 462, targetY: 356 };

it("keeps branch endpoints and puts the relationship label on the smooth curve", () => {
  const [path, x, y] = mcpBranchPath(edge, source, target)!;
  expect(path.startsWith("M166,132 C")).toBe(true);
  expect(path.endsWith("462,356")).toBe(true);
  expect(x).toBeGreaterThan(edge.sourceX);
  expect(x).toBeLessThan(edge.targetX);
  expect(y).toBeGreaterThan(edge.sourceY);
  expect(y).toBeLessThan(edge.targetY);
  expect(mcpBranchPath(edge, source, target, [{ x: x - 20, y: y - 20, width: 40, height: 40 }])).toBeNull();
});

it("keeps direct finding connections above the main chain and leaves reverse links to their directional router", () => {
  const far = { ...target, x: 1104, y: 96 };
  const direct = { ...edge, targetX: 1234, targetY: 132 };
  const between = { x: 500, y: 96, width: 260, height: 188 };
  expect(mcpBranchPath(direct, source, far, [between])![2]).toBeLessThan(source.y);
  expect(mcpBranchPath(direct, source, far)![2]).toBe(direct.sourceY);
  expect(mcpBranchPath(direct, source, far, [{ ...between, y: 600 }])![2]).toBe(direct.sourceY);
  expect(mcpBranchPath(edge, target, source)).toBeNull();
  expect(mcpBranchPath({ ...edge, sourceX: NaN }, source, target)).toBeNull();
});
