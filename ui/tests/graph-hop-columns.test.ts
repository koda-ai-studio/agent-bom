import type { Edge, Node } from "@xyflow/react";
import { describe, expect, it } from "vitest";

import type { LineageNodeData } from "@/components/lineage-nodes";
import { hopColumnLayout } from "@/lib/graph-hop-columns";

const node = (id: string, x = 0, y = 0): Node<LineageNodeData> => ({ id, position: { x, y }, data: { label: id, nodeType: "package" } });
const edge = (source: string, target: string): Edge => ({ id: `${source}->${target}`, source, target });
const OPTIONS = { columnGap: 360, rowGap: 380 };

/** The first-run preview: one hop from the agent to its server and finding, two to the server's packages. */
const nodes = [node("bot", 0, 0), node("server", 400, -190), node("finding", 400, 190),
  node("werkzeug", 800, -190), node("flask", 1200, 0), node("requests", 800, 190)];
const edges = [edge("bot", "server"), edge("bot", "finding"), edge("server", "werkzeug"), edge("server", "flask"), edge("server", "requests"), edge("flask", "requests")];

describe("connection preview columns", () => {
  it("puts every node at the same hop distance from the start in one column", () => {
    const placed = new Map(hopColumnLayout(nodes, edges, "bot", OPTIONS).map(item => [item.id, item.position]));
    expect(placed.get("bot")!.x).toBe(0);
    expect(new Set(["server", "finding"].map(id => placed.get(id)!.x))).toEqual(new Set([OPTIONS.columnGap]));
    expect(new Set(["werkzeug", "flask", "requests"].map(id => placed.get(id)!.x))).toEqual(new Set([2 * OPTIONS.columnGap]));
  });

  it("stacks a column at an even row rhythm, centred on the start node, with no two cards on one row", () => {
    const placed = hopColumnLayout(nodes, edges, "bot", OPTIONS);
    const column = placed.filter(item => item.position.x === 2 * OPTIONS.columnGap).map(item => item.position.y).sort((a, b) => a - b);
    expect(column).toEqual([-OPTIONS.rowGap, 0, OPTIONS.rowGap]);
  });

  it("orders a column by its parents so lines into it do not cross", () => {
    const placed = new Map(hopColumnLayout(nodes, edges, "bot", OPTIONS).map(item => [item.id, item.position]));
    // The server's children sit level with or after the server, never above the finding's row order.
    expect(placed.get("server")!.y).toBeLessThan(placed.get("finding")!.y);
  });

  it("reads top to bottom on a phone: each hop is one row, so the preview stacks inside a narrow frame", () => {
    const placed = new Map(hopColumnLayout(nodes, edges, "bot", { ...OPTIONS, vertical: true }).map(item => [item.id, item.position]));
    expect(placed.get("bot")!.y).toBe(0);
    expect(new Set(["server", "finding"].map(id => placed.get(id)!.y))).toEqual(new Set([OPTIONS.rowGap]));
    expect(new Set(["werkzeug", "flask", "requests"].map(id => placed.get(id)!.y))).toEqual(new Set([2 * OPTIONS.rowGap]));
    // A two-node phone preview is one column: start above its neighbour.
    const pair = hopColumnLayout(nodes.slice(0, 2), edges, "bot", { ...OPTIONS, vertical: true });
    expect(new Set(pair.map(item => item.position.x)).size).toBe(1);
  });

  it("places a node unreachable from the start in a column after the reachable ones", () => {
    const placed = new Map(hopColumnLayout([...nodes, node("loose")], edges, "bot", OPTIONS).map(item => [item.id, item.position]));
    expect(placed.get("loose")!.x).toBe(3 * OPTIONS.columnGap);
  });
});
