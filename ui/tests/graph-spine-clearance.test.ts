import { expect, it } from "vitest";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";
import type { Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";

it("keeps contextual nodes below the top path even in columns without a path hop", () => {
  const nodes: Node<LineageNodeData>[] = [
    ["entry", "user"], ["agent", "orchestration"], ["server", "mcp_server"],
    ["workload", "infra"], ["source", "code"], ["image", "infra"],
  ].map(([id, semanticLayer]) => ({ id: id!, position: { x: 0, y: 0 }, data: { label: id!, nodeType: "container", semanticLayer } }));
  const path = ["entry", "agent", "server"];
  const placed = semanticGraphLayout(nodes, [], path).nodes;
  expect(placed.filter(n => path.includes(n.id)).every(n => n.position.y === 0)).toBe(true);
  expect(placed.filter(n => !path.includes(n.id)).every(n => n.position.y > 0)).toBe(true);
});
