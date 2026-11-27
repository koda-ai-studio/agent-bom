import { MarkerType, type Node } from "@xyflow/react";
import { expect, it } from "vitest";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { semanticGraphLayout } from "@/lib/graph-semantic-layout";

it("preserves zoom-compensated arrow geometry through semantic layout", () => {
  const nodes: Node<LineageNodeData>[] = [
    { id: "server", position: { x: 0, y: 0 }, data: { label: "Server", nodeType: "server", semanticLayer: "mcp_server" } },
    { id: "tool", position: { x: 0, y: 0 }, data: { label: "Tool", nodeType: "tool", semanticLayer: "tool" } },
  ];
  const marker = { type: MarkerType.ArrowClosed, width: 48, height: 40, markerUnits: "userSpaceOnUse" };
  const result = semanticGraphLayout(nodes, [{ id: "provides", source: "server", target: "tool", markerEnd: marker, data: { relationship: "provides_tool" } }]);
  expect(result.edges[0]!.markerEnd).toMatchObject(marker);
});
