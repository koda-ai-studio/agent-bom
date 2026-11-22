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

it("connects nodes in one semantic column on the same outside edge", () => {
  const nodes: Node<LineageNodeData>[] = ["job", "config", "workload"].map(id => ({ id, position: { x: 0, y: 0 },
    data: { label: id, nodeType: "container", semanticLayer: "infra" } }));
  const links = [{ id: "down", source: "job", target: "workload" }, { id: "up", source: "config", target: "job" }];
  const result = semanticGraphLayout(nodes, links);
  for (const edge of result.edges) expect(edge).toMatchObject({ sourceHandle: null, targetHandle: "context" });
});

it("reserves an owner's context rows before placing unrelated peers in the same layer", () => {
  const nodes: Node<LineageNodeData>[] = [["entry", "user"], ["a-workload", "infra"], ["b-config", "code"], ["c-source", "code"], ["package", "package"]]
    .map(([id, semanticLayer]) => ({ id: id!, position: { x: 0, y: 0 }, data: { label: id!, nodeType: "container", semanticLayer } }));
  const placed = semanticGraphLayout(nodes, [{ id: "owns", source: "a-workload", target: "package", data: { relationship: "contains" } }], ["entry"]).nodes;
  const y = (id: string) => placed.find(n => n.id === id)!.position.y;
  expect(y("package")).toBeGreaterThan(y("a-workload"));
  expect(y("package")).toBeLessThan(y("b-config"));
});
