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

it("branches an owner's context one rank right, on its owner's row, before unrelated peers", () => {
  const nodes: Node<LineageNodeData>[] = [["entry", "user"], ["a-workload", "infra"], ["b-config", "code"], ["c-source", "code"], ["package", "package"]]
    .map(([id, semanticLayer]) => ({ id: id!, position: { x: 0, y: 0 }, data: { label: id!, nodeType: "container", semanticLayer } }));
  const placed = semanticGraphLayout(nodes, [{ id: "owns", source: "a-workload", target: "package", data: { relationship: "contains" } }], ["entry"]).nodes;
  const at = (id: string) => placed.find(n => n.id === id)!.position;
  expect(at("package").x).toBeGreaterThan(at("a-workload").x);
  expect(at("package").y).toBe(at("a-workload").y);
  expect(at("b-config").y).not.toBe(at("a-workload").y);
});

it("keeps a single layer's owners in one rank with each owner's context beside it", () => {
  const nodes: Node<LineageNodeData>[] = [["z-owner", "code"], ["a-owner", "code"], ["z-package", "package"], ["a-package", "package"]]
    .map(([id, semanticLayer]) => ({ id: id!, position: { x: 0, y: 0 }, data: { label: id!, nodeType: "container", semanticLayer } }));
  const edges = ["z", "a"].map(prefix => ({ id: prefix, source: `${prefix}-owner`, target: `${prefix}-package`, data: { relationship: "contains" } }));
  const placed = semanticGraphLayout(nodes, edges).nodes;
  const pos = (id: string) => placed.find(node => node.id === id)!.position;
  expect(pos("z-owner").x).toBe(pos("a-owner").x);
  for (const prefix of ["z", "a"]) {
    expect(pos(`${prefix}-package`).x).toBeGreaterThan(pos(`${prefix}-owner`).x);
    expect(pos(`${prefix}-package`).y).toBe(pos(`${prefix}-owner`).y);
  }
});
