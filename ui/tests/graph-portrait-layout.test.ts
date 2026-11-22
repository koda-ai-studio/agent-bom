import { expect, it } from "vitest";
import type { Node, Edge } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { graphPortraitLayout } from "@/lib/graph-portrait-layout";

it("keeps the supplied spine connected vertically with its context beside the recorded owner", () => {
  const nodes: Node<LineageNodeData>[] = ["entry", "server", "asset"].map((id, index) => ({ id, position: { x: index * 380, y: 0 },
    data: { label: id, nodeType: "server", semanticLayer: ["user", "mcp_server", "asset"][index], semanticPathIndex: index } }));
  nodes.push({ id: "package", position: { x: 380, y: 240 }, data: { label: "Package", nodeType: "package", semanticLayer: "package", semanticOwner: "server" } });
  const edges: Edge[] = [{ id: "a", source: "entry", target: "server" }, { id: "b", source: "server", target: "asset" }, { id: "c", source: "server", target: "package" }];
  const original = structuredClone({ nodes, edges });
  const result = graphPortraitLayout(nodes, edges);
  const byId = new Map(result.nodes.map(n => [n.id, n]));
  const path = ["entry", "server", "asset"].map(id => byId.get(id)!);
  expect(new Set(path.map(n => n.position.x)).size).toBe(1);
  expect(path[0]!.position.y).toBeLessThan(path[1]!.position.y);
  expect(path[1]!.position.y).toBeLessThan(path[2]!.position.y);
  expect(byId.get("package")!.position.x).toBeGreaterThan(byId.get("server")!.position.x);
  expect(byId.get("package")!.position.y).toBeGreaterThan(byId.get("server")!.position.y);
  expect(result.nodes.every(n => n.position.x + Number(n.style?.width) <= 328)).toBe(true);
  expect(result.edges.map(e => [e.id, e.source, e.target])).toEqual(edges.map(e => [e.id, e.source, e.target]));
  expect({ nodes, edges }).toEqual(original);
});
