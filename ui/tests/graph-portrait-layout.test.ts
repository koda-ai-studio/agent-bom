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
  // A branch sits in a row of up to two under the hop it connects to, clear of the trunk line.
  expect(byId.get("package")!.position.x).not.toBe(byId.get("server")!.position.x);
  expect(byId.get("package")!.position.y).toBeGreaterThan(byId.get("server")!.position.y);
  expect(byId.get("package")!.position.y).toBeLessThan(byId.get("asset")!.position.y);
  expect(result.nodes.every(n => n.position.x + Number(n.style?.width) <= 328)).toBe(true);
  expect(result.edges.map(e => [e.id, e.source, e.target])).toEqual(edges.map(e => [e.id, e.source, e.target]));
  expect({ nodes, edges }).toEqual(original);
});

it("routes long portrait links along the glyph side, away from names and intervening nodes", () => {
  const nodes: Node<LineageNodeData>[] = ["a", "b", "c"].map((id, index) => ({ id, position: { x: 0, y: 0 },
    data: { label: id, nodeType: "server", semanticLayer: "mcp_server", semanticPathIndex: index } }));
  const result = graphPortraitLayout(nodes, [{ id: "long", source: "a", target: "c" }, { id: "hop", source: "a", target: "b" }]);
  expect(result.edges[0]).toMatchObject({ sourceHandle: "phone-left", targetHandle: "phone-left" });
  expect(result.edges[1]).toMatchObject({ sourceHandle: null, targetHandle: null });
});

it("puts a lone branch in the right column so its caption faces into the canvas, never off its left edge", () => {
  const nodes: Node<LineageNodeData>[] = [
    { id: "agent", position: { x: 0, y: 0 }, data: { label: "Developer Copilot", nodeType: "agent", semanticLayer: "orchestration", semanticPathIndex: 0 } },
    ...["filesystem", "github"].map(id => ({ id, position: { x: 0, y: 0 }, data: { label: id, nodeType: "server" as const, semanticLayer: "mcp_server" } })),
    { id: "peer", position: { x: 0, y: 0 }, data: { label: "SRE Runbook Agent", nodeType: "agent", semanticLayer: "orchestration" } },
  ];
  const edges: Edge[] = [["agent", "filesystem"], ["agent", "github"], ["peer", "filesystem"]].map(([source, target]) => ({ id: `${source}-${target}`, source: source!, target: target! }));
  const result = graphPortraitLayout(nodes, edges);
  const peer = result.nodes.find(n => n.id === "peer")!;
  expect(peer.data.phoneSide).toBe("right");
  // Its link to the server above crosses the centre gap: no same-side loop around the column.
  const link = result.edges.find(e => e.id === "peer-filesystem")!;
  expect(link.sourceHandle).not.toBe(link.targetHandle);
});
