import { describe, expect, it } from "vitest";
import type { Edge, Node } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { peerPreviewLayout } from "@/lib/graph-peer-preview-layout";

describe("named peer preview layout", () => {
  const nodes: Node<LineageNodeData>[] = ["root", "c", "a", "b", "rest"].map(id => ({
    id, type: id === "rest" ? "clusterPillNode" : "serverNode", position: { x: 0, y: 0 }, data: { label: id, nodeType: "server" },
  }));
  const edges: Edge[] = nodes.slice(1).map(n => ({ id: n.id, source: "root", target: n.id, data: { relationship: "uses", traversable: false } }));
  it("centres the parent between distinct branches and preserves every canonical link", () => {
    const result = peerPreviewLayout(nodes, edges)!;
    const children = result.nodes.filter(n => n.id !== "root");
    expect(new Set(children.map(n => n.position.y)).size).toBe(4);
    expect(result.nodes.find(n => n.id === "root")?.position.y).toBe(330);
    expect(result.nodes.find(n => n.id === "rest")?.position.y).toBe(660);
    expect(result.edges.map(e => [e.id, e.source, e.target, e.data?.traversable])).toEqual(edges.map(e => [e.id, e.source, e.target, false]));
    expect(result.edges.every(e => e.data?.quietLabel === true)).toBe(true);
  });
  it("leaves joined or cyclic graphs to the full hierarchy layout", () => {
    expect(peerPreviewLayout(nodes, [...edges, { id: "back", source: "a", target: "root" }])).toBeNull();
    expect(peerPreviewLayout(nodes, edges.map(e => e.id === "b" ? { ...e, source: "a" } : e))).toBeNull();
  });
});
