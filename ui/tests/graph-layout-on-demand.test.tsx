import { renderHook } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import * as dagre from "@/lib/dagre-layout";
import { useGraphLayout } from "@/lib/use-graph-layout";

it("does no Dagre work for a summary or a renderer that owns its layout, and resumes on demand", () => {
  const nodes = [{ id: "a", data: {}, position: { x: 0, y: 0 } }, { id: "b", data: {}, position: { x: 0, y: 0 } }];
  const edges = [{ id: "a-b", source: "a", target: "b" }];
  const layout = vi.spyOn(dagre, "applyDagreLayout");
  const { result, rerender } = renderHook(({ enabled }) => useGraphLayout("dagre-lr", nodes, edges, {}, enabled), { initialProps: { enabled: false } });
  expect(layout).not.toHaveBeenCalled();
  expect(result.current.nodes).toBe(nodes);
  expect(result.current.edges).toBe(edges);
  expect(result.current.pending).toBe(false);
  rerender({ enabled: true });
  expect(layout).toHaveBeenCalledTimes(1);
  expect(result.current.nodes[0]!.position).not.toEqual(result.current.nodes[1]!.position);
  layout.mockRestore();
});


it("does no unused Dagre work for a bounded peer preview and resumes for a general graph", () => {
  const peers = ["root", "a", "b", "c", "rest"].map(id => ({
    id, type: id === "rest" ? "clusterPillNode" : "agentNode",
    position: { x: 0, y: 0 }, data: { label: id, nodeType: "agent" },
  }));
  const links = peers.slice(1).map(node => ({ id: node.id, source: "root", target: node.id }));
  const layout = vi.spyOn(dagre, "applyDagreLayout");
  try {
    const { result, rerender } = renderHook(({ edges }) => useGraphLayout("dagre-lr", peers, edges), { initialProps: { edges: links } });
    expect(layout).not.toHaveBeenCalled();
    expect(result.current.nodes.filter(node => node.id !== "root").map(node => node.position.y)).toEqual([0, 272, 544, 816]);
    expect(result.current.edges).toHaveLength(4);
    rerender({ edges: [...links, { id: "a-b", source: "a", target: "b" }] });
    expect(layout).toHaveBeenCalledTimes(1);
    expect(result.current.edges).toHaveLength(5);
  } finally { layout.mockRestore(); }
});
