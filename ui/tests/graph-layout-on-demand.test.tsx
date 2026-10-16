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
