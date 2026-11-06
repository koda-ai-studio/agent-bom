import { act, renderHook } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { Node, NodeChange } from "@xyflow/react";
import type { LineageNodeData } from "@/components/lineage-nodes";
import { useDisplayNodeMeasurements } from "@/hooks/use-display-node-measurements";

type N = Node<LineageNodeData>;
const asset: N = { id: "asset", position: { x: 0, y: 0 }, data: { label: "asset", nodeType: "container" } };
const group: N = { id: "display:findings:asset", position: { x: 370, y: 0 }, data: { label: "Findings", nodeType: "misconfiguration", displayOnly: true } };
const dimensions = (id: string, width: number): NodeChange<N> => ({ id, type: "dimensions", dimensions: { width, height: 180 } });

describe("useDisplayNodeMeasurements", () => {
  it("forwards canonical changes and keeps display nodes out of the persisted layout", () => {
    const persist = vi.fn();
    const { result } = renderHook(() => useDisplayNodeMeasurements([asset, group], persist));
    act(() => result.current.onNodesChange([dimensions("asset", 300), dimensions(group.id, 240), { id: group.id, type: "position", position: { x: 9, y: 9 } }]));
    expect(persist).toHaveBeenCalledTimes(1);
    expect(persist.mock.calls[0]![0].map((change: { id: string }) => change.id)).toEqual(["asset"]);
  });

  it("applies a display node's measurement so React Flow can draw its edges", () => {
    const { result } = renderHook(() => useDisplayNodeMeasurements([asset, group], vi.fn()));
    expect(result.current.nodes.find(n => n.id === group.id)?.measured).toBeUndefined();
    act(() => result.current.onNodesChange([dimensions(group.id, 240)]));
    expect(result.current.nodes.find(n => n.id === group.id)?.measured).toEqual({ width: 240, height: 180 });
    expect(result.current.nodes.find(n => n.id === "asset")?.measured).toBeUndefined();
  });

  it("does not call the persistence handler at all for display-only changes", () => {
    const persist = vi.fn();
    const { result } = renderHook(() => useDisplayNodeMeasurements([asset, group], persist));
    act(() => result.current.onNodesChange([dimensions(group.id, 240)]));
    expect(persist).not.toHaveBeenCalled();
  });

  it("drops the measurement of a display node that has gone", () => {
    const { result, rerender } = renderHook(({ nodes }) => useDisplayNodeMeasurements(nodes, vi.fn()), { initialProps: { nodes: [asset, group] } });
    act(() => result.current.onNodesChange([dimensions(group.id, 240)]));
    const other: N = { ...group, id: "display:findings:other" };
    rerender({ nodes: [asset, other] });
    act(() => result.current.onNodesChange([dimensions(other.id, 200)]));
    expect(result.current.nodes.find(n => n.id === other.id)?.measured).toEqual({ width: 200, height: 180 });
    rerender({ nodes: [asset, group] });
    expect(result.current.nodes.find(n => n.id === group.id)?.measured).toBeUndefined();
  });
});
