import { renderHook, waitFor } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { get } from "@/lib/api-transport";
import { useGraphNodeAggregates } from "@/lib/graph-node-aggregates";
vi.mock("@/lib/api-transport", () => ({ get: vi.fn() }));
beforeEach(() => vi.mocked(get).mockReset());
const row = { node_id: "node:a", semantic_layer: "app", aggregate: { issue_count: 37, worst_severity: "high", exposed_count: 4 } };
it("requests the selected hops in one snapshot-pinned batch and keeps backend totals", async () => {
  vi.mocked(get).mockResolvedValue({ scan_id: "scan", snapshot_generation: "revision", aggregates: [row], missing_node_ids: ["node:b"] });
  const { result, rerender } = renderHook(({ hops }) => useGraphNodeAggregates("scan", hops, "revision"), { initialProps: { hops: ["node:a", "node:b"] } });
  await waitFor(() => expect(result.current.get("node:a")?.aggregate.issue_count).toBe(37));
  const url = new URL(vi.mocked(get).mock.calls[0]![0], "https://example.test");
  expect(url.pathname).toBe("/v1/graph/node-aggregates");
  expect(url.searchParams.getAll("node_id")).toEqual(["node:a", "node:b"]);
  expect(url.searchParams.get("scan_id")).toBe("scan");
  expect(url.searchParams.get("snapshot_generation")).toBe("revision");
  expect(result.current.has("node:b")).toBe(false);
  rerender({ hops: ["node:a", "node:b"] });
  expect(get).toHaveBeenCalledTimes(1);
});
it("hides old aggregates immediately when the path snapshot changes", async () => {
  vi.mocked(get).mockResolvedValueOnce({ scan_id: "first", aggregates: [row], missing_node_ids: [] }).mockImplementationOnce(() => new Promise(() => {}));
  const { result, rerender } = renderHook(({ scan }) => useGraphNodeAggregates(scan, ["node:a"]), { initialProps: { scan: "first" } });
  await waitFor(() => expect(result.current.size).toBe(1));
  rerender({ scan: "second" });
  expect(result.current.size).toBe(0);
});
it("shows no computed fallback for failed reads or a different snapshot", async () => {
  vi.mocked(get).mockResolvedValue({ scan_id: "other", aggregates: [row], missing_node_ids: [] });
  const { result } = renderHook(() => useGraphNodeAggregates("scan", ["node:a"]));
  await waitFor(() => expect(get).toHaveBeenCalledTimes(1));
  expect(result.current.size).toBe(0);
});
it("does not send an unbounded hop list", () => {
  const { result } = renderHook(() => useGraphNodeAggregates("scan", Array.from({ length: 26 }, (_, i) => `node:${i}`)));
  expect(get).not.toHaveBeenCalled();
  expect(result.current.size).toBe(0);
});

import { buildAttackPathGraphModel } from "@/lib/attack-path-graph-model";
import { branchingFixture } from "./fixtures/attack-path-graph-fixture";
import type { GraphNodeAggregate } from "@/lib/graph-node-aggregates";
it("passes authoritative aggregates through the selected-path model without counting adjacent findings", () => {
  const { graph, selected } = branchingFixture();
  const nodeId = selected.hops[0]!;
  const aggregate = { ...row, node_id: nodeId } as GraphNodeAggregate;
  const model = buildAttackPathGraphModel(graph, selected, { nodeAggregates: new Map([[nodeId, aggregate]]) });
  expect(model.nodes.find(node => node.id === nodeId)?.aggregate?.issue_count).toBe(37);
  expect(model.nodes.find(node => node.id === selected.hops[1])?.aggregate).toBeUndefined();
});

import { render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { AttackPathGraphNode } from "@/components/attack-path-graph-node";
it("renders backend count and severity even when only one finding is loaded", () => {
  const { graph, selected } = branchingFixture();
  const nodeId = selected.hops[0]!;
  const model = buildAttackPathGraphModel(graph, selected, { nodeAggregates: new Map([[nodeId, { ...row, node_id: nodeId } as GraphNodeAggregate]]) });
  const node = { ...model.nodes.find(node => node.id === nodeId)!, findings: [{ id: "one", label: "One", severity: "low" }] };
  render(<ReactFlowProvider><AttackPathGraphNode id={node.id} data={{ node, vertical: false, onOpenFindings: vi.fn(), onExpandGroup: vi.fn() }}
    type="attackPathNode" selected={false} dragging={false} draggable={false} selectable deletable={false} zIndex={0} isConnectable={false} positionAbsoluteX={0} positionAbsoluteY={0} /></ReactFlowProvider>);
  const badge = screen.getByRole("button", { name: /Findings \(37\)/ });
  expect(badge).toHaveAttribute("data-severity", "high");
  expect(screen.getByText("4 exposed entities")).toBeInTheDocument();
});
