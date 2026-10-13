import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { GraphPathImpact } from "@/components/graph-path-impact";
import { api } from "@/lib/api";
import type { GraphImpactResponse } from "@/lib/api-types";

const props = { nodeId: "finding:a", label: "Finding A", scanId: "scan-a", tenantId: "tenant-a", snapshotGeneration: "generation-a" };
const result = { node_id: props.nodeId, scan_id: props.scanId, tenant_id: props.tenantId, snapshot_generation: props.snapshotGeneration,
  affected_count: 3, affected_nodes: ["a", "b", "c"], affected_by_type: { agent: 3 }, max_depth_reached: 2, completeness: { status: "truncated", complete: false, sampled: false, truncated: true, returned: 3 } } as GraphImpactResponse;
afterEach(() => vi.restoreAllMocks());

it.each(["node_id", "scan_id", "tenant_id", "snapshot_generation"] as const)("rejects impact from a different %s", async field => {
  vi.spyOn(api, "getGraphImpact").mockResolvedValue({ ...result, [field]: "other" });
  render(<GraphPathImpact {...props} />);
  await screen.findByRole("alert");
  expect(screen.queryByText(/3 upstream related nodes/)).not.toBeInTheDocument();
});

it("discards a delayed result after changing the selected finding", async () => {
  let complete!: (value: GraphImpactResponse) => void;
  vi.spyOn(api, "getGraphImpact").mockImplementationOnce(() => new Promise(resolve => { complete = resolve; })).mockResolvedValueOnce({ ...result, node_id: "finding:b", affected_count: 1 });
  const { rerender } = render(<GraphPathImpact {...props} />);
  rerender(<GraphPathImpact {...props} nodeId="finding:b" label="Finding B" />);
  await screen.findByText(/At least 1 upstream related node/);
  await act(async () => complete(result));
  expect(screen.queryByText(/3 upstream related nodes/)).not.toBeInTheDocument();
});

it("retries failed evidence without treating failure as zero impact", async () => {
  const read = vi.spyOn(api, "getGraphImpact").mockRejectedValueOnce(new Error("private connection string")).mockResolvedValueOnce(result);
  render(<GraphPathImpact {...props} />);
  await screen.findByRole("alert");
  expect(screen.queryByText(/private connection string/)).not.toBeInTheDocument();
  fireEvent.click(screen.getByRole("button", { name: "retry impact" }));
  await waitFor(() => expect(read).toHaveBeenCalledTimes(2));
  expect(await screen.findByText(/At least 3 upstream related nodes/)).toBeVisible();
  expect(screen.getByRole("link", { name: "Explore upstream relationships" })).toHaveAttribute("href", "/security-graph?scan=scan-a&investigate=1&root=finding%3Aa&direction=reverse&lens=lineage");
});

it("labels reverse traversal depth so it is not read as the selected path's hop count", async () => {
  vi.spyOn(api, "getGraphImpact").mockResolvedValue({ ...result, completeness: { complete: true }, max_depth_reached: 1 } as typeof result);
  render(<GraphPathImpact {...props} />);
  const summary = await screen.findByText(/upstream related nodes/);
  expect(summary).toHaveTextContent("3 upstream related nodes · up to 1 reverse step from this node");
  expect(summary).not.toHaveTextContent(/recorded hops/);
  expect(screen.getByText(/Traversal depth is counted from this node, not along the selected path/)).toBeInTheDocument();
});
