import { act, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
  expect(screen.getByRole("link", { name: "Explore upstream relationships" })).toHaveAttribute("href", "/security-graph?scan=scan-a&investigate=1&root=finding%3Aa&direction=reverse&depth=4&lens=lineage");
});

it("labels reverse traversal depth so it is not read as the selected path's hop count", async () => {
  vi.spyOn(api, "getGraphImpact").mockResolvedValue({ ...result, completeness: { complete: true }, max_depth_reached: 1 } as typeof result);
  render(<GraphPathImpact {...props} />);
  const summary = await screen.findByText(/upstream related nodes/);
  expect(summary).toHaveTextContent("3 upstream related nodes · up to 1 reverse step from this node");
  expect(summary).not.toHaveTextContent(/recorded hops/);
  expect(screen.getByText(/Traversal depth is counted from this node, not along the selected path/)).toBeInTheDocument();
});

type DetailNode = { id: string; label: string; entity_type: string; depth: number };
const detailed = (direction: "reverse" | "forward", nodes: DetailNode[]) => ({
  ...result, completeness: { complete: true }, direction, affected_nodes: nodes.map(node => node.id), affected_count: nodes.length,
  affected_by_type: nodes.reduce<Record<string, number>>((acc, node) => ({ ...acc, [node.entity_type]: (acc[node.entity_type] ?? 0) + 1 }), {}),
  max_depth_reached: Math.max(...nodes.map(node => node.depth)), affected_nodes_detail: nodes,
}) as GraphImpactResponse;

it("opens each count as a list of its nodes, nearest first, each linking to its own lineage", async () => {
  const read = vi.spyOn(api, "getGraphImpact").mockResolvedValue(detailed("reverse", [
    { id: "pkg:p", label: "pillow@9.0.0", entity_type: "package", depth: 1 },
    { id: "agent:a", label: "data-pipeline", entity_type: "agent", depth: 3 },
  ]));
  render(<GraphPathImpact {...props} />);
  fireEvent.click(await screen.findByRole("button", { name: /Agent · 1/ }));
  const list = screen.getByRole("list", { name: "Agent nodes" });
  const link = within(list).getByRole("link", { name: /data-pipeline/ });
  expect(link.getAttribute("href")).toContain("root=agent%3Aa");
  expect(within(list).getByText(/3 steps/)).toBeVisible();
  expect(read).toHaveBeenCalledWith("finding:a", "scan-a", 4, expect.anything(), "reverse");
});

it("toggles to downstream — what this can reach — at the same depth", async () => {
  const read = vi.spyOn(api, "getGraphImpact").mockImplementation((_node, _scan, _depth, _options, direction) =>
    Promise.resolve(direction === "forward"
      ? detailed("forward", [{ id: "cred:c", label: "API_KEY", entity_type: "credential", depth: 2 }])
      : detailed("reverse", [{ id: "agent:a", label: "data-pipeline", entity_type: "agent", depth: 1 }])));
  render(<GraphPathImpact {...props} />);
  await screen.findByRole("button", { name: /Agent · 1/ });
  fireEvent.click(screen.getByRole("radio", { name: /Downstream/ }));
  expect(await screen.findByRole("button", { name: /Credential · 1/ })).toBeVisible();
  expect(read).toHaveBeenLastCalledWith("finding:a", "scan-a", 4, expect.anything(), "forward");
  expect(screen.getByText(/downstream node this can reach/)).toBeVisible();
  const explore = screen.getByRole("link", { name: "Explore downstream relationships" });
  expect(new URL(explore.getAttribute("href")!, "http://x").searchParams.get("direction")).toBe("forward");
});

it("answers the AppSec question for a finding root: what this finding exposes, selected by default", async () => {
  vi.spyOn(api, "getGraphImpact").mockResolvedValue({ ...result, completeness: { complete: true } } as typeof result);
  render(<GraphPathImpact {...props} findingRoot />);
  expect(await screen.findByText(/3 assets exposed to this finding/)).toBeVisible();
  expect(screen.getByRole("radio", { name: "Exposed · what runs or reaches this finding" })).toHaveAttribute("aria-checked", "true");
  expect(screen.getByRole("radio", { name: "Linked · records this finding points to" })).toHaveAttribute("aria-checked", "false");
  expect(screen.queryByText(/upstream/i)).toBeNull();
});
