import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { expect, it, vi } from "vitest";
import { GraphAgentConnections } from "@/components/graph-agent-connections";
import { api } from "@/lib/api";
import { useGraphNodeAggregates } from "@/lib/graph-node-aggregates";
import { buildGraph } from "../scripts/product-proof-graph.mjs";
import fixture from "./fixtures/product-proof-rollup.json";

vi.mock("@/lib/api", () => ({ api: { queryGraph: vi.fn(), getGraph: vi.fn() } }));
vi.mock("@/lib/graph-node-aggregates", () => ({ useGraphNodeAggregates: vi.fn() }));
vi.mock("@/hooks/use-narrow-viewport", () => ({ useNarrowViewport: () => true }));
vi.mock("@/lib/static-demo", () => ({ isStaticDemo: () => false }));

it("uses the same refreshed count for the mobile badge and its disclosure", async () => {
  const graph = buildGraph() as unknown as Awaited<ReturnType<typeof api.queryGraph>>;
  const rootId = "agent:developer-copilot";
  const current = fixture.node_aggregates[rootId];
  vi.mocked(api.queryGraph).mockResolvedValue(graph);
  vi.mocked(useGraphNodeAggregates).mockReturnValue(new Map([[rootId, { node_id: rootId, ...current,
    finding_disclosure: {issue_count: current.aggregate.issue_count, severity_counts: current.aggregate.severity_counts, exclude_node_ids: []} }]]));
  const findings = vi.fn(); const inspect = vi.fn();
  const { rerender } = render(<GraphAgentConnections scanId={graph.scan_id} rootId={rootId} aggregate={{ ...current.aggregate, issue_count: 0 }}
    onInspect={inspect} onFindings={findings} onUnavailable={vi.fn()} />);
  fireEvent.click(await screen.findByRole("button", { name: "Open 1 finding for Developer Copilot" }));
  expect(findings).toHaveBeenCalledWith(rootId, "Developer Copilot", current.aggregate, []);
  expect(screen.getByText("Shared MCP server: filesystem MCP. Expand it to inspect tools and access evidence.")).toBeVisible();
  expect(screen.getByRole("button", { name: "Internet-exposed: copilot-portal:2.4.0" })).toBeVisible();
  fireEvent.click(screen.getByText("Recorded tool control context (1)"));
  fireEvent.click(within(screen.getByText("Recorded tool control context (1)").closest("details")!).getByRole("button", { name: "execute_command" }));
  expect(inspect).toHaveBeenCalledWith("tool:exec", "execute_command");
  expect(screen.getByText("default-deny gateway policy")).toBeVisible();
  rerender(<GraphAgentConnections scanId={graph.scan_id} rootId={rootId} generation="refreshed" aggregate={current.aggregate}
    onInspect={inspect} onFindings={findings} onUnavailable={vi.fn()} />);
  await waitFor(() => expect(api.queryGraph).toHaveBeenCalledTimes(2));
  expect(await screen.findByRole("button", { name: "default-deny gateway policy" })).toBeVisible();
});
