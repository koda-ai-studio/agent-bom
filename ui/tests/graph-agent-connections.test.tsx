import { fireEvent, render, screen } from "@testing-library/react";
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
  vi.mocked(useGraphNodeAggregates).mockReturnValue(new Map([[rootId, { node_id: rootId, ...current }]]));
  const findings = vi.fn();
  render(<GraphAgentConnections scanId={graph.scan_id} rootId={rootId} aggregate={{ ...current.aggregate, issue_count: 0 }}
    onInspect={vi.fn()} onFindings={findings} onUnavailable={vi.fn()} />);
  fireEvent.click(await screen.findByRole("button", { name: "Open 1 finding for Developer Copilot" }));
  expect(findings).toHaveBeenCalledWith(rootId, "Developer Copilot", current.aggregate);
});
