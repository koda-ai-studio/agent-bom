import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { TraceExplorerPanel } from "@/components/trace-explorer-panel";
import type { TraceExplorerResponse } from "@/lib/api-types";

const { getTraceExplorer } = vi.hoisted(() => ({ getTraceExplorer: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { getTraceExplorer } }));

function fixture(): TraceExplorerResponse {
  const span = (agent: string, tool: string, verdict = "observed") => ({ span_id: tool, agent, tool, verdict, action_type: "tool_call", linked_findings: [], compliance_controls: [] });
  return { schema_version: "1", tenant_id: "tenant", session_count: 2, span_count: 4, blocked_count: 1, sessions: [
    { session_id: "unrelated", agent: "assistant-extra", blocked_count: 0, observed_count: 1, spans: [span("assistant-extra", "unrelated-tool")] },
    { session_id: "mixed", agent: "Assistant", blocked_count: 1, observed_count: 2, spans: [span("Assistant", "wrong-case-tool"), span("assistant", "exact-tool", "blocked"), span("other", "other-tool")] },
  ] };
}
beforeEach(() => { vi.clearAllMocks(); getTraceExplorer.mockResolvedValue(fixture()); });

describe("trace identity and coverage", () => {
  it("matches exact span identities and never selects unrelated session or actors", async () => {
    render(<TraceExplorerPanel agent="assistant" scanId="scan-1" />);
    await screen.findByRole("button", { name: /exact-tool/ });
    expect(getTraceExplorer).toHaveBeenCalledWith(120, "scan-1", { offset: 0, agent_name: "assistant", source: undefined });
    expect(screen.queryByText("unrelated-tool")).not.toBeInTheDocument();
    expect(screen.queryByText("wrong-case-tool")).not.toBeInTheDocument();
    expect(screen.queryByText("other-tool")).not.toBeInTheDocument();
    expect(screen.getByText("1 sessions · 1 blocked spans")).toBeVisible();
    expect(screen.getByText(/requests up to 120 records per source/)).toBeVisible();
    expect(screen.getByText(/Inventory identifiers are checked against snapshot/)).toHaveTextContent("scan-1");
  });
  it("drops selected spans when the requested identity changes", async () => {
    const { rerender } = render(<TraceExplorerPanel agent="assistant" />);
    fireEvent.click(await screen.findByRole("button", { name: /exact-tool/ }));
    rerender(<TraceExplorerPanel agent="other" />);
    await screen.findByRole("button", { name: /other-tool/ });
    expect(screen.queryByText("exact-tool")).not.toBeInTheDocument();
    rerender(<TraceExplorerPanel agent="absent" />);
    expect(await screen.findByText(/No activity matched this agent/)).toBeVisible();
    expect(screen.queryByText("other-tool")).not.toBeInTheDocument();
  });
  it("does not equate an empty bounded sample with no activity", async () => {
    getTraceExplorer.mockResolvedValue({ ...fixture(), sessions: [] });
    render(<TraceExplorerPanel />);
    expect(await screen.findByText(/No runtime activity records were returned/)).toHaveTextContent("does not prove that no activity occurred");
  });
  it("distinguishes unavailable activity from an empty sample", async () => {
    getTraceExplorer.mockRejectedValue(new Error("temporarily unavailable"));
    render(<TraceExplorerPanel agent="assistant" />);
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("Activity unavailable"));
    expect(screen.queryByText(/No activity matched/)).not.toBeInTheDocument();
  });
});

it("keeps native hierarchy, uncertainty and collection history visible without claiming an exact join", async () => {
  const data = fixture();
  data.sessions = [{ session_id: "native", blocked_count: 0, observed_count: 1, spans: [{
    span_id: "scoped-native-child", agent: "", tool: "lookup", action_type: "native_span", verdict: "success",
    linked_findings: [], compliance_controls: [], surface: "imported_trace", native_type: "TOOL", native_name: "Retrieve invoices",
    depth: 1, parent_span_id: "scoped-parent", parent_state: "missing", logical_root: true, event_time_missing: true,
    source_scope: { provider: "langfuse", project_id: "project-a", environment: "test" }, correlation_state: "unmapped",
  }] }];
  getTraceExplorer.mockResolvedValue(data);
  render(<TraceExplorerPanel />);
  expect(await screen.findByRole("button", { name: /Retrieve invoices/ })).toHaveTextContent("Parent outside this sample");
  expect(screen.getByText(/does not prove exploitation/)).toBeVisible();
  expect(screen.getByText(/No verified inventory-to-finding mapping/)).toBeVisible();
  fireEvent.click(screen.getByText("Source and parent evidence"));
  expect(screen.getByText("project-a")).toBeVisible();
  expect(screen.getByText("scoped-parent")).toBeVisible();
  fireEvent.click(screen.getByText("Collection history"));
  expect(screen.getByRole("button", { name: "Load revisions" })).toBeVisible();
});


it("pages retained observations and applies source filters on the server", async () => {
  getTraceExplorer.mockResolvedValue({ ...fixture(), retained_total: 241, offset: 0, limit: 120, has_more: true, source_counts: { langsmith: 241 } });
  render(<TraceExplorerPanel />);
  fireEvent.click(await screen.findByRole("button", { name: "Next activity page" }));
  await waitFor(() => expect(getTraceExplorer).toHaveBeenLastCalledWith(120, undefined, { offset: 120, agent_name: undefined, source: undefined }));
  fireEvent.change(screen.getByRole("combobox", { name: "Activity source" }), { target: { value: "langsmith" } });
  await waitFor(() => expect(getTraceExplorer).toHaveBeenLastCalledWith(120, undefined, { offset: 0, agent_name: undefined, source: "langsmith" }));
});

it("shows the recorded package path separately from execution evidence", async () => {
  const data = fixture();
  data.sessions[0]!.spans[0] = { ...data.sessions[0]!.spans[0]!, surface: "imported_trace", inventory_binding: {
    state: "exact_identifier", node_id: "agent:exact", scan_id: "scan/one", execution_proven: false,
    inventory_paths: [{ node_ids: ["agent:exact", "package:occurrence", "vulnerability:exact"], edge_ids: ["edge1", "edge2"], node_labels: ["Agent", "Installed package", "Recorded vulnerability"], finding_node_id: "vulnerability:exact", execution_proven: false, basis: "recorded_inventory_relationships" }],
  } };
  getTraceExplorer.mockResolvedValue(data);
  render(<TraceExplorerPanel />);
  expect(await screen.findByText("Agent → Installed package → Recorded vulnerability")).toBeVisible();
  expect(screen.getByText(/Inventory relationships do not prove/)).toBeVisible();
  expect(screen.getByRole("link", { name: "Inspect recorded finding path" })).toHaveAttribute("href", expect.stringContaining("scan=scan%2Fone"));
});
