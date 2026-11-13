import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AgentArchitectureView } from "@/components/agent-architecture/architecture-view";
import type { ArchitecturePagesState } from "@/lib/agent-architecture-pages";
import { agentByLabel, architecturePages, supervisorHarness, toolTeamHarness, wideCrew } from "./fixtures/agent-architecture-fixture";
import { COLLAPSE_AFTER } from "@/lib/agent-architecture-model";

const neighbors = vi.fn(async (nodeId: string) => {
  const findings = [{ id: "vuln:CVE-2026-0001", label: "CVE-2026-0001", severity: "high" }, { id: "vuln:CVE-2026-0002", label: "CVE-2026-0002", severity: "medium" }];
  return {
    node_id: nodeId, found: true, truncated: false, total_neighbors: 3,
    neighbors: [...findings.map(item => ({ ...item, entity_type: "vulnerability" })), { id: "server:tickets", label: "tickets", entity_type: "server", severity: "" }],
    edges: [...findings.map(item => ({ source: nodeId, target: item.id, relationship: "vulnerable_to" })), { source: nodeId, target: "server:tickets", relationship: "uses" }],
  };
});
vi.mock("@/lib/api", () => ({ api: { getGraphNodeNeighbors: (nodeId: string) => neighbors(nodeId) } }));

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});
afterEach(cleanup);

function state(overrides: Partial<ArchitecturePagesState> = {}): ArchitecturePagesState {
  const page = architecturePages().first_page;
  return { status: "ready", harnesses: page.harnesses, page, total: page.pagination.total, hasMore: page.pagination.has_more, notice: null, error: null, errorKind: null, ...overrides };
}

function renderView(props: Partial<React.ComponentProps<typeof AgentArchitectureView>> = {}) {
  const onLoadMore = vi.fn();
  const onRestart = vi.fn();
  const view = render(<AgentArchitectureView state={state()} loadingMore={false} narrow={false} onLoadMore={onLoadMore} onRestart={onRestart} {...props} />);
  return { ...view, onLoadMore, onRestart };
}

const supervisorId = () => supervisorHarness().harness_id;

describe("AgentArchitectureView", () => {
  it("draws the selected harness in layers with severity badges equal to the recorded findings", () => {
    renderView({ initialHarnessId: toolTeamHarness().harness_id });
    const harness = toolTeamHarness();
    const triage = agentByLabel(harness, "triage_agent", "subgraph");
    const node = screen.getByTestId(`architecture-node-${triage.id}`);
    const badge = within(node).getByRole("button", { name: "2 findings on triage_agent, worst high. Open details" });
    expect(badge).toHaveTextContent("2");
    expect(badge).toHaveAttribute("data-severity", "high");
    expect(screen.getAllByTestId(/^architecture-node-/)).toHaveLength(harness.agent_count);
  });

  it("switches to the flow layout with start and finish, keeping unresolved stubs labelled", () => {
    renderView({ initialHarnessId: supervisorId() });
    expect(screen.getByText("1 unresolved route")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Flow" }));
    expect(screen.getByRole("button", { name: "Flow" })).toHaveAttribute("aria-pressed", "true");
    expect(screen.getByText("End")).toBeInTheDocument();
    expect(screen.getByText("End of research_builder")).toBeInTheDocument();
    expect(screen.getByText("1 unresolved route")).toBeInTheDocument();
    const research = agentByLabel(supervisorHarness(), "research");
    expect(within(screen.getByTestId(`architecture-node-${research.id}`)).getByLabelText("Returns to supervisor (sequential step)")).toBeInTheDocument();
  });

  it("says observed paths are not available instead of drawing them", () => {
    renderView();
    expect(screen.getByText(/Observed runtime paths are not available yet/)).toBeInTheDocument();
    expect(screen.getByRole("list", { name: "Graph legend" })).not.toHaveTextContent(/observed/i);
  });

  it("lists only the edge kinds drawn in the legend", () => {
    renderView({ initialHarnessId: supervisorId() });
    const legend = screen.getByRole("list", { name: "Graph legend" });
    expect(legend).toHaveTextContent("Entry");
    expect(legend).toHaveTextContent("Unresolved route");
    expect(legend).not.toHaveTextContent("Handoff");
    fireEvent.click(screen.getByRole("button", { name: "Flow" }));
    expect(screen.getByRole("list", { name: "Graph legend" })).toHaveTextContent("Handoff");
    expect(screen.getByRole("list", { name: "Graph legend" })).not.toHaveTextContent("Crew or group member");
  });

  it("collapses a large layer and expands it on request", () => {
    const wide = wideCrew(COLLAPSE_AFTER + 3);
    const page = { ...architecturePages().first_page, harnesses: [wide] };
    renderView({ state: state({ harnesses: [wide], page }) });
    expect(screen.getByText("5 more agents")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Expand 5 more agents" }));
    expect(screen.queryByText("5 more agents")).toBeNull();
    expect(screen.getAllByTestId(/^architecture-node-/)).toHaveLength(COLLAPSE_AFTER + 4);
  });

  it("opens the agent detail panel on Enter with models, tools, credential names and links", async () => {
    renderView({ initialHarnessId: toolTeamHarness().harness_id });
    const triage = agentByLabel(toolTeamHarness(), "triage_agent", "subgraph");
    const flowNode = screen.getByTestId(`architecture-node-${triage.id}`).closest(".react-flow__node") as HTMLElement;
    flowNode.focus();
    fireEvent.keyDown(flowNode, { key: "Enter" });
    const dialog = screen.getByRole("dialog");
    expect(within(dialog).getByText("openai:gpt-4o-mini")).toBeInTheDocument();
    expect(within(dialog).getByText("lookup_ticket")).toBeInTheDocument();
    expect(within(dialog).getByText("OPENAI_API_KEY")).toBeInTheDocument();
    expect(within(dialog).getByText(/2 findings · worst high/)).toBeInTheDocument();
    const investigate = within(dialog).getByRole("link", { name: /Investigate in graph/ });
    expect(investigate.getAttribute("href")).toContain(`node=${encodeURIComponent(triage.id)}`);
    expect((await within(dialog).findByRole("link", { name: "Open CVE-2026-0001 in findings" })).getAttribute("href")).toBe("/findings?cve=CVE-2026-0001");
    expect(within(dialog).getByText("CVE-2026-0002")).toBeInTheDocument();
    expect(within(dialog).queryByText("tickets")).toBeNull();
    expect(neighbors).toHaveBeenCalledWith(triage.id);
  });

  it("shows an empty state when no multi-agent framework was found", () => {
    const page = { ...architecturePages().first_page, harnesses: [], summary: { ...architecturePages().first_page.summary, harnesses: 0, framework_agents: 0, placed_agents: 0, unplaced_framework_agents: 0, frameworks: {} }, pagination: { ...architecturePages().first_page.pagination, total: 0, has_more: false, next_cursor: "" } };
    renderView({ state: state({ harnesses: [], page, total: 0, hasMore: false }) });
    expect(screen.getByText("No multi-agent harnesses in this estate")).toBeInTheDocument();
  });

  it("states incomplete coverage and its gaps honestly", () => {
    const base = architecturePages().first_page;
    const page = { ...base, coverage: { ...base.coverage, complete: false } };
    renderView({ state: state({ page }) });
    expect(screen.getByRole("status", { name: "Coverage" })).toHaveTextContent(/Coverage is incomplete/);
    for (const gap of base.coverage.gaps) expect(screen.getByText(gap)).toBeInTheDocument();
  });

  it("pages harnesses with the API cursor and reports a rejected cursor", () => {
    const { onLoadMore, unmount } = renderView();
    fireEvent.click(screen.getByRole("button", { name: "Load more harnesses (2 of 3)" }));
    expect(onLoadMore).toHaveBeenCalled();
    unmount();
    const { onRestart } = renderView({ state: state({ status: "error", errorKind: "cursor", error: "Invalid cursor for this query; restart from the first page." }) });
    expect(screen.getByRole("alert")).toHaveTextContent("Invalid cursor");
    fireEvent.click(screen.getByRole("button", { name: "Start over" }));
    expect(onRestart).toHaveBeenCalled();
  });

  it("shows the snapshot-changed notice after a restart", () => {
    renderView({ state: state({ notice: "The snapshot changed while paging, so harnesses were reloaded from the first page." }) });
    expect(screen.getByText(/snapshot changed while paging/)).toBeInTheDocument();
  });

  it("uses a single-column step list on a phone", () => {
    renderView({ narrow: true, initialHarnessId: supervisorId() });
    expect(document.querySelector(".react-flow")).toBeNull();
    const steps = screen.getByRole("region", { name: "Harness layers" });
    expect(within(steps).getByRole("button", { name: /^supervisor, Orchestrator/ })).toBeInTheDocument();
    // No lines are drawn on a phone, so the legend lists no line styles.
    expect(screen.getByRole("list", { name: "Graph legend" })).not.toHaveTextContent(/Entry|Declared inside|Unresolved route/);
    expect(screen.getByRole("list", { name: "Graph legend" })).toHaveTextContent("Findings on agent");
    fireEvent.click(screen.getByRole("button", { name: "Flow" }));
    expect(screen.getByRole("region", { name: "Harness flow steps" })).toBeInTheDocument();
  });
});
