import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { branchingFixture } from "./fixtures/attack-path-graph-fixture";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: null, loading: false }) }));
vi.mock("@/components/graph-entity-drawer", () => ({
  GraphEntityDrawer: ({ data }: { data: { label: string } }) => <output data-testid="drawer">{data.label}</output>,
}));
vi.mock("@/components/graph-relationship-detail", () => ({
  GraphRelationshipDetail: ({ edge }: { edge: { relationship: string } }) => <output data-testid="relationship">{edge.relationship}</output>,
}));
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});
afterEach(cleanup);

function renderLayered() {
  const { graph, selected } = branchingFixture();
  return render(<SecurityGraphInvestigation embedded graph={graph} attackPath={selected} focusMode onFocusModeChange={vi.fn()}
    fullGraphHref="/graph" scanId="scan-1" />);
}

describe("embedded focused path", () => {
  it("renders the layered graph without the CVE as a hop or always-on relationship labels", () => {
    renderLayered();
    const canvas = screen.getByTestId("security-graph-investigation");
    expect(canvas).toHaveAttribute("data-path-layout", "layered");
    expect(within(canvas).queryByTestId("attack-path-node-cve:next")).toBeNull();
    expect(within(canvas).getByTestId("attack-path-node-pkg:next")).toHaveAttribute("data-role", "target");
    expect(within(canvas).queryByText("Depends On")).toBeNull();
    expect(screen.getByRole("toolbar", { name: "Graph controls" })).toBeInTheDocument();
  });

  it("opens a single finding's detail straight from its badge", async () => {
    renderLayered();
    fireEvent.click(screen.getByRole("button", { name: /^1 finding on urllib3@2\.2\.1/ }));
    await waitFor(() => expect(screen.getByTestId("drawer")).toHaveTextContent("CVE-2024-37891"));
  });

  it("lists several findings, then opens the chosen one", async () => {
    renderLayered();
    fireEvent.click(screen.getByRole("button", { name: /^2 findings on next@15\.2\.2/ }));
    const list = screen.getByRole("region", { name: "Findings on next@15.2.2" });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    fireEvent.click(within(list).getByText("CVE-2025-00001"));
    await waitFor(() => expect(screen.getByTestId("drawer")).toHaveTextContent("CVE-2025-00001"));
  });

  it("opens a branch node's detail", async () => {
    renderLayered();
    fireEvent.click(within(screen.getByTestId("attack-path-node-dataset:finance")).getByText("finance-board-index"));
    await waitFor(() => expect(screen.getByTestId("drawer")).toHaveTextContent("finance-board-index"));
  });

  it("opens the relationship detail from the keyboard", async () => {
    const { container } = renderLayered();
    const line = container.querySelector('[data-id="user:contractor->sa:jit:acted_as"]')!;
    fireEvent.keyDown(line, { key: "Enter" });
    await waitFor(() => expect(screen.getByTestId("relationship")).toHaveTextContent("acted_as"));
  });

  it("opens a node's detail from the keyboard", async () => {
    const { container } = renderLayered();
    fireEvent.keyDown(container.querySelector('.react-flow__node[data-id="role:admin"]')!, { key: "Enter" });
    await waitFor(() => expect(screen.getByTestId("drawer")).toHaveTextContent("prod-ai-admin"));
  });

  it("opens the relationship detail for a recorded edge", async () => {
    const { container } = renderLayered();
    fireEvent.click(container.querySelector('[data-id="agent:copilot->server:filesystem:uses"]')!);
    await waitFor(() => expect(screen.getByTestId("relationship")).toHaveTextContent("uses"));
  });
});
