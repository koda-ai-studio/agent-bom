import { render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { describe, expect, it, vi } from "vitest";
import { GraphScopeNode } from "@/components/graph-scope-node";
import { GraphEntityDrawer } from "@/components/graph-entity-drawer";
import { buildRollupFlowGraph } from "@/lib/graph-rollup-view";
import type { GraphRollupContainer } from "@/lib/api-types";

vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ loading: false, session: { tenant_id: "test", role: "analyst" } }) }));

const leaf: GraphRollupContainer = {
  id: "cred:slot", label: "API_TOKEN", entity_type: "credential", severity: "",
  is_container: false, has_children: false, direct_child_count: 0,
  aggregate: { descendant_count: 0, by_type: {}, severity_counts: { none: 1 }, worst_severity: "", worst_severity_rank: 0, internet_exposed: false, toxic_combo: false, exposed_count: 0, toxic_count: 0 },
};

describe("entities in scope navigation", () => {
  it("shows a leaf as an inspectable entity without empty scope counts", () => {
    render(<ReactFlowProvider><GraphScopeNode item={leaf} /></ReactFlowProvider>);
    expect(screen.getByText("Inspect entity")).toBeVisible();
    expect(screen.queryByText("contained entities")).not.toBeInTheDocument();
    expect(screen.queryByText("Inspect scope")).not.toBeInTheDocument();
  });
  it("opens leaf evidence rather than an empty scope summary", () => {
    const data = buildRollupFlowGraph([leaf]).nodes[0]!.data;
    render(<GraphEntityDrawer data={data} onClose={vi.fn()} enrich={false} variant="docked" />);
    expect(screen.queryByLabelText("Scope details")).not.toBeInTheDocument();
    expect(screen.getByTestId("graph-drawer-tab-overview")).toBeVisible();
  });
  it("uses a finding's own severity when it has no descendants", () => {
    const finding = { ...leaf, id: "finding:high", entity_type: "misconfiguration", label: "Credential exposure", severity: "high" };
    render(<ReactFlowProvider><GraphScopeNode item={finding} /></ReactFlowProvider>);
    expect(screen.getByText("High severity")).toBeVisible();
    expect(screen.getByText("Inspect finding")).toBeVisible();
    expect(screen.queryByText("No severity recorded")).not.toBeInTheDocument();
  });
});
