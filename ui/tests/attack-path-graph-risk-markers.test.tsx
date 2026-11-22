import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";

import { AttackPathGraph } from "@/components/attack-path-graph";
import { edge, node, path } from "./fixtures/attack-path-graph-fixture";

beforeAll(() => {
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});
afterEach(cleanup);

const context = (fields: Record<string, unknown>, reasons: Record<string, unknown>[]) => ({
  risk_context: { version: 1, scan_id: "s", sources: ["sample"], internet_exposed: null, privilege_level: null, is_admin: null,
    data_sensitivity: null, crown_jewel: false, reasons, ...fields },
});

/** Every marker reads the canonical backend field for that assessment. */
function leaderPath() {
  const graph = {
    scan_id: "s", tenant_id: "t", created_at: "", interaction_risks: [], stats: {},
    nodes: [
      node("vm:web", "container", "member-portal", context({ internet_exposed: true }, [
        { field: "internet_exposed", rule: "recorded_internet_exposed", attribute: "internet_exposed", value: true }])),
      node("role:app", "role", "phi-export-approver", context({ is_admin: true, privilege_level: "admin" }, [])),
      node("db:claims", "data_store", "claims-ledger", context({ data_sensitivity: "phi" }, [])),
    ],
    edges: [edge("vm:web", "role:app", "assumes"), edge("role:app", "db:claims", "can_access")],
    attack_paths: [],
  } as never;
  return { graph, selected: path(["vm:web", "role:app", "db:claims"], ["assumes", "can_access"]) };
}

describe("AttackPathGraph risk markers", () => {
  it("reads canonical exposure, privilege and classification without inferring a crown jewel", () => {
    const { graph, selected } = leaderPath();
    render(<AttackPathGraph graph={graph} attackPath={selected} narrow={false} onOpenFindings={vi.fn()} onNodeSelect={vi.fn()} onEdgeSelect={vi.fn()} />);
    expect(within(screen.getByTestId("attack-path-node-vm:web")).getByLabelText("Internet-exposed (recorded)")).toBeInTheDocument();
    expect(within(screen.getByTestId("attack-path-node-role:app")).getByLabelText("Privileged: admin (recorded)")).toBeInTheDocument();
    const jewel = screen.getByTestId("attack-path-node-db:claims");
    expect(within(jewel).queryByLabelText(/Crown jewel/)).toBeNull();
    expect(within(jewel).getByLabelText("Sensitive data: phi (recorded)")).toBeInTheDocument();
    const legend = screen.getByRole("list", { name: "Graph legend" });
    for (const label of ["Internet-exposed", "Privileged", "Sensitive data"]) expect(within(legend).getByText(label)).toBeInTheDocument();
  });
});
