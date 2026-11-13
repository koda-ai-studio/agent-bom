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

/** Exposure -> identity -> crown jewel, every marker from a stored risk context. */
function leaderPath() {
  const graph = {
    scan_id: "s", tenant_id: "t", created_at: "", interaction_risks: [], stats: {},
    nodes: [
      node("vm:web", "container", "member-portal", context({ internet_exposed: true }, [
        { field: "internet_exposed", rule: "recorded_internet_exposed", attribute: "internet_exposed", value: true }])),
      node("role:app", "role", "phi-export-approver", context({ privilege_level: "admin", is_admin: true }, [
        { field: "privilege_level", rule: "admin_equivalence", attribute: "admin_equivalence_status", value: "admin" }])),
      node("db:claims", "data_store", "claims-ledger", context({ data_sensitivity: "phi", crown_jewel: true }, [
        { field: "data_sensitivity", rule: "recorded_data_sensitivity", attribute: "data_sensitivity", value: "phi" },
        { field: "crown_jewel", rule: "sensitive_data_store", attribute: "data_sensitivity", value: "phi" }])),
    ],
    edges: [edge("vm:web", "role:app", "assumes"), edge("role:app", "db:claims", "can_access")],
    attack_paths: [],
  } as never;
  return { graph, selected: path(["vm:web", "role:app", "db:claims"], ["assumes", "can_access"]) };
}

describe("AttackPathGraph risk markers", () => {
  it("reads exposure -> privileged identity -> crown jewel and explains each in the legend", () => {
    const { graph, selected } = leaderPath();
    render(<AttackPathGraph graph={graph} attackPath={selected} narrow={false} onOpenFindings={vi.fn()} onNodeSelect={vi.fn()} onEdgeSelect={vi.fn()} />);
    expect(within(screen.getByTestId("attack-path-node-vm:web")).getByLabelText("Internet-exposed (recorded)")).toBeInTheDocument();
    expect(within(screen.getByTestId("attack-path-node-role:app")).getByLabelText("Privileged: admin (recorded)")).toBeInTheDocument();
    const jewel = screen.getByTestId("attack-path-node-db:claims");
    expect(within(jewel).getByLabelText("Crown jewel: holds sensitive data (phi) (recorded)")).toBeInTheDocument();
    expect(within(jewel).getByLabelText("Sensitive data: phi (recorded)")).toBeInTheDocument();
    const legend = screen.getByRole("list", { name: "Graph legend" });
    for (const label of ["Internet-exposed", "Privileged", "Sensitive data", "Crown jewel"]) expect(within(legend).getByText(label)).toBeInTheDocument();
  });
});
