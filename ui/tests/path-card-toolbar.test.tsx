import { render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AttackPath, UnifiedGraphData } from "@/lib/graph-schema";
import type { ExposurePath } from "@/lib/exposure-path";

const mocks = vi.hoisted(() => ({
  nodes: ["agent:a", "pkg:p"].map((id, index) => ({
    id,
    position: { x: index * 336, y: 0 },
    data: { label: id, nodeType: index ? "package" : "agent", attributes: { node_id: id } },
  })),
}));
vi.mock("@/lib/api", () => ({ api: {} }));
vi.mock("@/components/auth-provider", () => ({ useAuthState: () => ({ session: null, loading: false }) }));
vi.mock("@/lib/graph-renderer-switch", () => ({ decideGraphRenderer: () => ({ kind: "webgl" }) }));
vi.mock("@/lib/unified-graph-flow", () => ({ buildUnifiedFlowGraph: () => ({ nodes: mocks.nodes, edges: [], legend: [] }) }));
vi.mock("@/lib/use-graph-layout", () => ({ useGraphLayout: () => ({ nodes: mocks.nodes, edges: [], pending: false }) }));
vi.mock("@/components/sigma-graph-overview", () => ({ SigmaGraphOverview: () => <div>canvas</div> }));

import { ExposurePathCommandCenter } from "@/components/exposure-path-command-center";
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";

beforeEach(() => { HTMLElement.prototype.scrollIntoView = vi.fn(); });

const path: ExposurePath = {
  id: "path-1",
  label: "agent -> pkg",
  summary: "",
  riskScore: 9,
  severity: "critical",
  source: { id: "agent:a", label: "agent", role: "agent" },
  target: { id: "pkg:p", label: "form-data@4.0.0", role: "package" },
  hops: [
    { id: "agent:a", label: "agent", role: "agent" },
    { id: "pkg:p", label: "form-data@4.0.0", role: "package" },
  ],
  relationships: [],
  nodeIds: ["agent:a", "pkg:p"],
  edgeIds: [],
  findings: [],
  affectedAgents: ["agent"],
  affectedServers: [],
  reachableTools: [],
  exposedCredentials: [],
};
const graph = { scan_id: "scan-1", nodes: [], edges: [], attack_paths: [] } as unknown as UnifiedGraphData;
const attackPath = { source: "agent:a", target: "pkg:p", hops: ["agent:a", "pkg:p"], edges: ["uses"] } as unknown as AttackPath;

function investigation() {
  return <SecurityGraphInvestigation embedded graph={graph} attackPath={attackPath} focusMode
    onFocusModeChange={vi.fn()} fullGraphHref="/graph" scanId="scan-1" />;
}

describe("path card toolbar", () => {
  it("collapses the view toggle, evidence summary and graph actions into one toolbar row", () => {
    render(<ExposurePathCommandCenter path={path} graphSlot={investigation()} />);
    const toggles = screen.getAllByRole("group", { name: "Exposure path view" });
    expect(toggles).toHaveLength(1);
    const toolbar = screen.getByRole("toolbar", { name: "Graph controls" });
    expect(toolbar).toContainElement(toggles[0]!);
    expect(within(toolbar).getByText("Open lineage")).toBeInTheDocument();
    expect(within(toolbar).getByLabelText("Visible relationship evidence")).toBeInTheDocument();
    expect(screen.getAllByLabelText("Visible relationship evidence")).toHaveLength(1);
    expect(screen.queryByText("Interactive graph")).not.toBeInTheDocument();
  });

  it("keeps the toggle available while the graph slot has no toolbar yet", () => {
    render(<ExposurePathCommandCenter path={path} graphSlot={<div>Loading selected path</div>} />);
    expect(screen.getAllByRole("group", { name: "Exposure path view" })).toHaveLength(1);
    expect(screen.queryByRole("toolbar", { name: "Graph controls" })).not.toBeInTheDocument();
  });

  it("gives a short path a content-sized canvas", () => {
    render(<ExposurePathCommandCenter path={path} graphSlot={investigation()} />);
    const canvas = screen.getByTestId("security-graph-investigation");
    expect(Number.parseInt(canvas.style.height, 10)).toBeLessThan(340);
  });
});
