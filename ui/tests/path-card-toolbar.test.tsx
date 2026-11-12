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

import { edge, node } from "./fixtures/attack-path-graph-fixture";
import { ExposurePathCommandCenter } from "@/components/exposure-path-command-center";
import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";

beforeEach(() => {
  HTMLElement.prototype.scrollIntoView = vi.fn();
  vi.stubGlobal("ResizeObserver", class { observe() {} unobserve() {} disconnect() {} });
  vi.stubGlobal("DOMMatrixReadOnly", class { m22 = 1; constructor() {} });
});

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
const attackPath = { source: "agent:a", target: "pkg:p", hops: ["agent:a", "pkg:p"], edges: ["depends_on"] } as unknown as AttackPath;
const graph = {
  scan_id: "scan-1", tenant_id: "t", created_at: "", interaction_risks: [], stats: {},
  nodes: [node("agent:a", "agent", "agent"), node("pkg:p", "package", "form-data@4.0.0")],
  edges: [edge("agent:a", "pkg:p", "depends_on")],
  attack_paths: [attackPath],
} as unknown as UnifiedGraphData;

function investigation(data: UnifiedGraphData = graph) {
  return <SecurityGraphInvestigation embedded graph={data} attackPath={attackPath} focusMode
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
    // Line styles are explained once, in the legend under the canvas.
    expect(screen.getAllByRole("list", { name: "Graph legend" })).toHaveLength(1);
    expect(screen.queryByText("Interactive graph")).not.toBeInTheDocument();
  });

  it("keeps the toggle available while the graph slot has no toolbar yet", () => {
    render(<ExposurePathCommandCenter path={path} graphSlot={<div>Loading selected path</div>} />);
    expect(screen.getAllByRole("group", { name: "Exposure path view" })).toHaveLength(1);
    expect(screen.queryByRole("toolbar", { name: "Graph controls" })).not.toBeInTheDocument();
  });

  it("gives a short path a content-sized canvas", () => {
    render(<ExposurePathCommandCenter path={path} graphSlot={investigation()} />);
    const canvas = screen.getByTestId("attack-path-graph-canvas");
    expect(Number.parseInt(canvas.style.height, 10)).toBeLessThan(340);
  });

  it("says so when the path's nodes are not in the loaded graph", () => {
    render(<ExposurePathCommandCenter path={path} graphSlot={investigation({ ...graph, nodes: [], edges: [] })} />);
    expect(screen.getByText(/Selected path nodes are not available in this graph page/)).toBeInTheDocument();
    expect(screen.queryByTestId("attack-path-graph-canvas")).toBeNull();
  });
});
