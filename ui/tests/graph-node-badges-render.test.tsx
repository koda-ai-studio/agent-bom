import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";

import { GraphLegend } from "@/components/graph-chrome";
import { lineageNodeTypes, type LineageNodeData } from "@/components/lineage-nodes";
import { legendItemsForVisibleGraph } from "@/lib/graph-utils";

const pkg: LineageNodeData = {
  label: "next@15.2.2",
  nodeType: "package",
  version: "15.2.2",
  ecosystem: "npm",
  severity: "critical",
  vulnCount: 1,
};
const cluster: LineageNodeData = {
  label: "prod-ai-runtime",
  nodeType: "cluster",
  description: "production",
  dimensions: { environment: "production", cloud_provider: "aws" },
};

describe("graph node badges on the canvas and in the legend", () => {
  it("renders an accessible severity ring and ecosystem chip on a vulnerable package", () => {
    const Renderer = lineageNodeTypes.packageNode;
    render(<ReactFlowProvider><section data-testid="node"><Renderer data={pkg} /></section></ReactFlowProvider>);
    const node = screen.getByTestId("node");
    expect(within(node).getByRole("img", { name: "Recorded severity: critical · 1 linked finding" })).toBeInTheDocument();
    expect(within(node).getByLabelText("Package ecosystem: npm")).toHaveTextContent("npm");
    expect(within(node).queryByText(/15\.2\.2 · npm/)).not.toBeInTheDocument();
  });

  it("renders provider and environment chips without repeating the raw environment subtitle", () => {
    const Renderer = lineageNodeTypes.clusterNode;
    render(<ReactFlowProvider><section data-testid="node"><Renderer data={cluster} /></section></ReactFlowProvider>);
    const node = screen.getByTestId("node");
    const chips = [...node.querySelectorAll("[data-node-badge]")].map((chip) => chip.textContent);
    expect(chips).toEqual(["AWS", "PROD"]);
    expect(within(node).getByLabelText("Environment: production")).toBeInTheDocument();
    expect(within(node).queryByText("production", { exact: true })).not.toBeInTheDocument();
    expect(within(node).queryByRole("img")).not.toBeInTheDocument();
  });

  it("builds legend chips from the same renderer as the node chips", () => {
    const nodes = [{ id: "p", data: pkg }, { id: "c", data: cluster }];
    render(<GraphLegend embedded items={legendItemsForVisibleGraph(nodes, [])} />);
    expect(screen.getByText("Node badges")).toBeInTheDocument();
    for (const label of ["AWS provider", "Production environment", "npm ecosystem", "Critical severity ring"]) {
      expect(screen.getByText(label)).toBeInTheDocument();
    }
    const legendChips = [...document.querySelectorAll("[data-node-badge]")].map((chip) => chip.outerHTML.replace(/ (title|aria-label)="[^"]*"/g, ""));
    const { container } = render(<ReactFlowProvider><lineageNodeTypes.clusterNode data={cluster} /></ReactFlowProvider>);
    const nodeChips = [...container.querySelectorAll("[data-node-badge]")].map((chip) => chip.outerHTML.replace(/ (title|aria-label)="[^"]*"/g, ""));
    for (const chip of nodeChips) expect(legendChips).toContain(chip);
  });
});

it("renders collision context as visible text, independent of hover", () => {
  const Renderer = lineageNodeTypes.agentNode;
  render(<ReactFlowProvider><Renderer data={{ label: "Workspace reader", nodeType: "agent", identityContext: "Config 926bd270c907" }} /></ReactFlowProvider>);
  expect(screen.getByText("Config 926bd270c907")).toBeVisible();
});
