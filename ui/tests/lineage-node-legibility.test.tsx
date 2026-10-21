import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { render, screen } from "@testing-library/react";
import { ReactFlowProvider } from "@xyflow/react";
import { LineageDetailPanel } from "@/components/lineage-detail";
import { lineageNodeTypes } from "@/components/lineage-nodes";

const source = readFileSync(
  resolve(__dirname, "../components/lineage-nodes.tsx"),
  "utf8",
);

describe("lineage node labels", () => {
  it("uses the same entity glyph in the canvas and inspector", () => {
    const Renderer = lineageNodeTypes.agentNode;
    const { container } = render(<ReactFlowProvider>
      <section data-testid="node"><Renderer data={{ label: "Review agent", nodeType: "agent" }} /></section>
      <LineageDetailPanel data={{ label: "Review agent", nodeType: "agent" }} onClose={() => {}} variant="inline" />
    </ReactFlowProvider>);
    const nodeIcon = screen.getByTestId("node").querySelector("svg");
    const inspectorIcon = container.querySelector('[data-testid="graph-entity-drawer"] svg');
    expect(inspectorIcon?.innerHTML).toBe(nodeIcon?.innerHTML);
  });
  it("qualifies partial graph counts visibly without claiming empty inventory", () => {
    const Renderer = lineageNodeTypes.agentNode;
    render(<ReactFlowProvider><Renderer data={{ label: "Scoped agent", nodeType: "agent", serverCount: 0, packageCount: 0, countScope: "loaded_graph", countHopLimits: { serverCount: 1, packageCount: 3 } }} /></ReactFlowProvider>);
    expect(screen.queryByText("Loaded graph")).not.toBeInTheDocument();
    expect(screen.getByTitle(/Servers: 1 hop; packages: 3 hops/)).toHaveTextContent("0 linked servers");
  });
  it("does not repeat the provider the vendor mark already names as a caption", () => {
    const Renderer = lineageNodeTypes.dataStoreNode;
    render(<ReactFlowProvider><Renderer data={{
      label: "risk-scores-staging-2", nodeType: "dataStore", entityType: "data_store", description: "snowflake",
      attributes: { cloud_provider: "snowflake", resource_type: "table" }, dimensions: { cloud_provider: "snowflake" },
    }} /></ReactFlowProvider>);
    expect(screen.getByText("Table", { exact: true })).toBeVisible();
    expect(screen.queryByText("snowflake", { exact: true })).not.toBeInTheDocument();
    expect(screen.getByRole("img", { name: /Snowflake/ })).toBeInTheDocument();
  });

  it("keeps a caption that says something the mark does not", () => {
    const Renderer = lineageNodeTypes.dataStoreNode;
    render(<ReactFlowProvider><Renderer data={{
      label: "orders", nodeType: "dataStore", entityType: "data_store", description: "ANALYTICS.PUBLIC",
      attributes: { cloud_provider: "snowflake" }, dimensions: { cloud_provider: "snowflake" },
    }} /></ReactFlowProvider>);
    expect(screen.getByText("ANALYTICS.PUBLIC")).toBeInTheDocument();
  });

  it("does not show a count-scope label on a server without counts", () => {
    const Renderer = lineageNodeTypes.serverNode;
    render(<ReactFlowProvider><Renderer data={{ label: "Image processing MCP server", nodeType: "server", countScope: "loaded_graph" }} /></ReactFlowProvider>);
    expect(screen.queryByText("Loaded graph")).not.toBeInTheDocument();
    expect(screen.queryByTitle(/Distinct entities linked/)).not.toBeInTheDocument();
  });

  it.each([
    { entityType: "application", nodeType: "container" as const, badge: "Application" },
    { entityType: "container", nodeType: "container" as const, badge: "Container" },
    { entityType: "package", nodeType: "package" as const, badge: "Package" },
    { entityType: undefined, nodeType: "container" as const, badge: "Container" },
  ])("labels $entityType as $badge without changing its renderer", ({ entityType, nodeType, badge }) => {
    const Renderer = nodeType === "package" ? lineageNodeTypes.packageNode : lineageNodeTypes.containerNode;
    render(
      <ReactFlowProvider>
        <Renderer data={{ label: "inventory item", entityType, nodeType }} />
      </ReactFlowProvider>,
    );
    expect(screen.getByText(badge, { exact: true })).toBeVisible();
    if (entityType === "application") {
      expect(screen.queryByText("Container", { exact: true })).not.toBeInTheDocument();
    }
  });

  it("keeps credential identifiers intact with wrap opportunities at separators", () => {
    const Renderer = lineageNodeTypes.credentialNode;
    const { container } = render(<ReactFlowProvider><Renderer data={{ label: "AWS_SECRET_ACCESS_KEY", nodeType: "credential" }} /></ReactFlowProvider>);
    const label = container.querySelector("p");
    expect(label?.textContent).toBe("AWS_SECRET_ACCESS_KEY");
    expect(label?.querySelectorAll("wbr").length).toBeGreaterThan(1);
  });

  it("keeps expansion controls readable when asset focus dims unrelated nodes", () => {
    const Renderer = lineageNodeTypes.clusterPillNode;
    render(<ReactFlowProvider><Renderer data={{ label: "+40 accounts", nodeType: "account", dimmed: true }} /></ReactFlowProvider>);
    expect(screen.getByTestId("cluster-pill")).not.toHaveClass("opacity-25");
    expect(screen.getByRole("button", { name: /Expand/ })).toBeVisible();
  });

  it("wraps long asset names instead of clipping them to one line", () => {
    // Estate names are long by nature -- GCS_SERVICE_ACCOUNT_JSON,
    // data: customer-pii-prod. Clipped to a single 180px line they render as
    // "GCS_SERVICE_ACC..." and the node stops identifying anything. The grid
    // has vertical slack and no horizontal slack, so the label takes a second
    // line rather than a wider node.
    // Neither the detailed node nor the rolled-up summary node may clip.
    expect(source).not.toMatch(/flex-1 truncate/);
    const Renderer = lineageNodeTypes.containerNode;
    const { container } = render(<ReactFlowProvider><Renderer data={{ label: "image@sha256:abcdef", nodeType: "container" }} /></ReactFlowProvider>);
    expect(container.querySelector('[data-graph-entity="true"] > p')).toHaveClass("w-full", "min-w-0", "break-words", "line-clamp-3");
    expect(source).toContain("line-clamp-2 text-xs");
  });
});

it("uses the recorded agent source mark in both the canvas and inspector", () => {
  const Renderer = lineageNodeTypes.agentNode;
  const data = { label: "Release helper", nodeType: "agent" as const, agentType: "claude-code", severity: "critical" };
  const { container } = render(<ReactFlowProvider>
    <Renderer data={data} />
    <LineageDetailPanel data={data} onClose={() => {}} variant="inline" />
  </ReactFlowProvider>);
  expect(screen.getAllByRole("img", { name: "Source: Claude Code" })).toHaveLength(2);
  expect(container.querySelectorAll('img[src="/logos/claude.svg"]')).toHaveLength(2);
  expect(container.querySelector('[data-graph-entity="true"]')).toHaveTextContent("Release helper");
});

it("retains the agent glyph with a secondary vendor badge", () => {
  const Renderer = lineageNodeTypes.agentNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Billing Agent", nodeType: "agent", agentType: "claude-code" }} /></ReactFlowProvider>);
  const glyph = container.querySelector(".graph-entity-glyph");
  expect(glyph?.querySelector("svg.lucide-bot")).not.toBeNull();
  expect(glyph?.querySelector('[data-agent-source="claude"]')).not.toBeNull();
  expect(glyph?.querySelector('[data-agent-source-badge]')).not.toBeNull();
  expect(glyph?.getAttribute("style")).not.toContain("border-color");
});

it("distinguishes a recorded repository from its child folders without changing circular styling", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "example-org/payments", nodeType: "directory", attributes: { is_repo_root: true, full_name: "example-org/payments", provider: "github" } }} /></ReactFlowProvider>);
  expect(screen.getByText("Repository", { exact: true })).toBeVisible();
  expect(screen.queryByText("Folder", { exact: true })).not.toBeInTheDocument();
  const host = screen.getByRole("img", { name: "Source: GitHub" });
  expect(host).toBeVisible();
  expect(host.parentElement).toHaveClass("graph-entity-glyph");
  expect(host).toHaveAttribute("data-graph-source-badge", "true");
  expect(container.querySelector('.graph-entity-glyph')).toHaveClass("rounded-full");
  expect(container.querySelector('svg.lucide-folder-git-2')).not.toBeNull();
});

it("shows unknown repository remote explicitly and keeps scanned revision separate", () => {
  render(<ReactFlowProvider><LineageDetailPanel data={{ label: "local-repo", nodeType: "directory", attributes: { is_repo_root: true, default_branch: "main" } }} onClose={() => {}} variant="inline" /></ReactFlowProvider>);
  expect(screen.getByText("Remote not recorded")).toBeVisible();
  expect(screen.getByText("Scanned commit")).toBeVisible();
  expect(screen.getByText("Default branch")).toBeVisible();
});

it("distinguishes security findings from config files and preserves the canonical title", () => {
  const Renderer = lineageNodeTypes.misconfigNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "Workflow publishes with a long-lived registry token", nodeType: "misconfiguration", severity: "high", attributes: { display_title: "Long-lived registry token" } }} /></ReactFlowProvider>);
  expect(screen.getByText("Finding", { exact: true })).toBeVisible();
  expect(container.querySelector('[data-graph-entity] > p')).toHaveTextContent("Long-lived registry token");
  expect(screen.getByTitle("Workflow publishes with a long-lived registry token · High severity")).toBeVisible();
});

it("uses explicit provider metadata on infrastructure while keeping its entity glyph", () => {
  const Renderer = lineageNodeTypes.containerNode;
  const { container } = render(<ReactFlowProvider><Renderer data={{ label: "production workload", nodeType: "container", attributes: { cloud_provider: "aws" } }} /></ReactFlowProvider>);
  expect(screen.getByRole("img", { name: "Source: AWS" })).toBeVisible();
  expect(container.querySelector('.graph-entity-glyph > svg')).not.toBeNull();
});
