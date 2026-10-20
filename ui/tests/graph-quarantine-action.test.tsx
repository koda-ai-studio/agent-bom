import { render, screen } from "@testing-library/react";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { GraphEntityDrawer } from "@/components/graph-entity-drawer";
import type { LineageNodeData } from "@/components/lineage-nodes";

function node(nodeType: string): LineageNodeData {
  return { label: "shared-display-name", nodeType, severity: "none" } as unknown as LineageNodeData;
}

describe("graph containment boundary", () => {
  it("offers review with explicit gateway scope, never a mutation from a discovered agent", () => {
    render(<GraphEntityDrawer data={node("agent")} onClose={() => {}} enrich={false} />);
    expect(screen.getByRole("link", { name: "Review gateway controls" })).toHaveAttribute("href", "/fleet");
    expect(screen.getByText(/Read-only discovery cannot stop this agent/)).toBeTruthy();
    expect(screen.getByText(/Direct cloud calls and other connections remain outside/)).toBeTruthy();
    expect(screen.queryByTestId("graph-quarantine-agent")).toBeNull();
  });

  it("does not show agent controls for a package", () => {
    render(<GraphEntityDrawer data={node("package")} onClose={() => {}} enrich={false} />);
    expect(screen.queryByRole("link", { name: "Review gateway controls" })).toBeNull();
  });

  it("cannot resolve a containment subject by a mutable display name", () => {
    const source = ["app/graph/graph-page-client.tsx", "hooks/use-graph-page-data.tsx", "hooks/use-graph-canvas-model.tsx", "hooks/use-graph-page-actions.tsx", "components/graph-page-view.tsx"]
      .map(path => readFileSync(path, "utf8")).join("\n");
    expect(source.includes("quarantineAgentByLabel")).toBe(false);
    expect(source.includes("api.quarantineFleetAgent")).toBe(false);
  });
});
