import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingExposureSummary } from "@/components/finding-exposure-summary";
import { findingAssetKind, reachabilityVerdict } from "@/lib/finding-exposure";
import type { EnrichedVuln } from "@/lib/findings-view";

describe("finding asset kind", () => {
  it("names the kind from the canonical node, not a mislabelled entity type", () => {
    expect(findingAssetKind({ node_id: "pkg:pypi:langchain@0.0.150", entity_type: "server" })).toBe("Package");
    expect(findingAssetKind({ node_id: "pkg:pypi:langchain@0.0.150:image:abc", entity_type: "package" })).toBe("Package in container image");
    expect(findingAssetKind({ node_id: "server:etl", entity_type: "package" })).toBe("MCP server");
    expect(findingAssetKind({ node_id: undefined, entity_type: "cloud_resource" })).toBe("Cloud resource");
    expect(findingAssetKind({})).toBe("Asset");
  });
});

describe("reachability verdict", () => {
  it("states a recorded agent path with its basis", () => {
    const verdict = reachabilityVerdict({ graph_reachable: true, graph_min_hop_distance: 2, graph_reachable_from_agents: ["agent:cursor", "agent:data-pipeline"] });
    expect(verdict.label).toBe("Reachable from 2 agents");
    expect(verdict.tone).toBe("reachable");
    expect(verdict.basis).toMatch(/2 hops/);
    expect(verdict.basis).toMatch(/does not prove exploitation/);
  });

  it("does not read an absent path as safe, nor an unassessed one as unreachable", () => {
    expect(reachabilityVerdict({ graph_reachable: false }).label).toBe("No agent path recorded");
    expect(reachabilityVerdict({ graph_reachable: false }).basis).toMatch(/not proof/);
    expect(reachabilityVerdict({ graph_reachable: null }).label).toBe("Reachability not assessed");
  });
});

const vuln = (overrides: Partial<EnrichedVuln>) => ({
  id: "CVE-2023-4863", agents: [], affected_servers: [], packages: ["pillow@9.0.0"], graph_reachable: null,
  ...overrides,
}) as EnrichedVuln;

describe("finding exposure summary", () => {
  it("shows the affected agents and servers as links and the verdict", () => {
    render(<FindingExposureSummary vuln={vuln({ agents: ["data-pipeline"], affected_servers: ["etl-server"], graph_reachable: true, graph_min_hop_distance: 2, graph_reachable_from_agents: ["agent:data-pipeline"] })} />);
    expect(screen.getByRole("link", { name: "data-pipeline" })).toHaveAttribute("href", "/agents?name=data-pipeline");
    expect(screen.getByRole("link", { name: "etl-server" })).toHaveAttribute("href", "/findings?q=etl-server");
    expect(screen.getByText("Reachable from 1 agent")).toBeVisible();
  });

  it("falls back to the graph's reaching agents when the occurrence names none", () => {
    render(<FindingExposureSummary vuln={vuln({ graph_reachable: true, graph_reachable_from_agents: ["agent:cursor"] })} />);
    expect(screen.getByRole("link", { name: "cursor" })).toHaveAttribute("href", "/agents?name=cursor");
  });

  it("falls back to the graph's hosting MCP servers when the occurrence names none", () => {
    const hostServers = [{ id: "server:811cd4af", label: "Provider Directory MCP" }];
    render(<FindingExposureSummary vuln={vuln({ graph_reachable: true, graph_reachable_from_agents: ["agent:reviewer-20"] })} hostServers={hostServers} />);
    expect(screen.getByText("Hosting MCP servers")).toBeVisible();
    const server = screen.getByRole("link", { name: "Provider Directory MCP" });
    expect(server).toHaveAttribute("title", "server:811cd4af");
    expect(server).toHaveAttribute("href", "/findings?q=Provider+Directory+MCP");
    expect(screen.queryByText(/No agent or MCP server is recorded/)).toBeNull();
  });

  it("keeps the occurrence's own servers over the graph's hosts", () => {
    render(<FindingExposureSummary vuln={vuln({ affected_servers: ["etl-server"] })} hostServers={[{ id: "server:x", label: "Other" }]} />);
    expect(screen.getByText("MCP servers")).toBeVisible();
    expect(screen.queryByRole("link", { name: "Other" })).toBeNull();
  });

  it("says plainly when no agent or server is recorded", () => {
    render(<FindingExposureSummary vuln={vuln({})} />);
    expect(screen.getByText(/No agent or MCP server is recorded/)).toBeVisible();
  });
});
