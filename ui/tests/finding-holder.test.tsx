import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingExposureSummary } from "@/components/finding-exposure-summary";
import { reachabilityVerdict } from "@/lib/finding-exposure";
import { findingHolder, reachingEntity } from "@/lib/finding-holder";
import type { EnrichedVuln } from "@/lib/findings-view";

const vuln = (overrides: Partial<EnrichedVuln>) => ({
  id: "CVE-2023-4863", agents: [], affected_servers: [], packages: ["pillow@9.0.0"], graph_reachable: null,
  ...overrides,
}) as EnrichedVuln;

describe("reaching entity", () => {
  it("names the kind and short name of a graph node id", () => {
    expect(reachingEntity("agent:data-pipeline")).toEqual({ kind: "agent", name: "Data Pipeline", id: "agent:data-pipeline" });
    expect(reachingEntity("kubernetes:workload:eks-0002-12/pharmacy-gateway/pharmacy-gateway-05")).toMatchObject({ kind: "workload", name: "pharmacy-gateway-05" });
    expect(reachingEntity("server:etl-server")).toMatchObject({ kind: "MCP server", name: "etl-server" });
    expect(reachingEntity("cloud_resource:aws:aws_instance:2109/us-east-1/i-0de0")).toMatchObject({ kind: "cloud resource", name: "i-0de0" });
  });
});

describe("reachability verdict names the reaching entity", () => {
  it("says which workload reaches it when no agent does", () => {
    const verdict = reachabilityVerdict({
      graph_reachable: true,
      graph_reachable_from_agents: [],
      graph_reachable_from: ["kubernetes:workload:eks-0002-12/pharmacy-gateway/pharmacy-gateway-05"],
    });
    expect(verdict.label).toBe("Reachable from workload pharmacy-gateway-05");
  });

  it("counts several non-agent reachers without calling them agents", () => {
    const verdict = reachabilityVerdict({
      graph_reachable: true,
      graph_reachable_from: ["kubernetes:workload:c/ns/a", "kubernetes:workload:c/ns/b"],
      graph_reachable_from_count: 4,
    });
    expect(verdict.label).toBe("Reachable from workload a and 3 more");
    expect(verdict.label).not.toMatch(/agent/);
  });

  it("keeps the agent count when agents reach it", () => {
    expect(reachabilityVerdict({ graph_reachable: true, graph_reachable_from_agents: ["agent:cursor"] }).label).toBe("Reachable from 1 agent");
  });
});

describe("finding exposure summary never contradicts its verdict", () => {
  it("lists the reaching workload instead of saying nothing is recorded", () => {
    render(<FindingExposureSummary vuln={vuln({
      graph_reachable: true,
      graph_reachable_from: ["kubernetes:workload:eks-0002-12/eligibility/eligibility-api-06"],
    })} />);
    expect(screen.getByText("Reachable from workload eligibility-api-06")).toBeVisible();
    expect(screen.getByText("Reaching workloads")).toBeVisible();
    expect(screen.getByText("eligibility-api-06")).toBeVisible();
    expect(screen.queryByText(/No agent or MCP server is recorded/)).toBeNull();
  });
});

describe("finding holder", () => {
  it("prefers the recorded agents, by display name", () => {
    expect(findingHolder(vuln({ agents: ["data-pipeline", "cursor"] }))).toEqual({ label: "Data Pipeline, Cursor", kind: "agents", title: "data-pipeline, cursor" });
  });

  it("falls back to the MCP server, then the reaching workload", () => {
    expect(findingHolder(vuln({ affected_servers: ["etl-server"] })).label).toBe("MCP server etl-server");
    expect(findingHolder(vuln({ graph_reachable_from: ["kubernetes:workload:c/ns/pharmacy-gateway-05"] })).label).toBe("Workload pharmacy-gateway-05");
  });

  it("gives a precise reason when no holder is recorded", () => {
    const holder = findingHolder(vuln({ node_id: "cloud_resource:aws:aws_iam_role:1/phi-export", entity_type: "cloud_resource" }));
    expect(holder.label).toBe("Cloud resource · no agent linked");
    expect(holder.kind).toBe("none");
    expect(holder.label).not.toMatch(/unavailable/i);
  });
});
