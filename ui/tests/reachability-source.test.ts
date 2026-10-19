import { describe, expect, it } from "vitest";

import { reachabilitySource, reachabilitySourceLabel } from "@/lib/reachability-source";

describe("reachabilitySource", () => {
  it("prefers an agent when one reaches the finding", () => {
    expect(reachabilitySource({ graph_reachable_from_agents: ["agent:copilot"], graph_reachable_from: ["kubernetes:workload:prod/api"] })).toBe(
      "agent:copilot",
    );
  });

  it("falls back to any inbound path source instead of assuming an agent", () => {
    expect(reachabilitySource({ graph_reachable_from_agents: [], graph_reachable_from: ["kubernetes:workload:prod/api"] })).toBe(
      "kubernetes:workload:prod/api",
    );
  });

  it("returns null when nothing names a source", () => {
    expect(reachabilitySource({})).toBeNull();
  });

  it("shortens node ids to their last segment", () => {
    expect(reachabilitySourceLabel("kubernetes:workload:eks-01/claims/claims-engine-00")).toBe("claims-engine-00");
    expect(reachabilitySourceLabel("agent:copilot")).toBe("copilot");
  });
});
