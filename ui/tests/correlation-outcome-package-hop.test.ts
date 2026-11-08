import { describe, expect, it } from "vitest";
import { buildCorrelationOutcome } from "@/lib/correlation-outcome";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

const receipt = (source: string, target: string, relationship: string) => ({
  source_node_id: source,
  target_node_id: target,
  relationship,
  direction: "directed",
  traversable: true,
  complete: true,
  truncated: false,
  runtime_observed_state: "not_observed",
  freshness: "fresh",
  relationship_provenance: "recorded",
  correlation_identity_status: "current",
  source_snapshot_ids: ["snap-1"],
});

function path(hops: string[]): AttackPath {
  const edges = hops.slice(1).map(() => "connects_to");
  return {
    source: hops[0],
    target: hops.at(-1),
    hops,
    edges,
    vuln_ids: [],
    composite_risk: 4.8,
    analysis: { status: "complete" },
    hop_evidence: hops.slice(1).map((target, index) => receipt(hops[index]!, target, edges[index]!)),
  } as unknown as AttackPath;
}

const node = (id: string, entity_type: string, label = id) => ({ id, entity_type, label }) as unknown as UnifiedNode;

function outcomeFor(hops: string[], nodes: UnifiedNode[]) {
  return buildCorrelationOutcome({
    path: path(hops),
    card: null,
    actions: [],
    nodeById: new Map(nodes.map((n) => [n.id, n])),
    scanId: "corr-1",
    graphScanId: "corr-1",
    fixFirstScanId: "corr-1",
  });
}

describe("correlation outcome package hop", () => {
  it("states that a fully resolved path has no package hop", () => {
    const outcome = outcomeFor(["svc", "agent", "sa", "data"], [
      node("svc", "server"), node("agent", "agent"), node("sa", "service_account"), node("data", "data_store"),
    ]);
    expect(outcome?.packageName).toBeUndefined();
    expect(outcome?.packageHop).toBe("absent");
  });

  it("keeps the package unknown when a hop node is not loaded", () => {
    const outcome = outcomeFor(["svc", "missing", "data"], [node("svc", "server"), node("data", "data_store")]);
    expect(outcome?.packageHop).toBe("unknown");
  });

  it("names the package when the path has one", () => {
    const outcome = outcomeFor(["svc", "pkg", "cve"], [
      node("svc", "server"), node("pkg", "package", "pillow@9.0.0"), node("cve", "vulnerability"),
    ]);
    expect(outcome?.packageName).toBe("pillow@9.0.0");
    expect(outcome?.packageHop).toBe("present");
  });
});
