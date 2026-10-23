import { describe, expect, it } from "vitest";

import { graphEdgeEvidence, graphEdgeEvidenceLabel } from "@/lib/graph-edge-evidence";

describe("graphEdgeEvidence", () => {
  it("reads the recorded tier and source directly", () => {
    expect(graphEdgeEvidence({ source: "cloud-inventory", tier: "modeled_infrastructure" })).toEqual({
      label: "Modeled",
      mode: "inferred",
      blocked: false,
      source: "cloud-inventory",
    });
    expect(graphEdgeEvidence({ source: "mcp-scan", tier: "static_scan" }).mode).toBe("static");
    expect(graphEdgeEvidence({ source: "runtime-proxy", tier: "runtime_observed" }).mode).toBe("runtime");
    expect(graphEdgeEvidence({ source: "graph-analysis", tier: "derived", derived_via: "x" }).label).toBe("Derived");
  });

  it("does not classify the retired heuristic tier as a static scan", () => {
    expect(graphEdgeEvidence({ tier: "static_evidence" }).mode).toBe("unknown");
    expect(graphEdgeEvidence({ evidence_tier: "static_evidence" }).label).toBe("Unclassified");
  });

  it("lets a blocked runtime receipt override the tier", () => {
    const result = graphEdgeEvidence({ source: "runtime-proxy", tier: "runtime_observed", blocked: true });
    expect(result).toMatchObject({ label: "Runtime blocked", blocked: true, mode: "runtime" });
  });

  it("keeps the heuristic for snapshots written before the envelope", () => {
    expect(graphEdgeEvidence({ source: "source-ast" }).label).toBe("Static / configured");
    expect(graphEdgeEvidence({ evidence_tier: "runtime_observed" }).label).toBe("Runtime observed");
    expect(graphEdgeEvidence({}).label).toBe("Not recorded");
  });

  it("an unknown tier falls back to the heuristic rather than inventing a label", () => {
    expect(graphEdgeEvidence({ tier: "made_up", source: "cloud-inventory" }).label).toBe("Static / configured");
  });

  it("labels legacy rehydrated edges as not recorded, with the scan origin", () => {
    expect(
      graphEdgeEvidenceLabel({ evidence: { source: "legacy_snapshot", tier: "legacy_unrecorded" }, source_scan_id: "s1" }),
    ).toBe("Scan inventory · no per-edge receipt");
  });
});


it.each(["external-import", "kubernetes", "authorization-evidence"])("does not promote %s recorded inventory into runtime activity", source => {
  expect(graphEdgeEvidence({ tier: "recorded", source })).toMatchObject({ mode: "recorded", label: "Recorded observation", blocked: false });
});
