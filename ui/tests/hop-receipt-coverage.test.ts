import { describe, expect, it } from "vitest";

import { hopReceiptCoverage } from "@/lib/hop-receipt-coverage";
import type { AttackPath } from "@/lib/graph-schema";

const receipt = (source: string, target: string, relationship: string, overrides: Record<string, unknown> = {}) => ({
  source_node_id: source, target_node_id: target, relationship, source_snapshot_ids: ["scan-1"],
  relationship_provenance: "recorded", correlation_identity_status: "current", evidence_tier: "static_scan",
  confidence: 1, freshness: "fresh", runtime_observed_state: "not_observed", direction: "directed",
  traversable: true, complete: true, truncated: false, ...overrides,
});

const path = (hopEvidence: unknown[], analysis?: string) => ({
  source: "agent:a", target: "cve:c",
  hops: ["agent:a", "server:s", "pkg:p", "cve:c"],
  edges: ["uses", "depends_on", "vulnerable_to"],
  hop_evidence: hopEvidence,
  ...(analysis ? { analysis: { status: analysis } } : {}),
}) as unknown as AttackPath;

describe("hopReceiptCoverage copy", () => {
  it("says once, in plain words, that no hop has recorded evidence", () => {
    const coverage = hopReceiptCoverage(path([]));
    expect(coverage.summary).toBe("No evidence recorded for 3 hops");
    expect(coverage.gaps).toEqual(["no record that the full path was analyzed"]);
  });

  it("counts fully evidenced hops without repeating the receipt count", () => {
    const coverage = hopReceiptCoverage(path([
      receipt("agent:a", "server:s", "uses"),
      receipt("server:s", "pkg:p", "depends_on", { freshness: "unknown" }),
      receipt("pkg:p", "cve:c", "vulnerable_to", { relationship_provenance: "unavailable" }),
    ], "complete"));
    expect(coverage.summary).toBe("1 of 3 hops fully evidenced");
    expect(coverage.gaps).toEqual(["evidence age unknown", "source of the link not recorded"]);
  });

  it("names hops that have no evidence at all", () => {
    const coverage = hopReceiptCoverage(path([receipt("agent:a", "server:s", "uses")], "limited"));
    expect(coverage.summary).toBe("1 of 3 hops fully evidenced · 2 with no evidence recorded");
    expect(coverage.gaps).toEqual(["path analysis stopped at its limits"]);
  });

  it("never claims more evidence than recorded", () => {
    const coverage = hopReceiptCoverage(path([
      receipt("agent:a", "server:s", "uses", { complete: false, traversable: false }),
    ]));
    expect(coverage.evidenced).toBe(0);
    expect(coverage.summary).toBe("0 of 3 hops fully evidenced · 2 with no evidence recorded");
    expect(coverage.gaps).toEqual([
      "evidence marked incomplete by its source",
      "link not confirmed as traversable",
      "no record that the full path was analyzed",
    ]);
  });
});
