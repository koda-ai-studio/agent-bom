import { describe, expect, it } from "vitest";

import { plainRelationshipSummary } from "@/lib/graph-relationship-plain";
import type { UnifiedEdge } from "@/lib/graph-schema";

const base: UnifiedEdge = { id: "e", source: "a", target: "b", relationship: "vulnerable_to", direction: "directed", weight: 1, traversable: true,
  first_seen: "2026-08-30T04:01:00+00:00", last_seen: "2026-08-30T04:01:00+00:00", evidence: {}, activity_id: 0 };

describe("plain relationship summary", () => {
  it("leads with a specific reason, a human source and the evidence kind for an advisory match", () => {
    const summary = plainRelationshipSummary({ ...base, evidence: { tier: "static_scan", source: "bundled_advisory_scanner", source_kind: "bundled_advisory_scanner" } }, "pillow@9.0.0", "CVE-2023-4863");
    expect(summary).toEqual({
      why: "pillow@9.0.0 is recorded as affected by CVE-2023-4863.",
      source: "Bundled advisory database",
      kind: "Static — read from files, manifests or configuration",
      freshness: "Recorded 2026-08-30 04:01 UTC (link record time, not source activity)",
      unknown: "Whether the vulnerable code is loaded or reachable at runtime.",
    });
  });

  it("keeps configured access distinct from observed access", () => {
    const configured = plainRelationshipSummary({ ...base, relationship: "can_access", evidence: { tier: "modeled_infrastructure", source: "identity_model" } }, "TICKETING_API_KEY", "customer-ticket-archive");
    expect(configured.kind).toBe("Modeled — derived from collected configuration, not observed");
    expect(configured.unknown).toBe("Whether this access was ever exercised.");
    const observed = plainRelationshipSummary({ ...base, relationship: "can_access", evidence: { tier: "runtime_observed", source: "gateway_runtime", observed_at: "2026-09-01T01:00:00Z" } }, "agent", "store");
    expect(observed.kind).toBe("Observed at runtime");
    expect(observed.freshness).toBe("Observed 2026-09-01 01:00 UTC");
    expect(observed.unknown).toBe("What was accessed beyond this recorded activity.");
  });

  it("says what is missing instead of inventing a source or time", () => {
    const summary = plainRelationshipSummary({ ...base, relationship: "future_link", evidence: {}, last_seen: "" }, "A", "B");
    expect(summary.source).toBe("Not recorded");
    expect(summary.kind).toBe("Not recorded");
    expect(summary.freshness).toBe("Not recorded");
    expect(summary.why).toBe("The snapshot records a link from A to B.");
  });

  it("humanizes an unknown collector id without dropping it", () => {
    expect(plainRelationshipSummary({ ...base, evidence: { source: "warehouse-export:snowflake" } }, "A", "B").source).toBe("Warehouse export: snowflake");
  });

  it("says where a workload runs", () => {
    expect(plainRelationshipSummary({ ...base, relationship: "hosted_on", evidence: {} }, "cluster-ops", "compute-00").why).toBe("cluster-ops runs on compute-00.");
  });
});
