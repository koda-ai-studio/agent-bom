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
    expect(configured.why).toBe("TICKETING_API_KEY is modeled as able to access customer-ticket-archive.");
    expect(configured.kind).toBe("Modeled — derived from collected configuration, not observed");
    expect(configured.unknown).toBe("Whether this access was ever exercised.");
    const observed = plainRelationshipSummary({ ...base, relationship: "can_access", evidence: { tier: "runtime_observed", source: "gateway_runtime", observed_at: "2026-09-01T01:00:00Z" } }, "agent", "store");
    expect(observed.kind).toBe("Observed at runtime");
    expect(observed.freshness).toBe("Observed 2026-09-01 01:00 UTC");
    expect(observed.unknown).toBe("Whether access succeeded unless the receipt records that outcome, and what occurred beyond it.");
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
    expect(plainRelationshipSummary({ ...base, relationship: "hosted_on", evidence: {} }, "cluster-ops", "compute-00").why).toBe("The snapshot links cluster-ops to compute-00 as hosted on; the evidence basis is not recorded.");
  });
});

it.each([
  ["static_scan", "A is configured with access to B."],
  ["modeled_infrastructure", "A is modeled as able to access B."],
  ["runtime_observed", "A recorded can access observation links A to B; its outcome is limited to the receipt."],
  ["legacy_unrecorded", "The snapshot links A to B as can access; the evidence basis is not recorded."],
])("qualifies access with %s evidence", (tier, why) => {
  expect(plainRelationshipSummary({ ...base, relationship: "can_access", evidence: { tier } }, "A", "B").why).toBe(why);
});

it("never describes blocked access as successful or a recorded inventory receipt as runtime", () => {
  const blocked = plainRelationshipSummary({ ...base, relationship: "can_access", evidence: { tier: "runtime_observed", blocked: true } }, "A", "B");
  expect(blocked.why).toContain("attempt to access B blocked");
  expect(blocked.unknown).toContain("this attempt was blocked");
  const recorded = plainRelationshipSummary({ ...base, relationship: "hosted_on", evidence: { tier: "recorded" } }, "A", "B");
  expect(recorded.kind).toBe("Recorded observation");
  expect(recorded.why).not.toContain("runs on");
});

it("keeps a registered network binding distinct from effective reachability and observed traffic", () => {
  const summary = plainRelationshipSummary({ ...base, relationship: "exposed_to",
    evidence: { source: "cloud-inventory", tier: "static_scan", reason: "registered_load_balancer_target", network_reachability: "unknown" } }, "frontend", "private VM");
  expect(summary.why).toBe("Collected configuration links frontend to private VM; effective network reachability is unknown.");
  expect(summary.unknown).toContain("routes, firewall rules and listeners");
  expect(summary.unknown).toContain("observed traffic");
  expect(summary.kind).toContain("Static");
});

it("explains owner-scope conflicts without presenting a confirmed relationship", () => {
  const summary = plainRelationshipSummary({ ...base, relationship: "owns",
    evidence: { source: "cloud-inventory", tier: "static_scan", identity_scope_status: "conflict" } }, "account", "asset");
  expect(summary.why).toContain("owner scope conflicts");
  expect(summary.kind).toBe("Unresolved identity scope");
  expect(summary.unknown).toContain("account, subscription or project");
});
