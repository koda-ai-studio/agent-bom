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

  it("says where a workload runs only as strongly as the evidence supports", () => {
    const why = (evidence: Record<string, unknown>) => plainRelationshipSummary({ ...base, relationship: "hosted_on", evidence }, "cluster-ops", "compute-00").why;
    expect(why({})).toBe("cluster-ops is recorded as running on compute-00.");
    expect(why({ source: "runtime-proxy" })).toBe("cluster-ops was observed running on compute-00.");
    expect(why({ source: "cloud-inventory" })).toBe("cluster-ops is configured to run on compute-00.");
  });

  const tiers: Array<[string, Record<string, unknown>]> = [
    ["runtime", { tier: "runtime_observed", source: "gateway_runtime" }],
    ["static", { source: "agent_discovery" }],
    ["inferred", { tier: "modeled_infrastructure", source: "identity_model" }],
    ["unknown", {}],
  ];
  const expected: Record<string, Record<string, string>> = {
    can_access: {
      runtime: "A was observed accessing B.", static: "A is configured with access to B.",
      inferred: "A is modeled as able to access B.", unknown: "A is recorded as able to access B.",
    },
    assumes: {
      runtime: "A was observed assuming B.", static: "A is configured to be able to assume B.",
      inferred: "A is modeled as able to assume B.", unknown: "A is recorded as able to assume B.",
    },
    authenticates_as: {
      runtime: "A was observed authenticating as B.", static: "A is configured to authenticate as B.",
      inferred: "A is modeled as authenticating as B.", unknown: "A is recorded as authenticating as B.",
    },
    uses: {
      runtime: "A was observed using B.", static: "A is configured to use B.",
      inferred: "A is modeled as using B.", unknown: "A is recorded as using B.",
    },
    exposes_cred: {
      runtime: "A was observed using the credential B.", static: "A references the credential B in its configuration.",
      inferred: "A is modeled as referencing the credential B.", unknown: "A is recorded as referencing the credential B.",
    },
  };
  for (const [relationship, byMode] of Object.entries(expected)) {
    for (const [mode, evidence] of tiers) {
      it(`words ${relationship} from ${mode} evidence without overstating it`, () => {
        expect(plainRelationshipSummary({ ...base, relationship, evidence }, "A", "B").why).toBe(byMode[mode]);
      });
    }
  }

  it("names a blocked runtime attempt as an attempt", () => {
    const summary = plainRelationshipSummary({ ...base, relationship: "can_access", evidence: { tier: "runtime_observed", source: "gateway_runtime", blocked: true } }, "A", "B");
    expect(summary.why).toBe("A was observed attempting to access B; the attempt was blocked.");
  });
});
