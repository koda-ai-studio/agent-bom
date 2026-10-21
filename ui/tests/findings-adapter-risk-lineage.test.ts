import { describe, expect, it } from "vitest";

import type { UnifiedFinding } from "@/lib/api";
import { collectUnifiedFindings } from "@/lib/findings-adapter";

function finding(overrides: Partial<UnifiedFinding>): UnifiedFinding {
  return {
    id: "f-1",
    finding_type: "CVE",
    severity: "high",
    title: "CVE-2022-0235: node-fetch@2.6.1",
    cve_id: "CVE-2022-0235",
    asset: { name: "node-fetch", asset_type: "package" },
    ...overrides,
  } as UnifiedFinding;
}

describe("collectUnifiedFindings risk + lineage", () => {
  it("keeps an unassessed risk unassessed instead of scoring it 0", () => {
    const [row] = collectUnifiedFindings([finding({ risk_score: null })]);
    expect(row?.risk_score).toBeUndefined();
  });

  it("keeps a real score, including an assessed zero", () => {
    expect(collectUnifiedFindings([finding({ risk_score: 7.2 })])[0]?.risk_score).toBe(7.2);
    expect(collectUnifiedFindings([finding({ risk_score: 0 })])[0]?.risk_score).toBe(0);
  });

  it("carries the dependency lineage the API reports", () => {
    const [row] = collectUnifiedFindings([finding({ is_direct: false, dependency_depth: 2, introduced_via: "requests" })]);
    expect([row?.is_direct, row?.dependency_depth, row?.introduced_via]).toEqual([false, 2, "requests"]);
  });
});
