import { expect, it } from "vitest";
import { queryStaticFindings } from "@/lib/static-demo-findings.mjs";

it("sorts by the requested recorded signal, not the unrelated risk score", () => {
  const findings = [
    { id: "cvss", cvss_score: 9.8, risk_score: 10, effective_reach_score: 20 },
    { id: "reach", cvss_score: 7.5, risk_score: 5, effective_reach_score: 90 },
    { id: "risk", cvss_score: 5, risk_score: 99 },
  ];
  expect(queryStaticFindings({ findings }, "/v1/findings?sort=cvss").findings.map(row => row.id)).toEqual(["cvss", "reach", "risk"]);
  expect(queryStaticFindings({ findings }, "/v1/findings?sort=effective_reach").findings.map(row => row.id)).toEqual(["reach", "cvss", "risk"]);
});

it("does not turn missing sample data into a clean result", () => {
  expect(() => queryStaticFindings({}, "/v1/findings")).toThrow(/dataset/i);
});

it("keeps all recorded domain memberships when grouping occurrences", () => {
  const findings = [
    { id: "a", cve_id: "CVE-2025-1000", package_name: "sample", finding_type: "vulnerability", domains: ["vuln"] },
    { id: "b", cve_id: "CVE-2025-1000", package_name: "sample", finding_type: "vulnerability", domains: ["aspm"] },
  ];
  const result = queryStaticFindings({ findings }, "/v1/findings?group_occurrences=true");
  expect(result.total).toBe(1);
  expect(result.facets.domain).toEqual({ vuln: 1, aspm: 1 });
});
