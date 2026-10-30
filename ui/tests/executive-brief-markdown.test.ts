import { expect, it } from "vitest";
import { briefMarkdown, type ExecutiveBrief } from "@/lib/executive-brief";
import { buildStaticExecutiveBrief } from "../scripts/static-demo-brief.mjs";
const makeBrief = () => buildStaticExecutiveBrief({
  overview: { issue_counts: { total: 3, critical: 1, high: 1, kev: 0 }, top_risks: [{ vulnerability_id: "<script>|\n# injected", owner: "[owner](https://untrusted.example)" }] },
  posture: { summary: "Sample posture" }, compliance: { overall_status: "unknown", evaluated_controls: 0, total_controls: 12 },
  history: { data_points: [{ scan_id: "history-one", timestamp: "2026-10-29" }] },
  graph: { nodes: [{ id: "a", label: "Agent" }, { id: "b", label: "Finding" }], attack_paths: [{ source: "a", target: "b", severity: "high" }] },
  tenantId: "sample-tenant", scanId: "graph-one", snapshotAt: "2026-10-30",
}) as ExecutiveBrief;
it("preserves sample provenance, source scope, incomplete evidence and inert labels in Markdown", () => {
  const brief = makeBrief(); const text = briefMarkdown(brief);
  expect(text).toContain("Sample data"); expect(text).toContain("graph-one");
  expect(text).toContain("Open issues: 3"); expect(text).toContain("Collection coverage: unknown");
  expect(text).toContain("Sample history does not record comparable scope");
  expect(text).not.toContain("<script>"); expect(text).not.toContain("\n# injected");
  expect(text).not.toContain("[owner](https://untrusted.example)");
  expect(text).toContain("independent_source_reads");
});
it("never converts an unavailable path read into zero exposure", () => {
  const brief = makeBrief(); brief.exposure_status = "unavailable"; brief.exposure_paths = null;
  expect(briefMarkdown(brief)).toContain("Path evidence unavailable");
  expect(briefMarkdown(brief)).not.toContain("No paths returned");
});
it("composes sample counts and paths from the same estate without inventing ownership or comparison", () => {
  const brief = makeBrief();
  expect(brief.issues.total).toBe(3); expect(brief.exposure_paths?.paths).toHaveLength(1);
  expect(brief.exposure_paths?.paths[0]).toMatchObject({ source: { id: "a", label: "Agent" }, reachability: "unknown" });
  expect(brief.scan_history.data_points[0]?.comparison?.status).toBe("not_comparable");
});
it("uses the supported findings text filter when an occurrence identifier is absent", async () => {
  const { briefFindingHref } = await import("@/lib/executive-brief");
  expect(briefFindingHref(makeBrief().remediation_priorities[0]!)).toBe("/findings?q=%3Cscript%3E%7C%0A%23+injected");
});
