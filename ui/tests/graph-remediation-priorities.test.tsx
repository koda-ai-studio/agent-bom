import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { GraphRemediationPriorities } from "@/components/graph-remediation-priorities";
import { InvestigationTools } from "@/components/investigation-path-workspace";
import type { FixFirstGraphViewResponse } from "@/lib/api-contracts/graph-views";

const view: FixFirstGraphViewResponse = {
  scan_id: "scan /one", tenant_id: "tenant-a", created_at: "2026-10-30", cards: [],
  summary: { total_paths: 3, matched_paths: 3, returned_paths: 0, highest_risk: 9, covered_findings: 2, node_count: 7, edge_count: 4 },
  focus: { cve: "", package: "", agent: "" },
  remediation_priorities: {
    schema_version: "graph-remediation-priorities.v1", coverage_basis: "recorded_paths_touching_selected_findings", source_coverage: "not_assessed",
    method: "greedy", assessed_paths: 3, candidate_count: 1, covered_paths: 2, remaining_paths: 1, complete: false,
    limitations: ["node_budget"], path_budget: 5000, recommendation_limit: 5, remediation_verified: false,
    recommendations: [{ id: "fix-a", rank: 1, asset_node_id: "package:a", asset_label: "requests@2.19", finding_node_id: "finding:a",
      finding_label: "Recorded advisory", finding_id: "occurrence:a", fixed_version: "2.32", guidance: "Review upgrading requests to 2.32.",
      covered_paths: 2, newly_covered_paths: 2, critical_paths: 2, high_paths: 0, unknown_reachability_paths: 2,
      remaining_paths_after_selection: 1, path_ids: ["path-a", "path-b"], path_sample_complete: true }],
  },
};

describe("graph remediation priorities", () => {
  it("exposes recommendations through investigation tools with evidence and verification links", () => {
    render(<InvestigationTools scope={<p>Scope</p>} exposure={<p>Paths</p>} priorities={<GraphRemediationPriorities view={view} scanId={view.scan_id} />} />);
    fireEvent.click(screen.getByText(/Investigation tools ·/));
    fireEvent.click(screen.getByRole("button", { name: "Prioritize fixes" }));
    expect(screen.getByRole("region", { name: "Shared remediation priorities" })).toBeVisible();
    expect(screen.getByText(/3 paths assessed/)).toBeVisible();
    expect(screen.getByText(/Coverage does not predict paths removed or prove a fix/)).toHaveTextContent("node budget");
    expect(screen.getByText("Reachability unknown")).toBeVisible();
    const url = new URL(screen.getByRole("link", { name: "Review path evidence" }).getAttribute("href")!, "http://localhost");
    expect(url.searchParams.get("scan")).toBe(view.scan_id);
    expect(url.searchParams.get("node")).toBe("finding:a");
    expect(screen.getByRole("link", { name: "Open verification workflow" })).toHaveAttribute("href", "/remediation?view=verification&scan=scan+%2Fone&finding=occurrence%3Aa#campaigns");
  });

  it("does not show recommendations from another snapshot", () => {
    render(<GraphRemediationPriorities view={view} scanId="different" />);
    expect(screen.getByText(/unavailable for this snapshot/)).toBeVisible();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  it("keeps missing guidance distinct from a clean result", () => {
    render(<GraphRemediationPriorities view={{ ...view, remediation_priorities: { ...view.remediation_priorities!, recommendations: [] } }} scanId={view.scan_id} />);
    expect(screen.getByText(/No applicable recorded guidance/)).toHaveTextContent("not a clean verdict");
  });

  it("does not infer recommendations when an older server omits the field", () => {
    const { remediation_priorities: _priorities, ...legacy } = view;
    render(<GraphRemediationPriorities view={legacy} scanId={view.scan_id} />);
    expect(screen.getByText(/unavailable for this snapshot/)).toBeVisible();
  });
});
