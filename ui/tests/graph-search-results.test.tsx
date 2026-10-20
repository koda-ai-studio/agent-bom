import { fireEvent, render, screen, within } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { GraphSearchResults } from "@/components/graph-search-results";
import type { UnifiedNode } from "@/lib/graph-schema";

const node = (id: string, label: string, attributes: Record<string, unknown>, extra: Partial<UnifiedNode> = {}): UnifiedNode => ({
  id, label, entity_type: "data_store", status: "active", risk_score: 0, severity: "", first_seen: "", last_seen: "",
  attributes, compliance_tags: [], data_sources: [], dimensions: { cloud_provider: String(attributes.cloud_provider ?? "") } as UnifiedNode["dimensions"],
  ...extra,
});

describe("GraphSearchResults", () => {
  it("tells same-named results apart by vendor, account and kind", () => {
    const onSelect = vi.fn();
    const results = [
      node("snowflake:stage:NORTHSTAR_00:audit-evidence-staging-4", "audit-evidence-staging-4", { cloud_provider: "snowflake", account_id: "NORTHSTAR_00", resource_type: "stage" }),
      node("aws:bucket:100000000007:audit-evidence-staging-4", "audit-evidence-staging-4", { cloud_provider: "aws", account_id: "100000000007", resource_type: "bucket" }),
    ];
    render(<GraphSearchResults results={results} severity={null} onSelect={onSelect} />);
    const stage = screen.getByTestId("graph-search-result-snowflake:stage:NORTHSTAR_00:audit-evidence-staging-4");
    expect(stage).toHaveTextContent("Stage");
    expect(stage).toHaveTextContent("Snowflake · NORTHSTAR_00");
    expect(within(stage).getByRole("img", { name: /Snowflake/ })).toBeInTheDocument();
    const bucket = screen.getByTestId("graph-search-result-aws:bucket:100000000007:audit-evidence-staging-4");
    expect(bucket).toHaveTextContent("Bucket");
    expect(bucket).toHaveTextContent("AWS · 100000000007");
    expect(bucket).toHaveAttribute("title", "aws:bucket:100000000007:audit-evidence-staging-4");
    expect(bucket).not.toHaveTextContent("Not assessed");
    fireEvent.click(bucket);
    expect(onSelect).toHaveBeenCalledWith(results[1]);
  });

  it("keeps severity and an assessed risk score, and names the scope", () => {
    const finding = node("misconfig:x", "Open SSH", {}, { entity_type: "misconfiguration", severity: "high", risk_score: 7.2, risk_assessment: { status: "assessed", basis: "graph", scope: "node" } });
    render(<GraphSearchResults results={[finding]} severity="high" onSelect={() => {}} />);
    expect(screen.getByText(/Search respects current entity scope and high\+ severity/)).toBeInTheDocument();
    const row = screen.getByTestId("graph-search-result-misconfig:x");
    expect(row).toHaveTextContent("high");
    expect(row).toHaveTextContent("risk 7.2");
  });
});
