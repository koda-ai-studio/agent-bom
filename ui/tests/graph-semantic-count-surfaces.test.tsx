import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { GraphHeadlineMetrics } from "@/components/graph-headline-metrics";
import { GraphCorrelationWorkflow } from "@/components/graph-correlation-workflow";
import type { GraphPageModel } from "@/components/graph-page-view";
import type { GraphCorrelationRun } from "@/lib/api";

const counts = { retained_count: 23, assessed_count: 71, basis: "derived_graph_paths" };
const page = (attackPaths: unknown) => ({ investigationMode: false, firstFramePending: false, selectedAttackPath: null,
  snapshotAttackPathCount: 999, graphData: { stats: { attack_paths: attackPaths } },
  flow: { summary: { findings: 0, findingSeverity: { critical: 0, high: 0, medium: 0, low: 0, unrated: 0 }, kevListed: 0, costUsd30d: 0, expensiveExposed: 0 } },
}) as unknown as GraphPageModel;

it("reads retained and assessed totals in the header rather than a legacy page total", () => {
  render(<GraphHeadlineMetrics page={page(counts)} />);
  expect(screen.getByTestId("graph-headline-metrics")).toHaveTextContent("23 attack paths");
  expect(screen.getByTestId("graph-headline-metrics")).toHaveTextContent("71 assessed");
  expect(screen.getByTestId("graph-headline-metrics")).not.toHaveTextContent("999");
});

it("does not render missing path counts as zero", () => {
  render(<GraphHeadlineMetrics page={page(undefined)} />);
  expect(screen.getByTestId("graph-headline-metrics")).toHaveTextContent("Attack path count unavailable");
});

it("reads the same retained and assessed totals in correlation receipts", () => {
  const run: GraphCorrelationRun = { correlation_id: "corr", tenant_id: "default", name: "Correlation", status: "complete",
    max_age_hours: 168, allow_stale: false, input_manifest: [], result_manifest: { output: { attack_path_count: 999, attack_paths: counts } },
    manifest_sha256: "", output_scan_id: "corr", failure_code: "", created_at: "2026-11-21T00:00:00Z", started_at: "", completed_at: "" };
  render(<GraphCorrelationWorkflow snapshots={[]} initialRun={run} onOpenSnapshot={() => undefined} />);
  expect(screen.getByTestId("graph-correlation-decision")).toHaveTextContent("23 retained paths");
  expect(screen.getByTestId("graph-correlation-decision")).toHaveTextContent("71 assessed");
  expect(screen.getByTestId("graph-correlation-decision")).not.toHaveTextContent("999");
});
