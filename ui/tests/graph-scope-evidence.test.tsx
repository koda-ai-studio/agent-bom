import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { GraphScopeEvidence } from "@/components/graph-scope-evidence";

it("summarizes only visible relationships and preserves mixed and missing evidence", () => {
  render(<GraphScopeEvidence edges={[
    { data: { evidenceLabel: "Runtime observed" } },
    { data: { evidenceLabel: "Modeled" } },
    { data: {} },
  ]} />);
  expect(screen.getByLabelText("Visible relationship evidence")).toHaveTextContent("Mixed evidence");
  expect(screen.getByText(/Runtime observed 1/)).toHaveTextContent("Modeled 1 · Runtime observed 1 · Unknown 1");
});
it("does not promote a recorded observation or blocked attempt to observed execution", () => {
  render(<GraphScopeEvidence edges={[{ data: { evidenceLabel: "Recorded observation" } }, { data: { evidenceLabel: "Runtime blocked" } }]} />);
  expect(screen.getByText(/Recorded observation 1/)).toHaveTextContent("Runtime blocked 1");
  expect(screen.queryByText(/Runtime observed/)).not.toBeInTheDocument();
});
it("keeps an empty scope explicit", () => {
  render(<GraphScopeEvidence edges={[]} />);
  expect(screen.getByText(/No visible relationships/)).toBeVisible();
});

it("does not classify aggregated links as observed when their receipt is unavailable", () => {
  render(<GraphScopeEvidence edges={[{ data: { evidenceMode: "runtime", aggregate: true } }]} />);
  expect(screen.getByLabelText("Visible relationship evidence")).toHaveTextContent("Bundled (expand for evidence)");
});
