import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { GraphFindingContext } from "@/components/graph-finding-context";

it("shows recorded source, priority factors and remediation without claiming a fix", () => {
  render(<GraphFindingContext data={{ nodeType: "misconfiguration", label: "Token finding", severity: "high", attributes: { file_path: ".github/workflows/publish.yaml", start_line: 12, recommendation: "Use short-lived credentials" } }} />);
  expect(screen.getByText(".github/workflows/publish.yaml:12")).toBeVisible();
  expect(screen.getByText("Use short-lived credentials")).toBeVisible();
  expect(screen.getByText(/High severity/)).toBeVisible();
  expect(screen.getByText(/not a verified fix/)).toBeVisible();
});
it("exposes missing context without inventing source, remediation or exploitation", () => {
  render(<GraphFindingContext data={{ nodeType: "vulnerability", label: "CVE-example" }} />);
  expect(screen.getByText("Source location not recorded")).toBeVisible();
  expect(screen.getByText("Remediation not recorded")).toBeVisible();
  expect(screen.queryByText(/Known exploited/)).not.toBeInTheDocument();
});
