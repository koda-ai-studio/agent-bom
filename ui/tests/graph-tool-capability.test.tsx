import { render, screen } from "@testing-library/react";
import { expect, it } from "vitest";
import { OverviewDetails } from "@/components/lineage-detail/overview";
import { shortDate } from "@/components/lineage-detail/fields";

it("discloses recorded shell capability without fabricating a risk assessment", () => {
  render(<OverviewDetails onClose={() => {}} data={{ label: "execute_command", nodeType: "tool", riskScore: 9.5, attributes: { tool_class: "shell", capabilities: ["execute"] } }} />);
  expect(screen.getByText("Shell command execution")).toBeVisible();
  expect(screen.getByText("Not assessed")).toBeVisible();
  expect(screen.queryByText("9.5")).not.toBeInTheDocument();
});
it("renders graph dates unambiguously with a timezone", () => {
  expect(shortDate("2026-06-03T16:30:00Z")).toBe("2026-06-03 16:30 UTC");
});

it("shows the capability assessment separately without an unrelated unknown node score", () => {
  render(<OverviewDetails onClose={() => {}} data={{ label: "shell", nodeType: "server", riskScore: 0, riskAssessment: {status: "not_assessed", basis: null, scope: null}, attributes: { capability_risk: {score: 2.41, level: "low", justification: "Recorded shell tool and credential references.", basis: "mcp_capability_portfolio_risk"} } }} />);
  expect(screen.getByText("2.41/10 · low")).toBeVisible();
  expect(screen.queryByText("Not assessed")).not.toBeInTheDocument();
  expect(screen.queryByText("Node risk score")).not.toBeInTheDocument();
});

it("retains an independently assessed overall risk beside capability risk", () => {
  render(<OverviewDetails onClose={() => {}} data={{ label: "shell", nodeType: "server", riskScore: 9.7, riskAssessment: {status: "assessed", basis: "recorded_vulnerability", scope: "dependency"}, attributes: { capability_risk: {score: 2.41, level: "low", justification: "Recorded shell capability.", basis: "mcp_capability_portfolio_risk"} } }} />);
  expect(screen.getByText("2.41/10 · low")).toBeVisible();
  expect(screen.getByText("Node risk score")).toBeVisible();
  expect(screen.getByText("9.7")).toBeVisible();
});
