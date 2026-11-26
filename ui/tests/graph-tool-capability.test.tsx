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
