import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RiskOwnershipLine } from "@/components/overview/risk-ownership-line";

const now = Date.parse("2026-10-19T00:00:00Z");

describe("risk ownership line", () => {
  it("shows the owner/team and the SLA due date on the card", () => {
    render(<RiskOwnershipLine ownership={{ owner: "platform-team", sla_due_at: "2026-10-26T00:00:00Z", sla_due_at_source: "severity-kev/v1" }} now={now} />);
    expect(screen.getByText("platform-team")).toBeVisible();
    expect(screen.getByText(/Due in 7 days/)).toBeVisible();
  });

  it("flags an unowned, overdue risk", () => {
    render(<RiskOwnershipLine ownership={{ owner: null, sla_due_at: "2026-10-16T00:00:00Z", sla_due_at_source: "severity-kev/v1" }} now={now} />);
    expect(screen.getByText("Unassigned")).toBeVisible();
    expect(screen.getByText(/Overdue by 3 days/)).toBeVisible();
  });

  it("renders nothing when ownership was not reported", () => {
    const { container } = render(<RiskOwnershipLine ownership={undefined} now={now} />);
    expect(container).toBeEmptyDOMElement();
  });
});
