import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { GraphRiskContext } from "@/components/graph-risk-context";

afterEach(cleanup);

const jewel = {
  risk_context: {
    version: 1, scan_id: "scan-7", sources: ["aws", "cnapp-overlay"], internet_exposed: false, privilege_level: null, is_admin: null,
    data_sensitivity: "phi", crown_jewel: true,
    reasons: [
      { field: "internet_exposed", rule: "recorded_not_public", attribute: "publicly_accessible", value: false },
      { field: "data_sensitivity", rule: "recorded_data_sensitivity", attribute: "data_sensitivity", value: "phi" },
      { field: "crown_jewel", rule: "sensitive_data_store", attribute: "data_sensitivity", value: "phi" },
    ],
  },
};

describe("GraphRiskContext", () => {
  it("lists every verdict with the recorded fact and scan behind it", () => {
    render(<GraphRiskContext attributes={jewel} />);
    const section = screen.getByRole("region", { name: "Risk context" });
    expect(within(section).getByText("Crown jewel")).toBeInTheDocument();
    expect(within(section).queryByText("Internet-exposed")).toBeNull();
    expect(within(section).getByText("Sensitive data")).toBeInTheDocument();
    const reasons = within(section).getAllByRole("listitem").map(item => item.textContent);
    expect(reasons).toEqual([
      "Internet-exposed: recorded publicly_accessible = false",
      "Sensitive data: phi",
      "Crown jewel: data store holding phi data",
    ]);
    expect(within(section).getByText(/scan-7/)).toHaveTextContent("Scan scan-7 · sources aws, cnapp-overlay");
  });

  it("renders nothing without a stored context", () => {
    const { container } = render(<GraphRiskContext attributes={{ internet_exposed: true }} />);
    expect(container).toBeEmptyDOMElement();
  });
});
