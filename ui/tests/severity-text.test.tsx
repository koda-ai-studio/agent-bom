import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge } from "@/components/severity-badge";
import { severityText } from "@/lib/api";

describe("severity text", () => {
  it("marks a defaulted severity as unscored and leaves rated ones alone", () => {
    expect(severityText("medium", { severity_source: "osv_heuristic" })).toBe("medium (unscored)");
    expect(severityText("low", { severity_source: "advisory:GHSA-79v4-65xg-pq4g" })).toBe("low");
    expect(severityText("high", { severity_source: "cvss" })).toBe("high");
    expect(severityText("medium")).toBe("medium");
  });

  it("prefers the label the API computed", () => {
    expect(severityText("medium", { severity_label: "medium (unscored)", severity_source: "cvss" })).toBe("medium (unscored)");
  });

  it("renders the unscored qualifier in the badge", () => {
    render(<SeverityBadge severity="medium" severitySource="ghsa_heuristic" />);
    expect(screen.getByText("medium (unscored)")).toBeInTheDocument();
  });
});
