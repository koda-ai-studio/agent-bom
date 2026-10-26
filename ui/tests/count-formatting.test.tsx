import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SeverityIssueStrip } from "@/components/overview/issue-strip";
import { StatStrip } from "@/components/stat-strip";
import { formatCount } from "@/lib/count-label";

describe("large counts carry thousands separators", () => {
  it("formats numbers but leaves preformatted strings alone", () => {
    expect(formatCount(12345)).toBe("12,345");
    expect(formatCount("92%")).toBe("92%");
  });

  it("formats stat strip values", () => {
    render(<StatStrip items={[{ label: "Findings", value: 12345 }]} />);
    expect(screen.getByText("12,345")).toBeInTheDocument();
  });

  it("formats the overview severity bands", () => {
    render(
      <SeverityIssueStrip
        summaryReady
        critical={1234}
        high={56789}
        kev={null}
        credentials={null}
        severity={{ critical: 1234, high: 56789, medium: 10000, low: 2500, unknown: 0 } as never}
        matrix={null}
      />,
    );
    expect(screen.getByText("1,234")).toBeInTheDocument();
    expect(screen.getByText("56,789")).toBeInTheDocument();
    expect(screen.getByText("10,000")).toBeInTheDocument();
  });
});
