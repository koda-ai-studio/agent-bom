import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { SeverityTrend } from "@/components/severity-trend";
import { severityTrend } from "@/lib/severity-trend";

const point = (timestamp: string, critical: number, high: number) => ({ timestamp, critical, high, medium: 0, low: 0, total_vulns: critical + high, posture_score: 0, posture_grade: "F" });

describe("severity trend", () => {
  it("orders snapshots oldest first and reports the change in critical findings", () => {
    const trend = severityTrend([point("2026-10-17T02:00:00Z", 103, 448), point("2026-10-10T02:00:00Z", 105, 460)]);
    expect(trend.status).toBe("series");
    expect(trend.points.map((p) => p.critical)).toEqual([105, 103]);
    expect(trend.criticalDelta).toBe(-2);
    expect(trend.highDelta).toBe(-12);
  });

  it("says a single snapshot is a single snapshot", () => {
    expect(severityTrend([point("2026-10-17T02:00:00Z", 3, 1)]).status).toBe("single");
    expect(severityTrend([]).status).toBe("none");
  });
});

describe("severity trend panel", () => {
  it("renders critical and high over the snapshots with the direction of change", () => {
    render(<SeverityTrend points={[point("2026-10-10T02:00:00Z", 105, 460), point("2026-10-17T02:00:00Z", 103, 448)]} />);
    expect(screen.getByRole("img", { name: /Critical and high findings across 2 snapshots/ })).toBeVisible();
    expect(screen.getByText("103")).toBeVisible();
    expect(screen.getByText(/critical now · 2 fewer than the first snapshot/)).toBeVisible();
    expect(screen.getByText(/KEV counts are not recorded per snapshot/)).toBeVisible();
  });

  it("explains a one-snapshot history plainly instead of an error", () => {
    render(<SeverityTrend points={[point("2026-10-17T02:00:00Z", 3, 1)]} />);
    expect(screen.getByText(/One snapshot so far/)).toBeVisible();
    expect(screen.queryByText(/missing comparison metadata/i)).toBeNull();
  });
});
