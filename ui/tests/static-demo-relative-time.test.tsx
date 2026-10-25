import { render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const SNAPSHOT = "2026-06-03T20:30:00Z";
const DUE_A_WEEK_AFTER_SNAPSHOT = "2026-06-10T20:30:00Z";

beforeEach(async () => {
  vi.resetModules();
  vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-10-25T12:00:00Z") });
  vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
  vi.stubGlobal("fetch", vi.fn(async () => new Response(
    JSON.stringify({ schema_version: "static-demo-routes.v1", snapshot_at: SNAPSHOT, routes: ["/"] }), { status: 200 },
  )));
  const { loadStaticDemoRoutes } = await import("@/lib/static-demo-routes");
  await loadStaticDemoRoutes();
});

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("relative times in the static demo are measured from the sample snapshot", () => {
  it("overview risk card: SLA a week after the snapshot is due, not months overdue", async () => {
    const { RiskOwnershipLine } = await import("@/components/overview/risk-ownership-line");
    render(<RiskOwnershipLine ownership={{ owner: "platform", sla_due_at: DUE_A_WEEK_AFTER_SNAPSHOT }} />);
    expect(screen.getByText("Due in 7 days")).toBeInTheDocument();
  });

  it("findings table SLA label", async () => {
    const { formatSlaDue } = await import("@/lib/findings-view");
    expect(formatSlaDue(DUE_A_WEEK_AFTER_SNAPSHOT)?.label).toBe("SLA in 7d");
  });

  it("finding ownership summary", async () => {
    const { ownershipSummary } = await import("@/lib/finding-ownership");
    expect(ownershipSummary({ owner: null, sla_due_at: DUE_A_WEEK_AFTER_SNAPSHOT }).slaState).toBe("due");
  });

  it("uses the wall clock outside the demo", async () => {
    vi.unstubAllEnvs();
    const { formatSlaDue } = await import("@/lib/findings-view");
    expect(formatSlaDue(DUE_A_WEEK_AFTER_SNAPSHOT)?.label).toMatch(/^SLA overdue \d+d$/);
  });
});
