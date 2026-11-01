import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BriefControlsAndHistory, BriefPriorities } from "@/components/executive-brief/sections";
import { type BriefPriority, briefTimestamp, slaChipLabel } from "@/lib/executive-brief";

const NOW = Date.parse("2026-11-01T18:40:00Z");
afterEach(() => vi.useRealTimers());

const priority = (overrides: Partial<BriefPriority> = {}): BriefPriority => ({
  vulnerability_id: "CVE-2023-4863", canonical_id: "finding/one", asset_id: "asset-a", package: "pillow@9.0.0", owner: "Data Platform team",
  severity: "critical", sla_due_at: "2026-11-08T18:32:07.903891+00:00", sla_due_at_source: "severity-kev/v1", sla_status: "due_soon", sla_policy: "Severity and KEV policy (v1)", ...overrides,
});
const brief = (rows: unknown[]) => ({
  remediation_priorities: rows, generated_at: "2026-11-01T18:40:18.091236+00:00",
  compliance: { overall_status: "warning", evaluated_controls: 3, total_controls: 20, frameworks: {}, latest_scan: "2026-11-01T18:35:00.123456+00:00" },
  scan_history: { data_points: [{ scan_id: "scan-1", timestamp: "2026-10-30T10:00:00.000001+00:00", comparison: { status: "not_comparable", reason: "different_scope" } }] },
}) as never;

describe("brief timestamps and SLA presentation", () => {
  it("renders relative plus absolute dates without microseconds", () => {
    vi.useFakeTimers(); vi.setSystemTime(NOW);
    expect(briefTimestamp("2026-11-08T18:32:07.903891+00:00")).toMatch(/^in 7 days · 8 Nov 2026/);
    expect(briefTimestamp("2026-11-08T18:32:07.903891+00:00")).not.toMatch(/903891/);
    expect(briefTimestamp(null)).toBe("Not recorded");
    expect(briefTimestamp("control-scan")).toBe("control-scan");
  });
  it("derives the chip from the API status and falls back to the timestamp", () => {
    vi.useFakeTimers(); vi.setSystemTime(NOW);
    expect(slaChipLabel(priority())).toEqual({ label: "Due soon", tone: "warning" });
    expect(slaChipLabel(priority({ sla_status: null, sla_due_at: "2026-10-01T00:00:00Z" }))).toEqual({ label: "Overdue", tone: "danger" });
    expect(slaChipLabel(priority({ sla_status: null, sla_due_at: "2027-01-01T00:00:00Z" }))).toEqual({ label: "On track", tone: "ok" });
    expect(slaChipLabel(priority({ sla_status: null, sla_due_at: null }))).toEqual({ label: "No SLA", tone: "muted" });
  });
  it("shows the policy display name and the chip instead of raw ids", () => {
    vi.useFakeTimers(); vi.setSystemTime(NOW);
    render(<BriefPriorities brief={brief([priority(), priority({ vulnerability_id: "CVE-2", canonical_id: "two", sla_status: null, sla_policy: null, sla_due_at: "2026-10-01T00:00:00Z", sla_due_at_source: "explicit" })])} />);
    expect(screen.getByText("Due soon")).toBeInTheDocument();
    expect(screen.getByText("Overdue")).toBeInTheDocument();
    expect(screen.getByText(/Severity and KEV policy \(v1\)/)).toBeInTheDocument();
    expect(screen.getByText(/Explicit due date/)).toBeInTheDocument();
    expect(screen.queryByText(/severity-kev\/v1/)).toBeNull();
    expect(screen.queryByText(/903891/)).toBeNull();
    expect(screen.getByText(/in 7 days · 8 Nov 2026/)).toBeInTheDocument();
  });
  it("humanizes control-evidence and scan-history timestamps", () => {
    vi.useFakeTimers(); vi.setSystemTime(NOW);
    render(<BriefControlsAndHistory brief={brief([])} />);
    expect(screen.getByText(/Latest scan: 5 minutes ago · 1 Nov 2026/)).toBeInTheDocument();
    expect(screen.getByText(/2 days ago · 30 Oct 2026/)).toBeInTheDocument();
    expect(screen.queryByText(/000001/)).toBeNull();
  });
});
