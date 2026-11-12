import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import {
  FindingStatusSelect,
  LifecycleDate,
  lifecycleSummary,
  openOccurrenceLabel,
  parseFindingStatus,
  resolutionReasonLabel,
} from "@/components/finding-lifecycle";
import { FindingLaneTable } from "@/components/finding-lane-table";
import { collectUnifiedFindings } from "@/lib/findings-adapter";

describe("finding lifecycle controls", () => {
  it("defaults an unknown status to the open view", () => {
    expect(parseFindingStatus(null)).toBe("open");
    expect(parseFindingStatus("nonsense")).toBe("open");
    expect(parseFindingStatus("resolved")).toBe("resolved");
    expect(parseFindingStatus("all")).toBe("all");
    expect(parseFindingStatus("stale")).toBe("stale");
  });

  it("names why a finding resolved, and nothing for an unknown reason", () => {
    expect(resolutionReasonLabel("no_longer_detected")).toBe("No longer detected");
    expect(resolutionReasonLabel("asset_deleted")).toBe("Asset deleted");
    expect(resolutionReasonLabel(null)).toBeNull();
    expect(resolutionReasonLabel("other")).toBeNull();
  });

  it("summarizes status with the resolution reason", () => {
    expect(lifecycleSummary({ lifecycle_status: "resolved", resolved_at: "2026-10-03T10:00:00+00:00", resolution_reason: "asset_deleted" })).toBe("Resolved · asset deleted");
    expect(lifecycleSummary({ lifecycle_status: "resolved", resolved_at: "2026-10-03T10:00:00+00:00", resolution_reason: "no_longer_detected" })).toBe("Resolved · no longer detected");
    expect(lifecycleSummary({ lifecycle_status: "open", stale: true })).toBe("Open · stale");
    expect(lifecycleSummary({ lifecycle_status: "reopened" })).toBe("Reopened");
    expect(lifecycleSummary({ lifecycle_status: "suppressed" })).toBe("Suppressed · not verified fixed");
    expect(lifecycleSummary({})).toBeNull();
  });

  it("shows why a cloud finding left the open queue, and stays quiet for a plain open one", () => {
    const base = { id: "f-1", summary: "CIS-5.2", severity: "high", finding_type: "CIS_FAIL", affected_agents: [], affected_servers: [], affected_packages: [], packages: [] };
    const { rerender } = render(<FindingLaneTable lane="cloud" onSelect={vi.fn()} findings={[{ ...base, lifecycle_status: "resolved", resolved_at: "2026-10-03T10:00:00+00:00", resolution_reason: "asset_deleted" }] as never} />);
    expect(screen.getByText("Resolved · asset deleted")).toBeInTheDocument();
    rerender(<FindingLaneTable lane="cloud" onSelect={vi.fn()} findings={[{ ...base, lifecycle_status: "open", stale: true }] as never} />);
    expect(screen.getByText("Open · stale")).toBeInTheDocument();
    rerender(<FindingLaneTable lane="cloud" onSelect={vi.fn()} findings={[{ ...base, lifecycle_status: "open" }] as never} />);
    expect(screen.queryByText(/^Open/)).toBeNull();
  });

  it("offers open, stale, resolved and all", () => {
    const onChange = vi.fn();
    render(<FindingStatusSelect value="open" onChange={onChange} />);
    const select = screen.getByRole("combobox", { name: "Finding status" });
    expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual(["Open", "Stale", "Resolved", "All statuses"]);
    fireEvent.change(select, { target: { value: "resolved" } });
    expect(onChange).toHaveBeenCalledWith("resolved");
  });

  it("renders a date only when one exists", () => {
    const { container, rerender } = render(<LifecycleDate label="Resolved" value={null} />);
    expect(container).toBeEmptyDOMElement();
    rerender(<LifecycleDate label="Resolved" value="2026-10-03T10:00:00+00:00" />);
    expect(screen.getByText(/^Resolved: /)).toHaveAttribute("datetime", "2026-10-03T10:00:00+00:00");
  });

  it("labels a partly fixed issue and stays quiet otherwise", () => {
    expect(openOccurrenceLabel(1, 1)).toBe("1 of 2 open");
    expect(openOccurrenceLabel(2, 0)).toBeNull();
    expect(openOccurrenceLabel(0, 2)).toBeNull();
    expect(openOccurrenceLabel(undefined, undefined)).toBeNull();
  });

  it("carries the API lifecycle fields through the adapter", () => {
    const [row, resolvedRow] = collectUnifiedFindings([
      {
        id: "finding-1",
        cve_id: "CVE-2021-33503",
        severity: "high",
        package: "urllib3",
        package_version: "1.26.4",
        status: "reopened",
        first_seen: "2026-10-01T10:00:00+00:00",
        last_seen: "2026-10-05T10:00:00+00:00",
        reopened_at: "2026-10-05T10:00:00+00:00",
        last_resolved_at: "2026-10-03T10:00:00+00:00",
        status_updated_at: "2026-10-05T10:00:00+00:00",
        open_occurrence_count: 1,
        resolved_occurrence_count: 1,
        stale: true,
        resolution_reason: null,
        resolved_by_scan_id: null,
      },
      {
        id: "finding-2",
        cve_id: "CVE-2023-43804",
        severity: "medium",
        package: "urllib3",
        package_version: "1.26.4",
        status: "resolved",
        resolved_at: "2026-10-03T10:00:00+00:00",
        resolution_reason: "no_longer_detected",
        scan_id: "scan-saw-it",
        resolved_by_scan_id: "scan-cleared-it",
      },
    ] as never);
    expect(row).toMatchObject({
      lifecycle_status: "reopened",
      stale: true,
      last_resolved_at: "2026-10-03T10:00:00+00:00",
      status_updated_at: "2026-10-05T10:00:00+00:00",
      open_occurrence_count: 1,
      resolved_occurrence_count: 1,
      resolved_by_scan_id: null,
    });
    expect(resolvedRow).toMatchObject({ lifecycle_status: "resolved", scan_id: "scan-saw-it", resolved_by_scan_id: "scan-cleared-it" });
  });
});
