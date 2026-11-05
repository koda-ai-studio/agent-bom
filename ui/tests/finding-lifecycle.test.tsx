import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { FindingStatusSelect, LifecycleDate, openOccurrenceLabel, parseFindingStatus } from "@/components/finding-lifecycle";
import { collectUnifiedFindings } from "@/lib/findings-adapter";

describe("finding lifecycle controls", () => {
  it("defaults an unknown status to the open view", () => {
    expect(parseFindingStatus(null)).toBe("open");
    expect(parseFindingStatus("nonsense")).toBe("open");
    expect(parseFindingStatus("resolved")).toBe("resolved");
    expect(parseFindingStatus("all")).toBe("all");
  });

  it("offers open, resolved and all", () => {
    const onChange = vi.fn();
    render(<FindingStatusSelect value="open" onChange={onChange} />);
    const select = screen.getByRole("combobox", { name: "Finding status" });
    expect(screen.getAllByRole("option").map((option) => option.textContent)).toEqual(["Open", "Resolved", "All statuses"]);
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
    const [row] = collectUnifiedFindings([
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
      },
    ] as never);
    expect(row).toMatchObject({
      lifecycle_status: "reopened",
      last_resolved_at: "2026-10-03T10:00:00+00:00",
      status_updated_at: "2026-10-05T10:00:00+00:00",
      open_occurrence_count: 1,
      resolved_occurrence_count: 1,
    });
  });
});
