import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { GraphProjectionNotice } from "@/components/graph-projection-notice";

describe("graph projection freshness", () => {
  it("keeps completed views quiet", () => {
    render(<GraphProjectionNotice onRetry={() => {}} />);
    expect(screen.queryByRole("status")).toBeNull();
  });
  it("identifies a previous view and offers an accessible refresh", () => {
    const retry = vi.fn();
    render(<GraphProjectionNotice coverage={{ refresh_status: "building", freshness: "previous_generation" }} onRetry={retry} />);
    expect(screen.getByRole("status").textContent).toContain("previous complete view");
    fireEvent.click(screen.getByRole("button", { name: "Check for updates" }));
    expect(retry).toHaveBeenCalledOnce();
  });
  it("names when the previous view's data was recorded", () => {
    const asOf = "2026-11-14T09:30:00+00:00";
    render(<GraphProjectionNotice coverage={{ refresh_status: "building", freshness: "previous_generation", as_of: asOf }} onRetry={() => {}} />);
    expect(screen.getByRole("status").textContent).toContain(`showing data from ${new Date(asOf).toLocaleString()}`);
  });
  it("never shows an invalid time", () => {
    render(<GraphProjectionNotice coverage={{ refresh_status: "building", freshness: "previous_generation", as_of: "not-a-time" }} onRetry={() => {}} />);
    expect(screen.getByRole("status").textContent).toContain("previous complete view");
    expect(screen.getByRole("status").textContent).not.toContain("Invalid");
  });
});
