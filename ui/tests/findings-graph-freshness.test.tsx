import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { FindingsGraphFreshnessNote } from "@/components/graph-projection-notice";

describe("findings graph freshness note", () => {
  it("stays quiet when the graph is current", () => {
    render(<FindingsGraphFreshnessNote freshness={null} />);
    expect(screen.queryByRole("status")).toBeNull();
  });
  it("says reachability waits on the graph update and names the previous graph's time", () => {
    const asOf = "2026-11-14T09:30:00+00:00";
    render(<FindingsGraphFreshnessNote freshness={{ freshness: "previous_generation", refresh_status: "building", as_of: asOf }} />);
    const text = screen.getByRole("status").textContent ?? "";
    expect(text).toContain("Updating graph");
    expect(text).toContain("reachability is unassessed");
    expect(text).toContain(new Date(asOf).toLocaleString());
  });
  it("labels a tenant's first build without a previous graph time", () => {
    render(<FindingsGraphFreshnessNote freshness={{ refresh_status: "building" }} />);
    const text = screen.getByRole("status").textContent ?? "";
    expect(text).toContain("reachability is unassessed until it is ready");
    expect(text).not.toContain("last complete graph");
  });
  it("omits an unknown time instead of rendering a placeholder", () => {
    render(<FindingsGraphFreshnessNote freshness={{ freshness: "previous_generation", refresh_status: "building", as_of: "" }} />);
    const text = screen.getByRole("status").textContent ?? "";
    expect(text).toContain("reachability is unassessed");
    expect(text).not.toContain("—");
  });
});
