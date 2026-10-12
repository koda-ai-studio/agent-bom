import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AdvisoryFreshness } from "@/components/advisory-freshness";
const { getIntelSources } = vi.hoisted(() => ({ getIntelSources: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { getIntelSources } }));
beforeEach(() => { getIntelSources.mockReset(); });
describe("advisory freshness", () => {
  it("keeps missing source timestamps unknown independently of scan freshness", async () => {
    getIntelSources.mockResolvedValue({ sources: [{ source_id: "osv", display_name: "OSV", enabled: true, feed_run: { last_synced: null, status: "not_synced", cap_hit: true } }] });
    render(<AdvisoryFreshness />);
    expect(await screen.findByText(/1 enabled sources/)).toBeInTheDocument();
    expect(screen.getByText("0 sync times recorded")).toBeInTheDocument();
    expect(screen.getByText("1 sync time unknown")).toBeInTheDocument();
    expect(screen.getByText("Not synced")).toBeInTheDocument();
    expect(screen.getByText("Last feed sync · Not recorded")).toBeInTheDocument();
    expect(screen.getByText("Partial feed")).toBeInTheDocument();
  });
  it("formats recorded feed times as readable UTC dates, separately from scan time", async () => {
    getIntelSources.mockResolvedValue({ sources: [{ source_id: "epss", display_name: "FIRST EPSS", enabled: true, feed_run: { last_synced: "2026-08-19T04:05:27.281150+00:00", status: "synced", cap_hit: false, validation_failures: 0 } }] });
    render(<AdvisoryFreshness />);
    expect(await screen.findByText("Synced")).toBeInTheDocument();
    expect(screen.getByText("Last feed sync · Aug 19, 2026, 4:05 AM UTC")).toBeInTheDocument();
    expect(screen.getByText("1 sync time recorded")).toBeInTheDocument();
    expect(screen.getByText("0 sync times unknown")).toBeInTheDocument();
  });
  it("does not translate a failed source request into current data", async () => {
    getIntelSources.mockRejectedValue(new Error("unavailable"));
    render(<AdvisoryFreshness />);
    expect(await screen.findByText(/source status unavailable/)).toBeInTheDocument();
    expect(screen.queryByText(/0 enabled sources/)).not.toBeInTheDocument();
  });
});
