import { render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AdvisoryFreshness } from "@/components/advisory-freshness";
const { getIntelSources } = vi.hoisted(() => ({ getIntelSources: vi.fn() }));
vi.mock("@/lib/api", () => ({ api: { getIntelSources } }));
beforeEach(() => { getIntelSources.mockReset(); });
afterEach(() => { vi.useRealTimers(); });
describe("advisory freshness", () => {
  it("keeps missing source timestamps unknown independently of scan freshness", async () => {
    getIntelSources.mockResolvedValue({ sources: [{ source_id: "osv", display_name: "OSV", enabled: true, feed_run: { last_synced: null, status: "not_synced", cap_hit: true } }] });
    render(<AdvisoryFreshness />);
    expect(await screen.findByText(/1 enabled source$/)).toBeInTheDocument();
    expect(screen.getByText("No feed sync recorded yet")).toBeInTheDocument();
    expect(screen.queryByText(/sync times? (recorded|unknown)/)).toBeNull();
    expect(screen.getByText("Not synced")).toBeInTheDocument();
    expect(screen.getByText("Last feed sync · Not recorded")).toBeInTheDocument();
    expect(screen.getByText("Partial feed")).toBeInTheDocument();
  });
  it("formats recorded feed times as readable UTC dates, separately from scan time", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: new Date("2026-08-19T10:00:00Z") });
    getIntelSources.mockResolvedValue({ sources: [{ source_id: "epss", display_name: "FIRST EPSS", enabled: true, feed_run: { last_synced: "2026-08-19T04:05:27.281150+00:00", status: "synced", cap_hit: false, validation_failures: 0 } }] });
    render(<AdvisoryFreshness />);
    expect(await screen.findByText("Synced")).toBeInTheDocument();
    expect(screen.getByText("Last feed sync · Aug 19, 2026, 4:05 AM UTC")).toBeInTheDocument();
    expect(screen.getByText("All synced")).toBeInTheDocument();
    expect(screen.queryByText(/never recorded/)).toBeNull();
  });
  it("names only the sources whose sync is missing when some have synced", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: new Date("2026-08-19T10:00:00Z") });
    getIntelSources.mockResolvedValue({ sources: [
      { source_id: "osv", display_name: "OSV", enabled: true, feed_run: { last_synced: "2026-08-19T04:05:27Z", status: "synced" } },
      { source_id: "kev", display_name: "KEV", enabled: true, feed_run: { last_synced: null, status: "not_synced" } },
      { source_id: "epss", display_name: "EPSS", enabled: true, feed_run: null },
    ] });
    render(<AdvisoryFreshness />);
    expect(await screen.findByText("1 of 3 synced · 2 never recorded")).toBeInTheDocument();
  });
  it("does not translate a failed source request into current data", async () => {
    getIntelSources.mockRejectedValue(new Error("unavailable"));
    render(<AdvisoryFreshness />);
    expect(await screen.findByText(/source status unavailable/)).toBeInTheDocument();
    expect(screen.queryByText(/0 enabled sources/)).not.toBeInTheDocument();
  });
  it("shows a partial NVD sync as partial with its reason, never as synced", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: new Date("2026-10-24T10:00:00Z") });
    getIntelSources.mockResolvedValue({ sources: [
      { source_id: "osv", display_name: "OSV", enabled: true, feed_run: { last_synced: "2026-10-24T06:00:00Z", status: "synced" } },
      { source_id: "nvd", display_name: "NVD", enabled: true, feed_run: { last_synced: "2026-10-24T06:00:00Z", status: "partial", partial_reason: "rate_limited", cap_hit: false } },
    ] });
    render(<AdvisoryFreshness />);
    const nvd = await screen.findByRole("listitem", { name: "NVD" });
    const status = within(nvd).getByTestId("source-status");
    expect(status).toHaveTextContent("Partial (rate limited)");
    expect(status).toHaveAttribute("data-status", "partial");
    expect(within(screen.getByRole("listitem", { name: "OSV" })).getByTestId("source-status")).toHaveAttribute("data-status", "synced");
    expect(screen.getByText("All recorded · 1 partial")).toBeInTheDocument();
    expect(screen.queryByText("All synced")).toBeNull();
  });
  it("marks a source stale when its last sync is older than a day, with its age", async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true, now: new Date("2026-10-24T10:00:00Z") });
    getIntelSources.mockResolvedValue({ sources: [
      { source_id: "nvd", display_name: "NVD", enabled: true, feed_run: { last_synced: "2026-10-20T10:00:00Z", status: "synced", cap_hit: true } },
    ] });
    render(<AdvisoryFreshness />);
    const status = await screen.findByTestId("source-status");
    expect(status).toHaveTextContent("Stale · 4 days old");
    expect(status).toHaveAttribute("data-status", "stale");
    expect(screen.getByText("Partial feed")).toBeInTheDocument();
    expect(screen.getByText("All recorded · 1 stale")).toBeInTheDocument();
  });
});
