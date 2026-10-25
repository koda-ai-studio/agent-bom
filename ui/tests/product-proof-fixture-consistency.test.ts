import { describe, expect, it } from "vitest";

import { CREATED_AT, intelSourcesFixture, loadOverviewProof } from "../scripts/product-proof-fixtures.mjs";

type Source = { source_id: string; enabled: boolean; feed_run: { status: string; last_synced: string | null } };

const SCAN_TIME_KEYS = ["latest_scan_at", "scan_timestamp", "generated_at", "completed_at"];

function scanTimes(value: unknown, out: Array<[string, string]> = []): Array<[string, string]> {
  if (Array.isArray(value)) value.forEach((item) => scanTimes(item, out));
  else if (value && typeof value === "object") {
    for (const [key, item] of Object.entries(value)) {
      if (SCAN_TIME_KEYS.includes(key) && typeof item === "string") out.push([key, item]);
      else scanTimes(item, out);
    }
  }
  return out;
}

describe("product-proof overview fixture", () => {
  it("dates every scan the overview reads at the fixture snapshot time", async () => {
    const proof = await loadOverviewProof();
    const overview = proof.responses["/v1/overview"] as { headline: { latest_scan_at: string } };
    expect(Date.parse(overview.headline.latest_scan_at)).toBe(Date.parse(CREATED_AT));
    const times = scanTimes([proof.responses["/v1/overview"], proof.responses["/v1/jobs"]]);
    expect(times.length).toBeGreaterThan(0);
    for (const [key, value] of times) expect([key, Date.parse(value)]).toEqual([key, Date.parse(CREATED_AT)]);
  });

  it("reports enabled, synced advisory sources when the overview lists CVE findings", async () => {
    const proof = await loadOverviewProof();
    const overview = proof.responses["/v1/overview"] as { headline: { critical: number; high: number } };
    expect(overview.headline.critical + overview.headline.high).toBeGreaterThan(0);
    const { sources, count } = intelSourcesFixture() as { sources: Source[]; count: number };
    expect(count).toBe(sources.length);
    const synced = sources.filter((source) => source.enabled && source.feed_run.status === "synced");
    expect(synced.map((source) => source.source_id).sort()).toEqual(["cisa_kev", "epss", "ghsa", "nvd", "osv"]);
    for (const source of synced) expect(source.feed_run.last_synced).toBe(CREATED_AT);
    // Feeds the sample estate never uses are disabled, so the overview reads "5 enabled · All synced".
    expect(sources.filter((source) => source.enabled)).toEqual(synced);
    for (const source of sources.filter((item) => !item.enabled)) {
      expect(source.feed_run).toMatchObject({ status: "freshness_unknown", last_synced: null });
    }
  });
});
