import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

const SNAPSHOT = "2026-06-03T20:30:00Z";

function source(id: string) {
  return { source_id: id, display_name: id.toUpperCase(), enabled: true, feed_run: { status: "synced", last_synced: SNAPSHOT } };
}

function stubFetch(manifest: object | null) {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (String(url).includes("routes.json")) {
      return manifest ? new Response(JSON.stringify(manifest), { status: 200 }) : new Response("", { status: 404 });
    }
    return new Response(JSON.stringify({ schema_version: "intel.sources.v1", sources: [source("osv"), source("nvd")], count: 2 }), { status: 200 });
  }));
}

async function renderFreshness() {
  const { AdvisoryFreshness } = await import("@/components/advisory-freshness");
  render(<AdvisoryFreshness />);
  await screen.findByText(/2 enabled sources/);
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.useRealTimers();
  vi.resetModules();
});

describe("static demo clock", () => {
  it("reads a sync at the snapshot time as stale against today's wall clock", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-10-25T12:00:00Z") });
    stubFetch(null);
    await renderFreshness();
    expect(await screen.findByText(/2 stale/)).toBeInTheDocument();
  });

  it("measures freshness from the demo snapshot in the static demo", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-10-25T12:00:00Z") });
    vi.stubEnv("NEXT_PUBLIC_STATIC_DEMO", "1");
    stubFetch({ schema_version: "static-demo-routes.v1", snapshot_at: SNAPSHOT, routes: ["/"] });
    await renderFreshness();
    expect(await screen.findByText("All synced")).toBeInTheDocument();
    expect(screen.queryByText(/stale/i)).toBeNull();
  });

  it("demoNow is the wall clock outside the demo", async () => {
    vi.useFakeTimers({ toFake: ["Date"], now: new Date("2026-10-25T12:00:00Z") });
    const { demoNow } = await import("@/lib/static-demo-routes");
    expect(demoNow(null)).toBe(Date.parse("2026-10-25T12:00:00Z"));
    expect(demoNow(Date.parse(SNAPSHOT))).toBe(Date.parse(SNAPSHOT));
  });
});
