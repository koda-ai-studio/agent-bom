import { execFileSync } from "node:child_process";
import path from "node:path";

import { describe, expect, it } from "vitest";

const UI_ROOT = path.resolve(__dirname, "..");

// Wall-clock reads that are not relative ages: elapsed timers, throttles, cache
// clocks, unique ids and export file stamps. Each is file:line-text with a reason.
// Relative ages, "x ago", SLA due/overdue and freshness windows must use
// nowForRelativeTime() (lib/relative-clock.ts) so the static demo measures them
// from its sample snapshot.
const ALLOWED: Record<string, string> = {
  "app/compliance/page.tsx|const stamp = new Date().toISOString().slice(0, 10);": "export file name date",
  "app/findings/page.tsx|downloadJson(exported, `finding-triage-openvex-${new Date().toISOString().slice(0, 10)}.json`);": "export file name date",
  "app/fleet/page.tsx|onClick={() => downloadJson(filtered, `fleet-${new Date().toISOString().slice(0, 10)}.json`)}": "export file name date",
  "app/jobs/page.tsx|downloadJson(exported, `jobs-${new Date().toISOString().slice(0, 10)}.json`);": "export file name date",
  "app/remediation/page.tsx|`remediation-plan-${new Date().toISOString().slice(0, 10)}.json`": "export file name date",
  "app/gateway/GatewayFeedPanel.tsx|if (page.events.length && Date.now() - notifiedAt > 3000) {": "notification throttle",
  "app/gateway/GatewayFeedPanel.tsx|notifiedAt = Date.now(); notify.current?.();": "notification throttle",
  "components/auth-provider.tsx|const startedAt = Date.now();": "API start-up wait timer",
  "components/auth-provider.tsx|if (startingRetryMs != null && Date.now() - startedAt < STARTING_MAX_WAIT_MS) {": "API start-up wait timer",
  "components/graph-chrome.tsx|a.download = filename ?? `graph-${Date.now()}.json`;": "export file name",
  "lib/api-cache.ts|return Date.now();": "response cache TTL clock",
  "lib/api-transport.ts|const random = globalThis.crypto?.randomUUID?.() ?? `${Date.now()}-${Math.random().toString(16).slice(2)}`;": "idempotency key fallback",
  "lib/graph-investigation-bundle.ts|exported_at: new Date().toISOString(),": "export timestamp",
  "lib/relative-clock.ts|return process.env.NEXT_PUBLIC_STATIC_DEMO === \"1\" && demoSnapshotAt !== null ? demoSnapshotAt : Date.now();": "the relative clock itself",
};

function wallClockReads(): string[] {
  const out = execFileSync("git", ["grep", "--untracked", "-nE", "Date\\.now([^A-Za-z_]|$)|new Date\\(\\s*\\)|Temporal\\.Now", "--", "app", "components", "lib", "hooks",
    ":!*.test.*", ":!lib/api-schema.generated.ts"], { cwd: UI_ROOT, encoding: "utf8" });
  return out.split("\n").filter(Boolean).map((line) => {
    const [file, , ...rest] = line.split(":");
    return `${file}|${rest.join(":").trim()}`;
  });
}

describe("relative times go through the relative clock", () => {
  it("has no unreviewed wall-clock read in UI source", () => {
    const unreviewed = wallClockReads().filter((site) => !(site in ALLOWED));
    expect(unreviewed).toEqual([]);
  });

  it("keeps the allowlist free of stale entries", () => {
    const present = new Set(wallClockReads());
    expect(Object.keys(ALLOWED).filter((site) => !present.has(site))).toEqual([]);
  });
});
