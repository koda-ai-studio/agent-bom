import { describe, expect, it } from "vitest";

import { blockedBreakdown, proxyConnectionLabel } from "@/lib/proxy-runtime-labels";

describe("runtime proxy header and block reasons", () => {
  it("names a loaded snapshot as a snapshot instead of 'Disconnected'", () => {
    expect(proxyConnectionLabel({ connected: false, liveTransport: false, hasSnapshot: true })).toBe("Snapshot (not live)");
    expect(proxyConnectionLabel({ connected: false, liveTransport: false, hasSnapshot: false })).toBe("Disconnected");
    expect(proxyConnectionLabel({ connected: true, liveTransport: true, hasSnapshot: true })).toBe("Live transport");
    expect(proxyConnectionLabel({ connected: true, liveTransport: false, hasSnapshot: false })).toBe("Connected");
  });

  it("reconciles the reason slices with the Blocked tile via an unattributed slice", () => {
    const slices = blockedBreakdown({ policy: 20, rate_limit: 14, none: 0 }, 36);
    expect(slices).toEqual([
      { name: "policy", value: 20 },
      { name: "rate_limit", value: 14 },
      { name: "unattributed", value: 2 },
    ]);
    expect(slices.reduce((sum, slice) => sum + slice.value, 0)).toBe(36);
    expect(blockedBreakdown({ policy: 3 }, 3)).toEqual([{ name: "policy", value: 3 }]);
    expect(blockedBreakdown({}, 0)).toEqual([]);
  });
});
