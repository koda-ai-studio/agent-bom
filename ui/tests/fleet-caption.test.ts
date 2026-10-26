import { describe, expect, it } from "vitest";

import { hiddenQuarantinedCount } from "@/lib/fleet-caption";

describe("fleet caption", () => {
  it("reports quarantined agents only when the list really leaves them out", () => {
    expect(hiddenQuarantinedCount("all", "", 5, 48, 43)).toBe(5);
    expect(hiddenQuarantinedCount("all", "", 5, 18, 18)).toBe(0);
  });

  it("never claims hidden agents for a filtered or searched list", () => {
    expect(hiddenQuarantinedCount("approved", "", 5, 48, 6)).toBe(0);
    expect(hiddenQuarantinedCount("all", "copilot", 5, 48, 2)).toBe(0);
  });
});
