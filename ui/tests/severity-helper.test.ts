import { describe, expect, it } from "vitest";
import { severityRank, severityAtOrAbove } from "@/lib/severity";

describe("canonical display severity", () => {
  it("ranks info above unknown and none, and normalizes vendor labels", () => {
    expect(severityRank("info")).toBe(1);
    expect(severityRank("none")).toBe(0);
    expect(severityRank("unknown")).toBe(0);
    expect(severityRank("unrecognized")).toBe(0);
    expect(severityRank(" CRITICAL ")).toBe(5);
    expect(severityRank("moderate")).toBe(3);
    expect(severityRank("informational")).toBe(1);
  });
  it("keeps unknown below none for policy thresholds", () => {
    expect(severityAtOrAbove("unknown", "none")).toBe(false);
    expect(severityAtOrAbove("info", "low")).toBe(true);
    expect(severityAtOrAbove("medium", "high")).toBe(false);
  });
});
