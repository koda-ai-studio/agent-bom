import { describe, expect, it } from "vitest";

import type { ExploitStoryHow } from "@/lib/api-exploit-story";
import { exploitFacts } from "@/lib/exploit-story";
import { formatProbabilityPercent } from "@/lib/probability-format";

describe("formatProbabilityPercent", () => {
  it("never rounds a probability below 1 up to 100%", () => {
    expect(formatProbabilityPercent(0.99979)).toBe("99.98%");
    expect(formatProbabilityPercent(0.9996)).toBe("99.96%");
    expect(formatProbabilityPercent(0.999999)).toBe("99.9999%");
  });

  it("keeps one decimal where it is exact enough", () => {
    expect(formatProbabilityPercent(0.4567)).toBe("45.7%");
    expect(formatProbabilityPercent(1)).toBe("100.0%");
    expect(formatProbabilityPercent(0)).toBe("0.0%");
  });

  it("never rounds a positive probability down to 0%", () => {
    expect(formatProbabilityPercent(0.0002)).toBe("0.02%");
  });
});

describe("exploit story EPSS fact", () => {
  it("shows 99.98% for EPSS 0.99979", () => {
    const how = {
      cvss: null,
      capabilities: [],
      kev: { listed: true },
      epss: { score: 0.99979, percentile: 0.9999 },
      reachability: { verdict: "unknown", basis: [] },
    } as unknown as ExploitStoryHow;
    expect(exploitFacts(how).find((fact) => fact.key === "epss")?.label).toBe("EPSS 99.98%");
  });
});
