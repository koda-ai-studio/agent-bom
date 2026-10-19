import { describe, expect, it } from "vitest";

import { evidenceTierLabel, exposurePriorityLabel } from "@/lib/plain-labels";

describe("plain risk labels", () => {
  it("names the exposure priority instead of echoing an internal colour band", () => {
    expect(exposurePriorityLabel("red", 79)).toBe("High exposure priority · 79/100");
    expect(exposurePriorityLabel("RED", undefined)).toBe("High exposure priority");
    expect(exposurePriorityLabel("pulsing-red", 93)).toBe("Critical exposure priority · 93/100");
    expect(exposurePriorityLabel("amber", 45)).toBe("Medium exposure priority · 45/100");
    expect(exposurePriorityLabel("green", 10)).toBe("Low exposure priority · 10/100");
    expect(exposurePriorityLabel("odd", 10)).toBe("Exposure priority odd · 10/100");
  });

  it("explains the evidence tier in words", () => {
    expect(evidenceTierLabel(3)).toBe("Reached from an agent or credential");
    expect(evidenceTierLabel(2)).toBe("Finding on the path");
    expect(evidenceTierLabel(1)).toBe("Exposure without a finding");
    expect(evidenceTierLabel(0)).toBe("No finding or exposure");
  });
});
