import { describe, expect, it } from "vitest";

import { hasDemoSeedSources, isDemoDataView } from "@/lib/demo-data";
import { isDemoEstate } from "@/lib/deployment-context";

describe("pushed --demo report", () => {
  // The sources a 0.115.0 `scan --demo --push-url` report reaches /v1/posture/counts with.
  const pushedDemoSources = ["agent_discovery", "demo", "iac"];

  it("shows the demo-data banner", () => {
    expect(hasDemoSeedSources(pushedDemoSources)).toBe(true);
    expect(isDemoDataView({ captureMode: false, scanSources: pushedDemoSources })).toBe(true);
  });

  it("is not mistaken for the seeded demo estate, which locks operator surfaces", () => {
    expect(isDemoEstate({ scan_sources: pushedDemoSources } as Parameters<typeof isDemoEstate>[0])).toBe(false);
  });

  it("leaves a real local scan unlabelled", () => {
    expect(isDemoDataView({ captureMode: false, scanSources: ["agent_discovery", "iac"] })).toBe(false);
  });
});
