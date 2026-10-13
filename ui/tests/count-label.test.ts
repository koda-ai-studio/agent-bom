import { describe, expect, it } from "vitest";

import { countLabel } from "@/lib/count-label";

describe("countLabel", () => {
  it("agrees the noun with the count", () => {
    expect(countLabel(1, "agent")).toBe("1 agent");
    expect(countLabel(0, "agent")).toBe("0 agents");
    expect(countLabel(3, "hop receipt")).toBe("3 hop receipts");
    expect(countLabel(1, "recorded relationship")).toBe("1 recorded relationship");
    expect(countLabel(2, "entity", "entities")).toBe("2 entities");
    expect(countLabel(1200, "node")).toBe("1,200 nodes");
  });
});
