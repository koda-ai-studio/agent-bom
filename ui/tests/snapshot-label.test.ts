import { expect, it } from "vitest";

import { snapshotLabel } from "@/lib/snapshot-label";

it("shows short snapshot names whole so siblings stay distinguishable", () => {
  expect(snapshotLabel("showcase-baseline")).toBe("showcase-baseline");
  expect(snapshotLabel("showcase")).toBe("showcase");
});

it("keeps the distinguishing suffix of a long id", () => {
  const a = snapshotLabel("current-estate:b420bb7c8d4fc9ac35d37a4af81e8501");
  const b = snapshotLabel("current-estate:b420bb7c8d4fc9ac35d37a4af81e9999");
  expect(a).not.toBe(b);
  expect(a.endsWith("af81e8501")).toBe(true);
  expect(a.startsWith("current-estate")).toBe(true);
  expect(a.length).toBeLessThanOrEqual(28);
  expect(a).toContain("…");
});
