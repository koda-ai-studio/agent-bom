import { describe, expect, it } from "vitest";

import { snapshotLabel, snapshotOptionLabel } from "@/lib/snapshot-label";

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

describe("snapshotOptionLabel", () => {
  it("joins the short snapshot name and its local capture time, the text the selector shows and titles", () => {
    const createdAt = "2026-06-30T16:00:00Z";
    const when = new Date(createdAt).toLocaleString(undefined, { dateStyle: "short", timeStyle: "short" });
    expect(snapshotOptionLabel({ scan_id: "scan-proof-ai-platform", created_at: createdAt })).toBe(`scan-proof-ai-platform · ${when}`);
  });
});
