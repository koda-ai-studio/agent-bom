import { expect, it } from "vitest";
import { policySetup, profileSetup, receiptStatus } from "@/lib/runtime-connection-status";
it("preserves unknown setup and distinguishes expired, revoked and bounded profile snapshots", () => {
  const now = Date.parse("2026-10-27T12:00:00Z");
  const row = { config_id: "one", tenant_id: "tenant-a", status: "active", revoked: false, expires_at: "" };
  expect(profileSetup({}, "tenant-a", now)).toBe("Profile setup unavailable");
  expect(profileSetup({ assignments: [] }, "tenant-a", now)).toBe("0 active profiles");
  expect(profileSetup({ assignments: [{ ...row, expires_at: "2026-10-26T12:00:00Z" }, { ...row, config_id: "two", revoked: true }] }, "tenant-a", now)).toBe("0 active profiles");
  expect(profileSetup({ assignments: [row, row] }, "tenant-a", now)).toBe("Profile setup unavailable");
  expect(profileSetup({ assignments: Array.from({ length: 1000 }, (_, i) => ({ ...row, config_id: String(i) })) }, "tenant-a", now)).toContain("first 1,000 records");
  for (const mode of ["__proto__", "toString", "unsupported"]) expect(policySetup({ policy_runtime: { source_kind: "policy_store", rollout_mode: mode } })).toBe("Policy setup unavailable");
  expect(policySetup({ policy_runtime: { source_kind: "caller_assertion", rollout_mode: "blocking" } })).toBe("Policy setup unavailable");
});
it("never treats missing, malformed or future receipt clocks as recently observed", () => {
  const now = Date.parse("2026-10-27T12:00:00Z");
  expect(receiptStatus(undefined, now)).toBe("No receipts in this window");
  expect(receiptStatus("bad", now)).toBe("Receipt time unverified");
  expect(receiptStatus("2026-10-28T00:00:00Z", now)).toBe("Receipt time unverified");
});
