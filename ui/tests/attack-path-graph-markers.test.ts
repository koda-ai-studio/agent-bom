import { describe, expect, it } from "vitest";

import { nodeContextMarkers } from "@/lib/attack-path-graph-markers";
import { riskContextOf, riskReasonText } from "@/lib/node-risk-context";

const kinds = (attributes: Record<string, unknown>) => nodeContextMarkers(attributes).map(marker => marker.kind);

const context = (fields: Record<string, unknown>, reasons: Record<string, unknown>[] = []) => ({
  risk_context: { version: 1, scan_id: "scan-1", sources: ["aws"], internet_exposed: null, privilege_level: null, is_admin: null,
    data_sensitivity: null, crown_jewel: false, reasons, ...fields },
});

describe("node context markers from the stored risk context", () => {
  it("uses the canonical data classification without deriving crown-jewel status", () => {
    expect(kinds({ data_classification: "phi" })).toEqual(["sensitive"]);
    expect(nodeContextMarkers({ data_classification: "phi" })[0]!.label).toBe("Sensitive data: phi (recorded)");
    expect(kinds(context({ data_sensitivity: "phi", crown_jewel: true }))).toEqual(["sensitive"]);
    expect(kinds({ data_classification: "none" })).toEqual([]);
    expect(kinds({ crown_jewel: true })).toEqual([]);
  });

  it("prefers the stored exposure verdict over a flat flag, like the path ranking", () => {
    expect(kinds({ ...context({ internet_exposed: false }), internet_exposed: true })).toEqual([]);
    expect(kinds(context({ internet_exposed: true }))).toEqual(["internet"]);
    expect(kinds(context({ internet_exposed: null }))).toEqual([]);
  });

  it("separates standing admin from a path to admin", () => {
    const admin = nodeContextMarkers({ privilege_level: "admin", admin_equivalent: true });
    expect(admin.map(marker => marker.label)).toEqual(["Privileged: admin (recorded)"]);
    const escalates = nodeContextMarkers({ privilege_level: "escalates_to_admin" });
    expect(escalates.map(marker => marker.label)).toEqual(["Privileged: can assume an admin role (recorded)"]);
    expect(kinds({ privilege_level: "read", admin_equivalent: false })).toEqual([]);
  });

  it("reads canonical flat badges on snapshots without a context", () => {
    expect(kinds({ internet_exposed: true, admin_equivalent: true, data_classification: "pii" })).toEqual(["internet", "sensitive", "privileged"]);
    expect(riskContextOf({ internet_exposed: true })).toBeNull();
  });

  it("explains each reason in words with its source", () => {
    expect(riskReasonText({ field: "internet_exposed", rule: "recorded_internet_exposed", attribute: "internet_exposed", value: true,
      evidence: { source: "cloud-inventory", inputs: { publicly_accessible: true } } }))
      .toBe("Internet-exposed: recorded (publicly_accessible)");
    expect(riskReasonText({ field: "internet_exposed", rule: "recorded_internet_exposed", attribute: "internet_exposed", value: true,
      evidence: { finding_ids: ["mc:sg-open"] } })).toBe("Internet-exposed: recorded (network rule mc:sg-open)");
    expect(riskReasonText({ field: "crown_jewel", rule: "declared_critical_asset", attribute: "asset_criticality", value: "tier0" }))
      .toBe("Crown jewel: declared criticality tier0");
    expect(riskReasonText({ field: "data_sensitivity", rule: "recorded_data_sensitivity", attribute: "data_sensitivity", value: "sensitive", evidence: { basis: ["name"] } }))
      .toBe("Sensitive data: sensitive, matched on the name only");
    expect(riskReasonText({ field: "privilege_level", rule: "kubernetes_cluster_admin_binding", attribute: "role", value: "ClusterRole/cluster-admin",
      evidence: { binding: "ClusterRoleBinding/ops" } })).toBe("Privilege: bound to ClusterRole/cluster-admin by ClusterRoleBinding/ops");
  });
});

it("reads folded privilege and data sensitivity without recomputing them from raw flags", () => {
  expect(kinds(context({ is_admin: true, privilege_level: "admin", data_sensitivity: "phi" }))).toEqual(["sensitive", "privileged"]);
  expect(kinds({ ...context({ is_admin: false, privilege_level: "read", data_sensitivity: "public" }), admin_equivalent: true,
    privilege_level: "admin", data_classification: "restricted" })).toEqual([]);
  expect(nodeContextMarkers(context({ is_admin: false, privilege_level: "escalates_to_admin" }))).toEqual([
    { kind: "privileged", label: "Privileged: can assume an admin role (recorded)" },
  ]);
  expect(kinds({ is_admin: true, data_sensitivity: "phi" })).toEqual([]);
});
