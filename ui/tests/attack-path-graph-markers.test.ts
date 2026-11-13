import { describe, expect, it } from "vitest";

import { nodeContextMarkers } from "@/lib/attack-path-graph-markers";
import { riskContextOf, riskReasonText } from "@/lib/node-risk-context";

const kinds = (attributes: Record<string, unknown>) => nodeContextMarkers(attributes).map(marker => marker.kind);

const context = (fields: Record<string, unknown>, reasons: Record<string, unknown>[] = []) => ({
  risk_context: { version: 1, scan_id: "scan-1", sources: ["aws"], internet_exposed: null, privilege_level: null, is_admin: null,
    data_sensitivity: null, crown_jewel: false, reasons, ...fields },
});

describe("node context markers from the stored risk context", () => {
  it("draws a crown-jewel marker only when the context establishes one", () => {
    const jewel = context({ data_sensitivity: "phi", crown_jewel: true }, [
      { field: "crown_jewel", rule: "sensitive_data_store", attribute: "data_sensitivity", value: "phi" },
    ]);
    expect(kinds(jewel)).toEqual(["sensitive", "crown_jewel"]);
    expect(nodeContextMarkers(jewel).find(marker => marker.kind === "crown_jewel")!.label).toBe("Crown jewel: holds sensitive data (phi) (recorded)");
    expect(kinds(context({ data_sensitivity: "none" }))).toEqual([]);
    expect(kinds({ crown_jewel: true })).toEqual([]);
  });

  it("prefers the stored exposure verdict over a flat flag, like the path ranking", () => {
    expect(kinds({ ...context({ internet_exposed: false }), internet_exposed: true })).toEqual([]);
    expect(kinds(context({ internet_exposed: true }))).toEqual(["internet"]);
    expect(kinds(context({ internet_exposed: null }))).toEqual([]);
  });

  it("separates standing admin from a path to admin", () => {
    const admin = nodeContextMarkers(context({ privilege_level: "admin", is_admin: true }));
    expect(admin.map(marker => marker.label)).toEqual(["Privileged: admin (recorded)"]);
    const escalates = nodeContextMarkers(context({ privilege_level: "escalates_to_admin" }));
    expect(escalates.map(marker => marker.label)).toEqual(["Privileged: can assume an admin role (recorded)"]);
    expect(kinds(context({ privilege_level: "read", is_admin: false }))).toEqual([]);
  });

  it("falls back to the recorded flat attributes on snapshots without a context", () => {
    expect(kinds({ internet_exposed: true, is_admin: true, data_sensitivity: "pii" })).toEqual(["internet", "sensitive", "privileged"]);
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
