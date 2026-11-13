/**
 * The stored per-node risk context (src/agent_bom/graph/risk_context.py) and
 * how to explain it. Reads only `attributes.risk_context`, which every graph
 * view keeps, so any page can import it.
 */
import { Crown, Database, Gem, Globe, type LucideIcon } from "lucide-react";

export type NodeContextMarkerKind = "internet" | "sensitive" | "privileged" | "crown_jewel";
export type NodeContextMarker = { kind: NodeContextMarkerKind; label: string };

export type RiskReason = {
  field: string;
  rule: string;
  attribute: string;
  value: unknown;
  evidence?: Record<string, unknown>;
};
export type NodeRiskContext = {
  version: number;
  scan_id: string;
  sources: string[];
  internet_exposed: boolean | null;
  privilege_level: string | null;
  is_admin: boolean | null;
  data_sensitivity: string | null;
  crown_jewel: boolean;
  reasons: RiskReason[];
};

/** One legend entry and icon per marker kind, in drawing order. */
export const MARKER_META: Record<NodeContextMarkerKind, { label: string; Icon: LucideIcon }> = {
  internet: { label: "Internet-exposed", Icon: Globe },
  sensitive: { label: "Sensitive data", Icon: Database },
  privileged: { label: "Privileged", Icon: Crown },
  crown_jewel: { label: "Crown jewel", Icon: Gem },
};
export const MARKER_KINDS = Object.keys(MARKER_META) as NodeContextMarkerKind[];
export const NON_SENSITIVE = new Set(["", "0", "false", "no", "none", "null", "unevaluable", "unknown", "public"]);

export function riskContextOf(attributes: Record<string, unknown>): NodeRiskContext | null {
  const value = attributes.risk_context;
  return value && typeof value === "object" && Array.isArray((value as NodeRiskContext).reasons) ? value as NodeRiskContext : null;
}

export function privilegedLabel(admin: boolean, escalates: boolean): string | null {
  return admin ? "Privileged: admin (recorded)" : escalates ? "Privileged: can assume an admin role (recorded)" : null;
}

const JEWEL_LABEL: Record<string, string> = {
  production_secret_store: "production secrets store",
  declared_critical_asset: "declared critical",
};

/** The markers a stored context establishes, each labelled with why. */
export function contextMarkers(context: NodeRiskContext): NodeContextMarker[] {
  const markers: NodeContextMarker[] = [];
  if (context.internet_exposed === true) markers.push({ kind: "internet", label: "Internet-exposed (recorded)" });
  const sensitivity = context.data_sensitivity;
  if (sensitivity && !NON_SENSITIVE.has(sensitivity)) markers.push({ kind: "sensitive", label: `Sensitive data: ${sensitivity.replaceAll("_", " ")} (recorded)` });
  const privileged = privilegedLabel(context.is_admin === true, context.privilege_level === "escalates_to_admin");
  if (privileged) markers.push({ kind: "privileged", label: privileged });
  if (context.crown_jewel === true) {
    const rule = context.reasons.find(reason => reason.field === "crown_jewel")?.rule ?? "";
    const why = rule === "sensitive_data_store" ? `holds sensitive data (${sensitivity})` : JEWEL_LABEL[rule] ?? "declared critical";
    markers.push({ kind: "crown_jewel", label: `Crown jewel: ${why} (recorded)` });
  }
  return markers;
}

const FIELD_LABEL: Record<string, string> = {
  internet_exposed: "Internet-exposed",
  privilege_level: "Privilege",
  data_sensitivity: "Sensitive data",
  crown_jewel: "Crown jewel",
};
// `{a}` is the recorded attribute, `{v}` its value; unknown rules print both.
const RULE_TEXT: Record<string, string> = {
  recorded_internet_exposed: "recorded",
  recorded_public_flag: "recorded {a}",
  recorded_public_ip: "public IP {v}",
  recorded_not_public: "recorded {a} = false",
  kubernetes_cluster_admin_binding: "bound to {v}",
  admin_equivalence: "policy analysis: {v}",
  recorded_admin_flag: "recorded {a}",
  recorded_privilege_level: "recorded level {v}",
  escalates_to_admin: "can assume an admin role",
  escalates_to_conditional_admin: "can assume a conditional admin role",
  recorded_data_sensitivity: "{v}",
  recorded_classification_tier: "tier {v}",
  recorded_regulatory_framework: "regulated: {v}",
  content_sampling: "content sampling found {v}",
  sensitive_data_store: "data store holding {v} data",
  declared_critical_asset: "declared criticality {v}",
  production_secret_store: "production secrets store",
};

const text = (value: unknown) => (Array.isArray(value) ? value.join(", ") : String(value));

/** A reason in plain words: which field, and the recorded fact behind it. */
export function riskReasonText(reason: RiskReason): string {
  const evidence = reason.evidence ?? {};
  let detail = (RULE_TEXT[reason.rule] ?? "{a} = {v}").replace("{a}", reason.attribute).replace("{v}", text(reason.value));
  if (Array.isArray(evidence.finding_ids) && evidence.finding_ids.length) detail += ` (network rule ${text(evidence.finding_ids)})`;
  else if (evidence.inputs && typeof evidence.inputs === "object") detail += ` (${Object.keys(evidence.inputs).join(", ")})`;
  if (typeof evidence.binding === "string") detail += ` by ${evidence.binding}`;
  if (Array.isArray(evidence.basis) && evidence.basis.join() === "name") detail += ", matched on the name only";
  return `${FIELD_LABEL[reason.field] ?? reason.field}: ${detail}`;
}
