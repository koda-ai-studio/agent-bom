/**
 * The stored per-node risk context (src/agent_bom/graph/risk_context.py) and
 * how to explain it. Reads only `attributes.risk_context`, which every graph
 * view keeps, so any page can import it.
 */
import { Crown, Database, Gem, Globe, type LucideIcon } from "lucide-react";

export type NodeContextMarkerKind = "internet" | "sensitive" | "privileged" | "crown_jewel";

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

export function riskContextOf(attributes: Record<string, unknown>): NodeRiskContext | null {
  const value = attributes.risk_context;
  return value && typeof value === "object" && Array.isArray((value as NodeRiskContext).reasons) ? value as NodeRiskContext : null;
}

const FIELD_LABEL: Record<string, string> = {
  internet_exposed: "Internet-exposed",
  privilege_level: "Privilege",
  data_sensitivity: "Sensitive data",
  crown_jewel: "Crown jewel",
};

function text(value: unknown): string {
  return Array.isArray(value) ? value.map(String).join(", ") : String(value);
}

function reasonDetail(reason: RiskReason): string {
  const evidence = reason.evidence ?? {};
  switch (reason.rule) {
    case "recorded_internet_exposed": {
      const findings = Array.isArray(evidence.finding_ids) ? evidence.finding_ids : [];
      if (findings.length) return `network rule in ${text(findings)}`;
      const inputs = evidence.inputs && typeof evidence.inputs === "object" ? Object.keys(evidence.inputs) : [];
      const source = typeof evidence.source === "string" ? `recorded by ${evidence.source}` : "recorded";
      return inputs.length ? `${source} (${inputs.join(", ")})` : source;
    }
    case "recorded_public_flag": return `recorded ${reason.attribute}`;
    case "recorded_public_ip": return `public IP ${text(reason.value)}`;
    case "recorded_not_public": return `recorded ${reason.attribute} = false`;
    case "kubernetes_cluster_admin_binding":
      return `bound to ${text(reason.value)}${typeof evidence.binding === "string" ? ` by ${evidence.binding}` : ""}`;
    case "admin_equivalence": return `policy analysis: ${text(reason.value)}`;
    case "escalates_to_admin": return "can assume an admin role";
    case "escalates_to_conditional_admin": return "can assume a conditional admin role";
    case "recorded_data_sensitivity": {
      const basis = Array.isArray(evidence.basis) ? evidence.basis.map(String) : [];
      return basis.length === 1 && basis[0] === "name" ? `${text(reason.value)}, matched on the name only` : text(reason.value);
    }
    case "content_sampling": return `content sampling found ${text(reason.value)}`;
    case "recorded_regulatory_framework": return `regulated: ${text(reason.value)}`;
    case "sensitive_data_store": return `data store holding ${text(reason.value)} data`;
    case "declared_critical_asset": return `declared criticality ${text(reason.value)}`;
    case "production_secret_store": return "production secrets store";
    default: return `${reason.attribute} = ${text(reason.value)}`;
  }
}

/** A reason in plain words: which field, and the recorded fact behind it. */
export function riskReasonText(reason: RiskReason): string {
  return `${FIELD_LABEL[reason.field] ?? reason.field}: ${reasonDetail(reason)}`;
}
