/**
 * Node context markers drawn only from recorded attributes. The graph build
 * stores a `risk_context` on each asset (src/agent_bom/graph/risk_context.py)
 * with the verdicts and the reasons behind them; markers read it first. Older
 * snapshots without one fall back to the flat predicates the backend used
 * before: `coerce_truthy` for exposure (unknown is not proof),
 * `has_sensitive_data_label` for sensitivity, and the admin test for privilege.
 */
import { contextMarkers, NON_SENSITIVE, privilegedLabel, riskContextOf, type NodeContextMarker } from "@/lib/node-risk-context";

export { MARKER_KINDS, MARKER_META, type NodeContextMarker, type NodeContextMarkerKind } from "@/lib/node-risk-context";

const TRUE_TEXT = new Set(["true", "t", "yes", "y", "1"]);
const SENSITIVITY_KEYS = ["data_sensitivity", "sensitivity", "data_classification_tier", "data_classification"];

export function recordedTrue(value: unknown): boolean {
  if (typeof value === "boolean") return value;
  if (typeof value === "number") return value === 1;
  return typeof value === "string" && TRUE_TEXT.has(value.trim().toLowerCase());
}

function sensitivityLabel(attributes: Record<string, unknown>): string | null {
  for (const key of SENSITIVITY_KEYS) {
    const value = attributes[key];
    if (value === true) return "sensitive";
    if (typeof value !== "string") continue;
    const text = value.trim().toLowerCase();
    if (!NON_SENSITIVE.has(text)) return text.replaceAll("_", " ");
  }
  return null;
}

export function nodeContextMarkers(attributes: Record<string, unknown>): NodeContextMarker[] {
  const context = riskContextOf(attributes);
  if (context) return contextMarkers(context);
  const markers: NodeContextMarker[] = [];
  if (recordedTrue(attributes.internet_exposed)) markers.push({ kind: "internet", label: "Internet-exposed (recorded)" });
  else if (recordedTrue(attributes.publicly_accessible)) markers.push({ kind: "internet", label: "Publicly accessible (recorded)" });
  const sensitivity = sensitivityLabel(attributes);
  if (sensitivity) markers.push({ kind: "sensitive", label: `Sensitive data: ${sensitivity} (recorded)` });
  const admin = recordedTrue(attributes.is_admin) || attributes.privilege_level === "admin";
  const privileged = privilegedLabel(admin, recordedTrue(attributes.escalates_to_admin));
  if (privileged) markers.push({ kind: "privileged", label: privileged });
  return markers;
}
