/** Graph badges read the backend's declared verdicts, never names or topology. */
import { NON_SENSITIVE, privilegedLabel, riskContextOf, type NodeContextMarker } from "@/lib/node-risk-context";
import { internetExposure } from "@/lib/graph-internet-context";

export { MARKER_KINDS, MARKER_META, type NodeContextMarker, type NodeContextMarkerKind } from "@/lib/node-risk-context";

export function nodeContextMarkers(attributes: Record<string, unknown>): NodeContextMarker[] {
  const markers: NodeContextMarker[] = [];
  if (internetExposure(attributes) === true) markers.push({ kind: "internet", label: "Internet-exposed (recorded)" });
  const context = riskContextOf(attributes);
  const classification = context?.data_sensitivity ?? attributes.data_classification;
  if (typeof classification === "string" && !NON_SENSITIVE.has(classification.trim().toLowerCase())) {
    markers.push({ kind: "sensitive", label: `Sensitive data: ${classification.replaceAll("_", " ")} (recorded)` });
  }
  const level = context?.privilege_level ?? attributes.privilege_level;
  const admin = typeof context?.is_admin === "boolean" ? context.is_admin : attributes.admin_equivalent === true || level === "admin";
  const privileged = privilegedLabel(admin, level === "escalates_to_admin");
  if (privileged) markers.push({ kind: "privileged", label: privileged });
  return markers;
}
