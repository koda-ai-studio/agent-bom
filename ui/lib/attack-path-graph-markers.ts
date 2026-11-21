/** Graph badges read the backend's declared verdicts, never names or topology. */
import { NON_SENSITIVE, privilegedLabel, type NodeContextMarker } from "@/lib/node-risk-context";
import { internetExposure } from "@/lib/graph-internet-context";

export { MARKER_KINDS, MARKER_META, type NodeContextMarker, type NodeContextMarkerKind } from "@/lib/node-risk-context";

export function nodeContextMarkers(attributes: Record<string, unknown>): NodeContextMarker[] {
  const markers: NodeContextMarker[] = [];
  if (internetExposure(attributes) === true) markers.push({ kind: "internet", label: "Internet-exposed (recorded)" });
  const classification = attributes.data_classification;
  if (typeof classification === "string" && !NON_SENSITIVE.has(classification.trim().toLowerCase())) {
    markers.push({ kind: "sensitive", label: `Sensitive data: ${classification.replaceAll("_", " ")} (recorded)` });
  }
  const privileged = privilegedLabel(attributes.admin_equivalent === true || attributes.privilege_level === "admin", attributes.privilege_level === "escalates_to_admin");
  if (privileged) markers.push({ kind: "privileged", label: privileged });
  return markers;
}
