/**
 * Node context markers drawn only from recorded attributes. The predicates
 * mirror the backend's: `coerce_truthy` for exposure (unknown is not proof),
 * `has_sensitive_data_label` for sensitivity, and the NHI governance
 * admin test for privilege.
 */
export type NodeContextMarker = { kind: "internet" | "sensitive" | "privileged"; label: string };

const TRUE_TEXT = new Set(["true", "t", "yes", "y", "1"]);
const NON_SENSITIVE = new Set(["", "0", "false", "no", "none", "null", "unevaluable", "unknown", "public"]);
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
  const markers: NodeContextMarker[] = [];
  if (recordedTrue(attributes.internet_exposed)) markers.push({ kind: "internet", label: "Internet-exposed (recorded)" });
  else if (recordedTrue(attributes.publicly_accessible)) markers.push({ kind: "internet", label: "Publicly accessible (recorded)" });
  const sensitivity = sensitivityLabel(attributes);
  if (sensitivity) markers.push({ kind: "sensitive", label: `Sensitive data: ${sensitivity} (recorded)` });
  if (recordedTrue(attributes.is_admin) || recordedTrue(attributes.escalates_to_admin) || attributes.privilege_level === "admin") {
    markers.push({ kind: "privileged", label: recordedTrue(attributes.escalates_to_admin) && !recordedTrue(attributes.is_admin) && attributes.privilege_level !== "admin"
      ? "Privileged: can assume an admin role (recorded)" : "Privileged: admin (recorded)" });
  }
  return markers;
}
