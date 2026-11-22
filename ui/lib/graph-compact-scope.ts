import type { GraphRollupContainer } from "@/lib/api-types";
import { rollupDisplaySeverity } from "@/lib/graph-rollup-view";

const label = (type: string) => type.replace(/_/g, " ").replace(/^./, letter => letter.toUpperCase());

/** A roll-up entry on the compact canvas: a short visible line, plus the full scope-card wording for assistive text. */
export function compactScopeCaption(item: GraphRollupContainer): { visible: string; spoken: string } {
  const scope = item.is_container || item.has_children;
  const finding = ["misconfiguration", "vulnerability"].includes(item.entity_type);
  const severity = rollupDisplaySeverity(item);
  const rated = severity && severity !== "none";
  const count = item.aggregate?.descendant_count;
  const visible = [scope ? `${count === undefined ? "—" : count.toLocaleString()} entities` : label(item.entity_type), rated ? severity : ""].filter(Boolean).join(" · ");
  const severityText = rated ? `${label(severity)}${scope ? " · highest severity" : " severity"}` : "No severity recorded";
  return { visible, spoken: `${severityText}. ${scope ? "Inspect scope" : finding ? "Inspect finding" : "Inspect entity"}` };
}
