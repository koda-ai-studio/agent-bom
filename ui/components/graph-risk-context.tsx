"use client";

import type { LucideIcon } from "lucide-react";

import { MARKER_META, riskContextOf, riskReasonText, type NodeRiskContext } from "@/lib/node-risk-context";

const CHIP = "inline-flex items-center gap-1 rounded border border-outline px-1.5 py-0.5 text-[11px] text-foreground";

type Verdict = { key: string; label: string; Icon?: LucideIcon };

function verdicts(context: NodeRiskContext): Verdict[] {
  const items: Verdict[] = [];
  if (context.crown_jewel) items.push({ key: "crown_jewel", label: "Crown jewel", Icon: MARKER_META.crown_jewel.Icon });
  if (context.internet_exposed === true) items.push({ key: "internet", label: "Internet-exposed", Icon: MARKER_META.internet.Icon });
  if (context.internet_exposed === false) items.push({ key: "internet", label: "Not internet-exposed" });
  if (context.is_admin === true) items.push({ key: "privileged", label: "Admin", Icon: MARKER_META.privileged.Icon });
  else if (context.privilege_level) items.push({ key: "privileged", label: `Privilege: ${context.privilege_level.replaceAll("_", " ")}` });
  if (context.data_sensitivity && context.data_sensitivity !== "none") {
    items.push({ key: "sensitive", label: `Sensitive: ${context.data_sensitivity.replaceAll("_", " ")}`, Icon: MARKER_META.sensitive.Icon });
  } else if (context.data_sensitivity === "none") items.push({ key: "sensitive", label: "Classified: no sensitive data" });
  return items;
}

/** The node's stored risk verdicts and the recorded facts that establish each one. */
export function GraphRiskContext({ attributes }: { attributes: Record<string, unknown> }) {
  const context = riskContextOf(attributes);
  if (!context) return null;
  return (
    <section aria-label="Risk context" className="space-y-1.5 text-xs text-ink-secondary">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-ink-tertiary">Risk context</p>
      <div className="flex flex-wrap gap-1.5">
        {verdicts(context).map(({ key, label, Icon }) => (
          <span key={key} className={CHIP}>{Icon && <Icon className="h-3 w-3" aria-hidden="true" />}{label}</span>
        ))}
      </div>
      <ul className="list-disc space-y-0.5 pl-4 break-words [overflow-wrap:anywhere]">
        {context.reasons.map((reason, index) => <li key={`${reason.field}:${reason.rule}:${index}`}>{riskReasonText(reason)}</li>)}
      </ul>
      <p className="text-[11px] text-ink-tertiary">Scan {context.scan_id || "unknown"} · sources {context.sources.join(", ") || "unknown"}</p>
    </section>
  );
}
