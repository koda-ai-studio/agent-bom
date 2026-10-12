"use client";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { entityIcon } from "@/lib/entity-icons";
import type { GraphConsequenceResponse } from "@/lib/api-types";

type Consequence = GraphConsequenceResponse["consequences"][number];
export const actionLabels: Record<string, string> = { read_data: "Read data", write_data: "Write data", delete_resource: "Delete a resource", alter_deployment: "Change a deployment", unclassified: "Unclassified action" };
export const statusLabels = { supported: "Recorded permission", conditional: "Conditional", blocked: "Blocked", unknown: "Unverified" };
export const readable = (value: string) => value.replaceAll("_", " ");
export const targetLabel = (item: Consequence) => item.node_labels?.at(-1) || item.resource || item.target_node_id;
export function consequenceTitle(item: Consequence) {
  const target = targetLabel(item);
  const titles: Record<string, string> = { read_data: `Read data from ${target}`, write_data: `Write data to ${target}`, delete_resource: `Delete ${target}`, alter_deployment: `Change ${target}` };
  return titles[item.category] ?? `Inspect access to ${target}`;
}

/** Render only the returned witness. The frontend never infers authority. */
export function GraphConsequencePath({ item }: { item: Consequence }) {
  const scopeBlocked = item.reason_codes.includes("outside_session_scope");
  const blocker = scopeBlocked ? "Recorded session scope excludes this action" : "Recorded denial stops this action";
  return <div className="rounded-2xl border border-outline bg-surface p-5 sm:p-8">
    <div className="mb-6 flex justify-between gap-3 text-xs text-ink-secondary"><span className="font-medium uppercase tracking-widest">Evidence path</span><span>{item.node_ids.length} recorded nodes</span></div>
    <ol aria-label="Selected consequence path" className="flex flex-col gap-3 lg:flex-row lg:items-stretch lg:overflow-x-auto lg:pb-3">
      {item.node_ids.map((id, index) => {
        const last = index === item.node_ids.length - 1;
        const type = item.node_types?.[index];
        const Icon = entityIcon(type?.replace(/_([a-z])/g, (_, char: string) => char.toUpperCase()));
        return <li key={`${index}:${id}`} className="flex min-w-0 flex-col items-stretch gap-3 lg:flex-row lg:items-center">
          {index > 0 && <div className="flex items-center gap-2 self-center text-xs text-ink-secondary lg:flex-col"><ArrowRight aria-hidden className={`h-5 w-5 rotate-90 lg:rotate-0 ${last && item.status === "blocked" ? "text-rose-600 dark:text-rose-300" : "text-ink-tertiary"}`} /><span>{last ? (item.status === "blocked" ? (scopeBlocked ? "outside scope" : "denied") : "action receipt") : "session binding"}</span></div>}
          <div className={`min-w-0 flex-1 rounded-xl border p-4 lg:w-44 lg:flex-none ${last && item.status === "blocked" ? "border-rose-500/50 bg-rose-500/5" : "border-outline-strong bg-surface-elevated"}`}>
            <Icon className={`mb-3 h-6 w-6 ${index === 0 ? "text-teal-600 dark:text-teal-300" : "text-ink-secondary"}`} />
            <p className="text-[10px] uppercase tracking-widest text-ink-tertiary">{index === 0 ? "Starting assumption" : type ? readable(type) : "Recorded entity"}</p>
            <p className="mt-1 break-words text-sm font-semibold text-foreground">{item.node_labels?.[index] ?? id}</p>
          </div>
        </li>;
      })}
    </ol>
    {item.status === "blocked" && <p className="mt-5 flex items-center gap-2 text-sm font-medium text-rose-700 dark:text-rose-300"><ShieldCheck className="h-4 w-4" />{blocker}</p>}
    <p className="mt-5 break-all border-t border-outline pt-4 font-mono text-xs text-ink-secondary">{item.action ?? "Action not recorded"}<span className="mx-2">→</span>{item.resource ?? item.target_node_id}</p>
  </div>;
}
