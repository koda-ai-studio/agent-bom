"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { SeverityBadge } from "@/components/severity-badge";
import { agentBlastPathHref } from "@/lib/agent-links";
import { api, type BlastRadius } from "@/lib/api";
import { exposedByImpactLabel, heldOnServerLabel } from "@/lib/credential-basis";

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SHOWN = 4;

type State = { status: "loading" } | { status: "error" } | { status: "ready"; rows: BlastRadius[] };

const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

/**
 * The agent's blast radius in its drawer: each vulnerable package that reaches
 * one of its servers, worst first, with the credentials that occurrence exposes.
 * Exposure is impact-filtered: a credential counts only when the advisory's
 * impact can reach it. Credentials the server holds without that assertion are
 * named separately; the exploit story counts those held credentials.
 */
export function AgentBlastSummary({ agentName }: { agentName: string }) {
  const [state, setState] = useState<State>({ status: "loading" });
  useEffect(() => {
    let cancelled = false;
    setState({ status: "loading" });
    void (async () => {
      try {
        const detail = await api.getAgentDetail(agentName);
        if (!cancelled) setState({ status: "ready", rows: detail.blast_radius ?? [] });
      } catch {
        if (!cancelled) setState({ status: "error" });
      }
    })();
    return () => { cancelled = true; };
  }, [agentName]);

  if (state.status === "loading") return <p role="status" className="text-xs text-ink-secondary">Reading the blast radius…</p>;
  if (state.status === "error") return <p className="text-xs text-ink-secondary">Blast radius unavailable.</p>;
  if (state.rows.length === 0) return <p className="text-xs text-ink-secondary">No vulnerable package reaches this agent&apos;s servers.</p>;

  const rows = [...state.rows].sort((a, b) => (RANK[a.severity?.toLowerCase() ?? ""] ?? 4) - (RANK[b.severity?.toLowerCase() ?? ""] ?? 4));
  const credentials = new Set(rows.flatMap((row) => row.exposed_credentials ?? []));
  const heldOnly = new Set(rows.flatMap((row) => row.all_server_credentials ?? []).filter((credential) => !credentials.has(credential)));
  return (
    <div className="space-y-2">
      <p className="text-xs text-ink-secondary">{plural(rows.length, "finding")} · {plural(credentials.size, "unique credential")} exposed by impact{heldOnly.size ? ` · ${heldOnly.size} on server` : ""}</p>
      <ul className="divide-y divide-outline rounded-lg border border-outline">
        {rows.slice(0, SHOWN).map((row) => {
          const exposed = row.exposed_credentials?.length ?? 0;
          const held = exposed ? [] : row.all_server_credentials ?? [];
          return (
            <li key={`${row.vulnerability_id}-${row.package ?? ""}`} className="flex flex-col gap-1 px-3 py-2 text-xs sm:flex-row sm:items-center sm:gap-3">
              <span className="flex min-w-0 shrink-0 items-center gap-2">
                <SeverityBadge severity={row.severity} />
                <Link href={agentBlastPathHref(agentName, row)} className="font-mono font-medium text-accent-mint hover:underline">{row.vulnerability_id}</Link>
              </span>
              <span className="flex min-w-0 flex-1 items-baseline gap-3">
                {row.package ? <span className="min-w-0 truncate font-mono text-ink-secondary" title={row.package}>{row.package}</span> : null}
                {held.length ? (
                  <span className="ml-auto shrink-0 text-right text-ink-secondary" title={`${held.join(", ")}. The server holds these credentials; this advisory's impact (${row.impact_category || "unknown"}) does not assert their exposure.`}>
                    {heldOnServerLabel(held.length)} · exposure not asserted
                  </span>
                ) : (
                  <span className={`ml-auto shrink-0 text-right ${exposed ? "text-[color:var(--status-warn)]" : "text-ink-tertiary"}`} title={(row.exposed_credentials ?? []).join(", ") || undefined}>
                    {exposedByImpactLabel(exposed)}
                  </span>
                )}
              </span>
            </li>
          );
        })}
      </ul>
      {rows.length > SHOWN ? <p className="text-xs text-ink-tertiary">{rows.length - SHOWN} more in full detail.</p> : null}
    </div>
  );
}
