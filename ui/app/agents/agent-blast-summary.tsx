"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

import { SeverityBadge } from "@/components/severity-badge";
import { agentBlastPathHref } from "@/lib/agent-links";
import { api, type BlastRadius } from "@/lib/api";

const RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const SHOWN = 4;

type State = { status: "loading" } | { status: "error" } | { status: "ready"; rows: BlastRadius[] };

const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

/**
 * The agent's blast radius in its drawer: each vulnerable package that reaches
 * one of its servers, worst first, with the credentials that occurrence exposes.
 * Counts read the same per-occurrence credentials the exploit story walks.
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
  return (
    <div className="space-y-2">
      <p className="text-xs text-ink-secondary">{plural(rows.length, "finding")} · {plural(credentials.size, "unique credential")} exposed</p>
      <ul className="divide-y divide-outline rounded-lg border border-outline">
        {rows.slice(0, SHOWN).map((row) => {
          const exposed = row.exposed_credentials?.length ?? 0;
          return (
            <li key={`${row.vulnerability_id}-${row.package ?? ""}`} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-2 text-xs">
              <SeverityBadge severity={row.severity} />
              <Link href={agentBlastPathHref(agentName, row)} className="font-mono font-medium text-accent-mint hover:underline">{row.vulnerability_id}</Link>
              {row.package ? <span className="font-mono text-ink-secondary">{row.package}</span> : null}
              <span className={exposed ? "ml-auto text-[color:var(--status-warn)]" : "ml-auto text-ink-tertiary"} title={(row.exposed_credentials ?? []).join(", ") || undefined}>
                {exposed ? `${plural(exposed, "credential")} exposed` : "No credentials exposed"}
              </span>
            </li>
          );
        })}
      </ul>
      {rows.length > SHOWN ? <p className="text-xs text-ink-tertiary">{rows.length - SHOWN} more in full detail.</p> : null}
    </div>
  );
}
