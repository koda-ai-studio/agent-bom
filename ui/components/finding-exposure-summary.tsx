import Link from "next/link";

import { reachabilityVerdict } from "@/lib/finding-exposure";
import { findingWorkloadScope, type EnrichedVuln } from "@/lib/findings-view";

const TONE = {
  reachable: "border-red-500/40 bg-red-500/10 text-red-700 dark:text-red-300",
  none: "border-outline bg-surface-muted text-ink-secondary",
  unknown: "border-outline bg-surface-muted text-ink-secondary",
} as const;

const chip = "rounded border border-outline bg-surface px-2 py-0.5 text-xs text-foreground underline decoration-dotted underline-offset-2 hover:bg-surface-muted";

/** Which agents and MCP servers this occurrence touches, and whether the graph reaches it. */
export function FindingExposureSummary({ vuln }: { vuln: EnrichedVuln }) {
  const scope = findingWorkloadScope(vuln);
  const reaching = (vuln.graph_reachable_from_agents ?? []).map((id) => id.replace(/^agent:/, ""));
  const agents = scope.agents.length ? scope.agents : reaching;
  const verdict = reachabilityVerdict(vuln);
  return (
    <div className="space-y-3">
      <div>
        <span className={`inline-flex rounded border px-2 py-0.5 text-xs font-semibold ${TONE[verdict.tone]}`}>{verdict.label}</span>
        <p className="mt-1 text-xs leading-5 text-ink-secondary">{verdict.basis}</p>
      </div>
      {agents.length || scope.servers.length ? (
        <dl className="grid gap-x-4 gap-y-2 text-sm sm:grid-cols-[auto_1fr]">
          {agents.length ? <>
            <dt className="text-ink-secondary">{scope.agents.length ? "Agents" : "Reaching agents"}</dt>
            <dd className="flex flex-wrap gap-1.5">{agents.map((agent) => <Link key={agent} href={`/agents?${new URLSearchParams({ name: agent })}`} className={chip}>{agent}</Link>)}</dd>
          </> : null}
          {scope.servers.length ? <>
            <dt className="text-ink-secondary">MCP servers</dt>
            <dd className="flex flex-wrap gap-1.5">{scope.servers.map((server) => <Link key={server} href={`/findings?${new URLSearchParams({ q: server })}`} className={chip}>{server}</Link>)}</dd>
          </> : null}
        </dl>
      ) : (
        <p className="text-sm text-ink-secondary">No agent or MCP server is recorded for this occurrence.</p>
      )}
    </div>
  );
}
