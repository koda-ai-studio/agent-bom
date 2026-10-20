import Link from "next/link";
import { KeyRound, Wrench } from "lucide-react";

import { buildGraphInvestigationHref } from "@/lib/attack-paths";
import type { AttackPath } from "@/lib/graph-schema";

const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

/**
 * What the path reaches beyond its hops: the credentials and tools exposed by
 * its server. The path ends at the advisory; these are what an attacker on it
 * would hold next.
 */
export function PathReachSummary({ path, scanId }: { path: AttackPath; scanId: string }) {
  const credentials = path.credential_exposure ?? [];
  const tools = path.tool_exposure ?? [];
  if (credentials.length === 0 && tools.length === 0) return null;
  const server = path.hops.find((hop) => hop.startsWith("server:"));
  const chip = "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs";
  return (
    <section aria-label="Reached from this path" className="rounded-lg border border-outline bg-surface px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-medium text-foreground">Reached from this path <span className="font-normal text-ink-secondary">· {plural(credentials.length, "credential")} · {plural(tools.length, "tool")}</span></p>
        {server ? (
          <Link className="text-xs font-medium text-accent-mint hover:underline"
            href={buildGraphInvestigationHref({ rootId: server, scanId: scanId || undefined, direction: "forward", depth: 2 })}>
            Show what the server reaches
          </Link>
        ) : null}
      </div>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {credentials.map((name) => <span key={`c:${name}`} className={`${chip} border-amber-500/40 bg-amber-500/10 font-mono text-amber-900 dark:text-amber-200`}><KeyRound className="h-3 w-3" aria-hidden="true" />{name}</span>)}
        {tools.map((name) => <span key={`t:${name}`} className={`${chip} border-violet-500/40 bg-violet-500/10 text-violet-900 dark:text-violet-200`}><Wrench className="h-3 w-3" aria-hidden="true" />{name}</span>)}
      </div>
    </section>
  );
}
