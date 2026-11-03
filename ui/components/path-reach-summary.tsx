import Link from "next/link";
import { KeyRound, Wrench } from "lucide-react";

import { buildGraphInvestigationHref } from "@/lib/attack-paths";
import type { AttackPath } from "@/lib/graph-schema";

const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? "" : "s"}`;

/** Metadata is reported context, never an inferred continuation of the path. */
export function PathReachSummary({ path, scanId }: { path: AttackPath; scanId: string }) {
  const credentials = path.credential_exposure ?? [];
  const tools = path.tool_exposure ?? [];
  if (credentials.length === 0 && tools.length === 0) return null;
  const server = path.hops.find((hop) => hop.startsWith("server:"));
  const chip = "inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs";
  return (
    <section aria-label="Reported path exposure" className="rounded-lg border border-outline bg-surface px-3 py-2 text-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="font-medium text-foreground">Reported exposure <span className="font-normal text-ink-secondary">· {plural(credentials.length, "credential")} · {plural(tools.length, "tool")}</span></p>
        {server ? (
          <Link prefetch={false} className="text-xs font-medium text-accent-mint hover:underline"
            href={buildGraphInvestigationHref({ rootId: server, scanId: scanId || undefined, direction: "forward", depth: 2 })}>
            Show what the server reaches
          </Link>
        ) : null}
      </div>
      <p className="mt-1 text-xs text-ink-secondary">References only; inspect recorded relationships to establish a connection.</p>
      <div className="mt-2 flex flex-wrap gap-1.5">
        {credentials.map((name) => <span key={`c:${name}`} className={`${chip} border-amber-500/40 bg-amber-500/10 font-mono text-amber-900 dark:text-amber-200`}><KeyRound className="h-3 w-3" aria-hidden="true" />{name}</span>)}
        {tools.map((name) => <span key={`t:${name}`} className={`${chip} border-violet-500/40 bg-violet-500/10 text-violet-900 dark:text-violet-200`}><Wrench className="h-3 w-3" aria-hidden="true" />{name}</span>)}
      </div>
    </section>
  );
}
