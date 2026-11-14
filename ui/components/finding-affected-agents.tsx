import type { MouseEvent } from "react";

import { ASSET_BASE } from "@/lib/asset-base";
import { agentDisplayName } from "@/lib/display-name";

const VISIBLE_AGENTS = 2;
const ADVISORY_ID = /^(CVE|GHSA|OSV|PYSEC|RUSTSEC|GO|MAL)-/i;
const LINK_CLASS = "underline decoration-dotted underline-offset-2 transition hover:text-foreground";

/**
 * The first agents a finding affects plus an explicit remainder. Items are
 * list entries spaced by the flex gap, so a wrapped line never opens on a
 * separator. The remainder counts every affected agent the API returned.
 */
export function FindingAffectedAgents({ findingId, agents, onOpenFinding }: {
  findingId: string;
  agents: string[];
  onOpenFinding: () => void;
}) {
  const visible = agents.slice(0, VISIBLE_AGENTS);
  const remaining = agents.length - visible.length;
  const stop = (event: MouseEvent) => event.stopPropagation();
  const allLabel = `All ${agents.length} affected agents for ${findingId}`;
  return (
    <ul data-testid="finding-affected-agents" className="flex flex-wrap gap-x-2 gap-y-0.5 text-ink-tertiary">
      {visible.map((agent) => (
        <li key={agent} className="min-w-0 [overflow-wrap:anywhere]">
          <a href={`${ASSET_BASE}/findings?q=${encodeURIComponent(agent)}`} onClick={stop} title={agent} className={LINK_CLASS}>
            {agentDisplayName(agent)}
          </a>
        </li>
      ))}
      {remaining > 0 ? (
        <li>
          {ADVISORY_ID.test(findingId) ? (
            <a href={`${ASSET_BASE}/advisories?id=${encodeURIComponent(findingId)}`} onClick={stop} aria-label={allLabel} title={allLabel}
              className={`font-medium text-ink-secondary ${LINK_CLASS}`}>
              {`+${remaining} more`}
            </a>
          ) : (
            <button type="button" onClick={(event) => { stop(event); onOpenFinding(); }} aria-label={allLabel} title={allLabel}
              className={`font-medium text-ink-secondary ${LINK_CLASS}`}>
              {`+${remaining} more`}
            </button>
          )}
        </li>
      ) : null}
    </ul>
  );
}
