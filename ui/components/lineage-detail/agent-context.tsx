import type { AgentContext, AgentContextGroup } from "@/lib/graph-agent-context";

function ContextGroup({ label, group }: { label: string; group: AgentContextGroup | undefined }) {
  return <section className="space-y-1.5" aria-label={label}>
    <h4 className="text-xs font-semibold text-foreground">{label}</h4>
    {!group?.items.length ? <p className="text-xs text-ink-secondary">{group?.recorded_count ? "Recorded links are unavailable in this view" : "Not recorded in this evidence"}</p> : <ul className="space-y-2">
      {group.items.map((item, index) => <li key={`${item.node_id}:${index}`} className="rounded-lg border border-outline bg-surface p-2 text-xs">
        <p className="break-words font-medium text-foreground">{item.label}</p>
        {(item.provider || item.service) && <p className="text-ink-secondary">{[item.provider, item.service].filter(Boolean).join(" · ")}</p>}
        {(item.account_id || item.region) && <p className="break-words text-ink-secondary">Scope: {[item.account_id, item.region].filter(Boolean).join(" · ")}</p>}
        <p className="break-words text-ink-secondary">{item.relationship.replaceAll("_", " ")} · {item.evidence_kind.replaceAll("_", " ")} · {item.source}</p>
        {item.last_seen && <p className="text-ink-secondary">Observed: {item.last_seen}</p>}
      </li>)}
    </ul>}
    {group?.truncated && <p className="text-xs text-ink-secondary">Showing {group.items.length} of {group.recorded_count} recorded links.</p>}
  </section>;
}

export function AgentContextDetails({ context }: { context: AgentContext | undefined }) {
  return <div className="space-y-4 rounded-xl border border-outline bg-surface-elevated p-3" aria-label="Agent execution and model context">
    <p className="text-xs text-ink-secondary">Membership does not establish where an agent executes or which model endpoint it calls.</p>
    <ContextGroup label="Platform association" group={context?.platforms} />
    <ContextGroup label="Execution host" group={context?.execution} />
    <p className="text-xs text-ink-secondary">A recorded host association does not prove runtime execution.</p>
    <ContextGroup label="Model links" group={context?.models} />
    <p className="text-xs text-ink-secondary">A model link alone does not verify an endpoint, model publisher or runtime invocation.</p>
    <ContextGroup label="Environment membership" group={context?.membership} />
    <p className="text-xs text-ink-secondary">{context?.basis === "snapshot" ? "Direct relationships retained in this snapshot." : "Direct relationships in the loaded graph; additional evidence may be outside this view."}</p>
  </div>;
}
