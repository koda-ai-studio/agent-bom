"use client";

import { useEffect, useRef } from "react";
import { ArrowRight, X } from "lucide-react";
import type { GraphRollupContainer } from "@/lib/api-types";
import { Drawer } from "@/components/drawer";
import { scopeTypeLabel } from "@/components/graph-scope-node";

export function GraphScopeDetail({ item, onClose, onOpenScope, onInspectRelationships, scanId, docked }: {
  item: GraphRollupContainer; onClose: () => void; onOpenScope?: (() => void) | undefined;
  onInspectRelationships?: (() => void) | undefined; scanId?: string | undefined; docked: boolean;
}) {
  const close = useRef(onClose);
  close.current = onClose;
  const closeButton = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!docked) return;
    const previous = document.activeElement;
    closeButton.current?.focus({ preventScroll: true });
    const escape = (event: KeyboardEvent) => { if (event.key === "Escape") close.current(); };
    document.addEventListener("keydown", escape);
    return () => {
      document.removeEventListener("keydown", escape);
      if ((previous instanceof HTMLElement || previous instanceof SVGElement) && previous.isConnected) previous.focus({ preventScroll: true });
    };
  }, [docked, item.id]);
  const aggregate = item.aggregate;
  const body = <div className="space-y-5 text-sm">
    <p className="text-xs leading-5 text-ink-secondary">Summary of entities contained in this scope. Open the scope to inspect their individual relationships and evidence.</p>
    <div className="grid grid-cols-2 gap-3 rounded-lg border border-outline bg-surface-muted p-3">
      <div><p className="text-xl font-semibold tabular-nums">{aggregate?.descendant_count.toLocaleString() ?? "—"}</p><p className="mt-1 text-xs text-ink-secondary">Contained entities</p></div>
      <div><p className="text-xl font-semibold tabular-nums">{item.direct_child_count.toLocaleString()}</p><p className="mt-1 text-xs text-ink-secondary">Direct children</p></div>
    </div>
    <section aria-label="Scope composition"><h4 className="mb-2 text-xs font-semibold text-ink-secondary">Entity types</h4>
      <dl className="space-y-2">{Object.entries(aggregate?.by_type ?? {}).sort((a, b) => b[1] - a[1]).map(([type, count]) => <div key={type} className="flex justify-between gap-3"><dt>{scopeTypeLabel(type)}</dt><dd className="tabular-nums">{count.toLocaleString()}</dd></div>)}</dl>
    </section>
    <section aria-label="Recorded severity"><h4 className="mb-2 text-xs font-semibold text-ink-secondary">Severity of contained entities</h4>
      <div className="flex flex-wrap gap-2">{Object.entries(aggregate?.severity_counts ?? {}).map(([severity, count]) => <span key={severity} className="rounded-md border border-outline px-2 py-1 text-xs">{severity === "none" ? "No severity" : scopeTypeLabel(severity)} <strong className="ml-1 tabular-nums">{count.toLocaleString()}</strong></span>)}</div>
      {!!aggregate?.exposed_count && <p className="mt-3 text-xs text-ink-secondary">{aggregate.exposed_count.toLocaleString()} entities recorded as internet exposed.</p>}
      {!!aggregate?.toxic_count && <p className="mt-2 text-xs text-ink-secondary">{aggregate.toxic_count.toLocaleString()} entities with compound risk signals.</p>}
    </section>
    <p className="text-xs leading-5 text-ink-secondary">Counts describe this graph snapshot and inherit its collection limits. They do not establish successful access or current runtime activity.</p>
    {onInspectRelationships && <button type="button" onClick={onInspectRelationships} className="text-xs text-foreground underline underline-offset-4">Inspect scope relationships</button>}
    <details className="text-xs text-ink-secondary"><summary className="cursor-pointer">Snapshot and identifier</summary><dl className="mt-2 space-y-1 [overflow-wrap:anywhere]"><dt>Snapshot</dt><dd>{scanId || "Not recorded"}</dd><dt>Scope</dt><dd>{item.id}</dd></dl></details>
  </div>;
  const footer = onOpenScope && <button type="button" onClick={onOpenScope} className="flex w-full items-center justify-between rounded-lg bg-foreground px-4 py-3 text-sm font-medium text-background">Explore scope<ArrowRight className="h-4 w-4" aria-hidden="true" /></button>;
  if (!docked) return <Drawer open onClose={onClose} title={item.label} eyebrow={`${scopeTypeLabel(item.entity_type)} · scope`} ariaLabel="Scope details" closeLabel="Close scope details" footer={footer} size="md">{body}</Drawer>;
  return <aside aria-label="Scope details" data-testid="graph-entity-drawer" className="flex w-[min(20rem,32vw)] shrink-0 flex-col border-l border-outline bg-surface text-foreground">
    <header className="flex items-start justify-between gap-3 border-b border-outline p-4"><div className="min-w-0"><p className="mb-1 text-xs text-ink-secondary">{scopeTypeLabel(item.entity_type)} · scope</p><h3 className="text-base font-semibold [overflow-wrap:anywhere]">{item.label}</h3></div><button ref={closeButton} type="button" onClick={onClose} aria-label="Close scope details" className="shrink-0 rounded p-1 hover:bg-surface-muted"><X className="h-4 w-4" /></button></header>
    <div className="min-h-0 flex-1 overflow-y-auto p-4">{body}</div>
    {footer && <footer className="border-t border-outline p-3">{footer}</footer>}
  </aside>;
}
