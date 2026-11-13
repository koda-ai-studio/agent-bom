"use client";

import { Workflow } from "lucide-react";
import { useCallback, useMemo, useState } from "react";

import { ArchitectureCanvas } from "@/components/agent-architecture/architecture-canvas";
import { ArchitectureDetail } from "@/components/agent-architecture/architecture-detail";
import { ArchitectureLegend } from "@/components/agent-architecture/architecture-legend";
import { CoverageNote, HarnessNotes } from "@/components/agent-architecture/architecture-notes";
import { ArchitectureSteps } from "@/components/agent-architecture/architecture-steps";
import { HarnessList } from "@/components/agent-architecture/harness-list";
import { PageEmptyState, PageErrorState } from "@/components/states/page-state";
import { buildArchitectureModel, frameworkLabel, type ArchitectureMode } from "@/lib/agent-architecture-model";
import type { ArchitecturePagesState } from "@/lib/agent-architecture-pages";
import type { AgentHarness } from "@/lib/agent-architecture-types";

type Props = {
  state: ArchitecturePagesState;
  loadingMore: boolean;
  /** Phones read the harness as a single column of steps. */
  narrow: boolean;
  onLoadMore: () => void;
  onRestart: () => void;
  initialHarnessId?: string | undefined;
};

const MODES: { id: ArchitectureMode; label: string }[] = [{ id: "layered", label: "Layered" }, { id: "flow", label: "Flow" }];

function ModeToggle({ mode, onChange }: { mode: ArchitectureMode; onChange: (mode: ArchitectureMode) => void }) {
  return (
    <div role="group" aria-label="Layout" className="inline-flex rounded-lg border border-outline bg-surface p-0.5">
      {MODES.map(item => (
        <button key={item.id} type="button" aria-pressed={mode === item.id} onClick={() => onChange(item.id)}
          className={`rounded-md px-3 py-1 text-sm font-medium focus-visible:outline-2 focus-visible:outline-[color:var(--focus-ring)] ${mode === item.id ? "bg-surface-elevated text-foreground shadow-sm" : "text-ink-secondary hover:text-foreground"}`}>
          {item.label}
        </button>
      ))}
    </div>
  );
}

function HarnessPanel({ harness, narrow, scanId }: { harness: AgentHarness; narrow: boolean; scanId: string }) {
  const [mode, setMode] = useState<ArchitectureMode>("layered");
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  const model = useMemo(() => buildArchitectureModel(harness, { mode, expanded }), [expanded, harness, mode]);
  const onExpand = useCallback((id: string) => setExpanded(current => new Set([...current, id])), []);
  const onOpen = useCallback((id: string) => setSelected(id), []);
  const node = model.nodes.find(item => item.id === selected) ?? null;
  return (
    <section aria-label={`Harness ${harness.label}`} className="min-w-0 overflow-hidden rounded-2xl border border-outline bg-surface">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-outline px-4 py-3">
        <div className="min-w-0">
          <h2 className="truncate text-base font-semibold text-foreground">{harness.label}</h2>
          <p className="truncate text-xs text-ink-secondary">
            {harness.harness_kind} · {frameworkLabel(harness.framework)} · {harness.agent_count} agents in {harness.layer_count} layers
            {harness.models.length ? ` · models ${harness.models.join(", ")}` : ""}
          </p>
        </div>
        <ModeToggle mode={mode} onChange={setMode} />
      </header>
      <HarnessNotes harness={harness} model={model} />
      {narrow
        ? <ArchitectureSteps model={model} onOpen={onOpen} onExpand={onExpand} />
        : <ArchitectureCanvas model={model} onOpen={onOpen} onExpand={onExpand} />}
      <ArchitectureLegend model={model} lines={!narrow} />
      <ArchitectureDetail node={node} model={model} scanId={scanId} onClose={() => setSelected(null)}
        onExpand={id => { onExpand(id); setSelected(null); }} />
    </section>
  );
}

function Alerts({ state, onRestart }: Pick<Props, "state" | "onRestart">) {
  return <>
    {state.notice && <p role="status" className="rounded-lg border border-outline bg-surface-elevated px-3 py-2 text-sm text-foreground">{state.notice}</p>}
    {state.status === "error" && (
      <div role="alert" className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[color:var(--status-danger-border)] bg-[color:var(--status-danger-bg)] px-3 py-2 text-sm text-foreground">
        <span>{state.errorKind === "cursor" ? "The next page could not be read: " : "Harnesses could not be loaded: "}{state.error}</span>
        <button type="button" onClick={onRestart} className="rounded-md border border-outline bg-surface px-3 py-1 font-medium hover:bg-surface-muted">Start over</button>
      </div>
    )}
  </>;
}

/**
 * Agent architecture: each multi-agent harness declared in source as a
 * layered map or a flow, with findings on the agents they affect.
 */
export function AgentArchitectureView({ state, loadingMore, narrow, onLoadMore, onRestart, initialHarnessId }: Props) {
  const [chosen, setChosen] = useState<string | undefined>(initialHarnessId);
  const page = state.page;
  const harness = state.harnesses.find(item => item.harness_id === chosen) ?? state.harnesses[0];
  if (!page && state.status === "error") {
    return <PageErrorState title="Could not load the agent architecture" detail={state.error ?? "The request failed."} actions={[{ label: "Try again", onClick: onRestart, variant: "primary" }]} />;
  }
  const summary = page?.summary;
  return (
    <div className="space-y-4">
      <header className="space-y-1">
        <h1 className="flex items-center gap-2 text-2xl font-semibold tracking-tight text-foreground"><Workflow className="h-6 w-6" aria-hidden="true" />Agent architecture</h1>
        <p className="text-sm text-ink-secondary">
          Multi-agent harnesses declared in source: who orchestrates whom, how a request flows, and which agents carry findings.
          {summary ? ` ${summary.harnesses} ${summary.harnesses === 1 ? "harness" : "harnesses"}, ${summary.placed_agents} agents placed${summary.unplaced_framework_agents ? `, ${summary.unplaced_framework_agents} framework ${summary.unplaced_framework_agents === 1 ? "agent" : "agents"} with no declared delegation` : ""}.` : ""}
        </p>
        <p className="text-xs text-ink-tertiary">Edges are declared in source code. Observed runtime paths are not available yet, so none are drawn.</p>
      </header>
      <Alerts state={state} onRestart={onRestart} />
      {page && <CoverageNote coverage={page.coverage} />}
      {state.harnesses.length === 0 && state.status === "ready" ? (
        <PageEmptyState title="No multi-agent harnesses in this estate"
          detail={`A harness appears when a scan finds framework agents that delegate to each other (${page?.coverage.frameworks_modelled.map(frameworkLabel).join(", ") || "supported frameworks"}). Agents with no declared delegation stay in the agent inventory.`}
          actions={[{ label: "Run a scan", href: "/scan", variant: "primary" }, { label: "Open agents", href: "/agents" }]} />
      ) : harness ? (
        <div className="space-y-3">
          <HarnessList harnesses={state.harnesses} selectedId={harness.harness_id} total={state.total} hasMore={state.hasMore}
            loadingMore={loadingMore} onSelect={setChosen} onLoadMore={onLoadMore} />
          <HarnessPanel key={harness.harness_id} harness={harness} narrow={narrow} scanId={page?.scan_id ?? ""} />
        </div>
      ) : null}
    </div>
  );
}
