"use client";

import type { InvestigationFlow, ReadingFlow, SpecificFlow } from "@/lib/graph-investigation-flow";

const FLOW_NAMES: Record<SpecificFlow, string> = { exposure: "Exposure", identity: "Identity and access", vulnerability: "Vulnerability", inventory: "Inventory" };
const ABSENT: Record<SpecificFlow, string> = { exposure: "no external entry", identity: "no identities", vulnerability: "no findings", inventory: "no containment" };
const FLOWS = Object.keys(FLOW_NAMES) as SpecificFlow[];

export function automaticFlowLabel({ applied, scenario, preview }: { applied: boolean; scenario: ReadingFlow; preview: boolean }) {
  return `Automatic · ${preview ? "connection preview" : !applied ? "current layout" : scenario === "connections" ? "Connections" : FLOW_NAMES[scenario]}`;
}

/** The control never pretends: a flow that cannot apply is disabled, with the reason on screen. */
export function GraphFlowControl({ value, automaticLabel, available, disabledReason, note, compact = false, onChange }: {
  value: InvestigationFlow;
  automaticLabel: string;
  available: Record<SpecificFlow, boolean>;
  disabledReason?: string | undefined;
  note?: string | undefined;
  /** A phone's narrow row: the combobox's own name and options say what it is. */
  compact?: boolean;
  onChange: (flow: InvestigationFlow) => void;
}) {
  // On a phone's narrow row a standing reason moves to Graph options; a just-chosen flow's note stays with it.
  const message = compact ? note : disabledReason ?? note;
  return <div data-testid="graph-flow-control" title={disabledReason} className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
    <label className="flex items-center gap-2"><span className={compact ? "sr-only" : undefined}>Flow</span>
      <select aria-label="Investigation flow" title={compact && value === "auto" ? automaticLabel : undefined} value={value} disabled={Boolean(disabledReason)} onChange={event => onChange(event.target.value as InvestigationFlow)}
        className={`rounded-md border border-outline bg-background px-2 py-1 text-foreground disabled:opacity-60 ${compact ? "min-h-11 w-[8.5rem]" : ""}`}>
        <option value="auto">{compact ? "Automatic" : automaticLabel}</option>
        {FLOWS.map(flow => <option key={flow} value={flow} disabled={!available[flow]}>{FLOW_NAMES[flow]}{available[flow] ? "" : ` (${ABSENT[flow]})`}</option>)}
      </select>
    </label>
    {message && <span role="status" data-testid="graph-flow-status" className="min-w-0 text-ink-secondary">{message}</span>}
  </div>;
}
