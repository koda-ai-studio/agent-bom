"use client";

import type { InvestigationFlow, SpecificFlow } from "@/lib/graph-investigation-flow";

const FLOW_NAMES: Record<SpecificFlow, string> = { exposure: "Exposure", identity: "Identity and access", vulnerability: "Vulnerability", inventory: "Inventory" };
const ABSENT: Record<SpecificFlow, string> = { exposure: "no external entry", identity: "no identities", vulnerability: "no findings", inventory: "no containment" };
const FLOWS = Object.keys(FLOW_NAMES) as SpecificFlow[];

export function automaticFlowLabel({ applied, scenario, preview }: { applied: boolean; scenario: SpecificFlow; preview: boolean }) {
  return `Automatic · ${preview ? "connection preview" : applied ? FLOW_NAMES[scenario] : "current layout"}`;
}

/** The control never pretends: a flow that cannot apply is disabled, with the reason on screen. */
export function GraphFlowControl({ value, automaticLabel, available, disabledReason, note, onChange }: {
  value: InvestigationFlow;
  automaticLabel: string;
  available: Record<SpecificFlow, boolean>;
  disabledReason?: string | undefined;
  note?: string | undefined;
  onChange: (flow: InvestigationFlow) => void;
}) {
  const message = disabledReason ?? note;
  return <div data-testid="graph-flow-control" className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
    <label className="flex items-center gap-2">Flow
      <select aria-label="Investigation flow" value={value} disabled={Boolean(disabledReason)} onChange={event => onChange(event.target.value as InvestigationFlow)}
        className="rounded-md border border-outline bg-background px-2 py-1 text-foreground disabled:opacity-60">
        <option value="auto">{automaticLabel}</option>
        {FLOWS.map(flow => <option key={flow} value={flow} disabled={!available[flow]}>{FLOW_NAMES[flow]}{available[flow] ? "" : ` (${ABSENT[flow]})`}</option>)}
      </select>
    </label>
    {message && <span role="status" data-testid="graph-flow-status" className="min-w-0 text-ink-secondary">{message}</span>}
  </div>;
}
