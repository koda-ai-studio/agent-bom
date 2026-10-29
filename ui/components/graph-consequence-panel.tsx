"use client";

import { useEffect, useRef, useState } from "react";
import { useAuthState } from "@/components/auth-provider";
import { GraphConsequenceResults } from "@/components/graph-consequence-results";
import { api } from "@/lib/api";
import type { GraphConsequenceResponse } from "@/lib/api-types";

type Props = {
  nodeId: string; scanId: string; snapshotGeneration?: string | null | undefined;
  findingRoot?: boolean; affectedNodeIds?: string[] | undefined;
};

export function GraphConsequencePanel(props: Props) {
  const { session, loading } = useAuthState();
  if (loading || !session) return null;
  return <ConsequenceForm key={JSON.stringify([session, props.nodeId, props.scanId, props.snapshotGeneration])} {...props} />;
}

function ConsequenceForm({ nodeId, scanId, snapshotGeneration, findingRoot = false, affectedNodeIds = [] }: Props) {
  const [control, setControl] = useState(false);
  const [affected, setAffected] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);
  const [result, setResult] = useState<GraphConsequenceResponse | null>(null);
  const abort = useRef<AbortController | null>(null);
  useEffect(() => () => abort.current?.abort(), []);
  async function assess() {
    abort.current?.abort();
    const controller = new AbortController(); abort.current = controller;
    setPending(true); setError(false); setResult(null);
    try {
      const response = await api.assessConsequences({
        root_node_id: nodeId, scan_id: scanId, snapshot_generation: snapshotGeneration ?? null,
        mode: findingRoot ? "vulnerability" : "assumed_compromise", assume_control: !findingRoot && control,
        affected_node_id: findingRoot ? affected : null, max_depth: 6, max_states: 256,
        max_results: 128, max_evidence_age_seconds: 3600,
      }, { signal: controller.signal });
      if (!controller.signal.aborted) setResult(response);
    } catch {
      if (!controller.signal.aborted) setError(true);
    } finally {
      if (!controller.signal.aborted) setPending(false);
    }
  }
  return <details className="rounded-lg border border-outline bg-surface-muted p-3 text-xs text-ink-secondary">
    <summary className="cursor-pointer font-semibold text-ink">Investigate consequences · experimental</summary>
    <p className="mt-2">{findingRoot ? "Vulnerability: check this affected asset's prerequisites before tracing authority." : "Assume compromised agent or principal: inspect potential actions, resources and stopping controls."}</p>
    <form className="my-3 space-y-3" onSubmit={event => { event.preventDefault(); void assess(); }}>
      {findingRoot ? <label className="block">Affected asset
        <select disabled={pending} className="mt-1 w-full min-w-0 rounded border border-outline bg-surface p-2 text-ink" value={affected} onChange={event => { setAffected(event.target.value); setResult(null); }}>
          <option value="">Select a linked component</option>
          {affectedNodeIds.map(id => <option key={id} value={id}>{id}</option>)}
        </select>
        {affectedNodeIds.length === 0 && <span className="mt-1 block">No linked affected asset loaded. Expand the finding evidence first.</span>}
      </label> : <label className="flex items-start gap-2"><input disabled={pending} type="checkbox" checked={control} onChange={event => { setControl(event.target.checked); setResult(null); }} />Assume control of this agent or principal</label>}
      <button type="submit" className="rounded border border-outline bg-surface px-3 py-2 font-medium text-ink disabled:opacity-50" disabled={pending || (findingRoot ? !affectedNodeIds.includes(affected) : !control)}>{pending ? "Assessing…" : "Trace consequences"}</button>
    </form>
    {error && <p role="alert">Assessment unavailable. Reload the graph and verify the selected snapshot and assumptions.</p>}
    {result && <GraphConsequenceResults result={result} />}
  </details>;
}
