"use client";
import Link from "next/link";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import { type ExecutiveBrief, briefMarkdown, saveBriefArtifact } from "@/lib/executive-brief";
import { useAuthState } from "@/components/auth-provider";
import { Card } from "@/components/card";
import { PanelButton } from "@/components/integrations/panel-kit";
import { BriefPriorities, BriefPaths, BriefControlsAndHistory } from "./sections";
import { BriefEvidence } from "./evidence";
import { BriefSummary } from "./summary";

function BriefContent() {
  const [brief, setBrief] = useState<ExecutiveBrief | null>(null);
  const [error, setError] = useState(false);
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    let active = true;
    const controller = new AbortController();
    void api.getExecutiveBrief(controller.signal).then(result => { if (active) setBrief(result); }, () => { if (active) setError(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [revision]);
  function refresh() { setBrief(null); setError(false); setLoading(true); setRevision(value => value + 1); }
  return <div className="space-y-5">
    <header className="flex flex-wrap items-start justify-between gap-3">
      <div><p className="text-xs uppercase tracking-wider text-ink-tertiary">Leadership evidence</p><h1 className="mt-1 text-2xl font-semibold">Executive brief</h1></div>
      <div className="flex flex-wrap items-center gap-3"><Link href="/" className="text-sm underline">Overview</Link><PanelButton onClick={refresh} disabled={loading}>Refresh brief</PanelButton></div>
    </header>
    <p className="max-w-4xl text-sm leading-6 text-ink-secondary">Where risk stands, what changed, and what needs an owner.</p>
    {loading ? <p role="status">Loading authenticated brief…</p> : null}
    {error ? <Card><p role="alert">Brief unavailable. Sign in with access to this tenant&apos;s brief, or retry when the control plane is available.</p></Card> : null}
    {brief ? <>
      <div className="flex flex-wrap justify-end gap-2">
        <PanelButton onClick={() => saveBriefArtifact(new Blob([briefMarkdown(brief)], { type: "text/markdown;charset=utf-8" }), "executive-brief.md")}>Download Markdown</PanelButton>
        <PanelButton onClick={() => saveBriefArtifact(new Blob([JSON.stringify(brief, null, 2) + "\n"], { type: "application/json" }), "executive-brief.json")}>Download JSON</PanelButton>
      </div>
      <BriefSummary brief={brief} />
      <div className="grid items-start gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <div className="min-w-0 space-y-5"><BriefPriorities brief={brief} /><BriefPaths brief={brief} /></div>
        <BriefControlsAndHistory brief={brief} />
      </div>
      <details className="rounded-xl border border-outline p-4"><summary className="cursor-pointer text-sm font-medium">Source scope and read consistency</summary><pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-words text-xs leading-6">{JSON.stringify(brief.scope, null, 2)}</pre></details>
      <BriefEvidence sample={brief.sample_data} />
    </> : null}
  </div>;
}

export function ExecutiveBriefPanel() {
  const { session } = useAuthState();
  return <BriefContent key={JSON.stringify(session)} />;
}
