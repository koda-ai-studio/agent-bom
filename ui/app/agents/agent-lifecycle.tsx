"use client";

import { SecurityGraphInvestigation } from "@/components/security-graph-investigation";
import { PageEmptyState } from "@/components/states/page-state";
import { lifecycleInventoryView, type LifecycleView } from "@/lib/agent-lifecycle-view";
import { type AgentLifecycleResponse, api } from "@/lib/api";
import { ArrowLeft, Download, Loader2 } from "lucide-react";
import Link from "next/link";
import { useEffect, useState } from "react";


export function LifecycleFlow({ data, agentName }: { data: AgentLifecycleResponse; agentName: string }) {
  const [view, setView] = useState<LifecycleView>("servers");
  const servers = data.graph?.nodes.filter(node => node.entity_type === "server") ?? [];
  const [serverId, setServerId] = useState(servers[0]?.id ?? "");
  const selectedServer = servers.some(node => node.id === serverId) ? serverId : servers[0]?.id ?? "";
  const visible = data.graph ? lifecycleInventoryView(data.graph, view, selectedServer) : null;
  const handleExport = () => {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `${agentName}-lifecycle.json`;
    link.click();
    URL.revokeObjectURL(url);
  };
  return <div className="space-y-4 p-3 sm:p-6" data-testid="agent-lifecycle-graph">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="min-w-0">
        <Link href="/agents" className="agents-back-link"><ArrowLeft className="h-4 w-4" /> Agents</Link>
        <h1 className="mt-2 text-lg font-semibold">Configured inventory</h1>
        <p className="mb-1 break-words text-sm font-medium">{agentName}</p>
        <p className="max-w-xl text-sm text-muted">Explore packages, tools, credentials and advisories for this agent. These relationships do not prove execution or effective access.</p>
      </div>
      <button onClick={handleExport} className="agents-flow-export"><Download className="h-4 w-4" /> Export</button>
    </div>
    <div className="flex flex-wrap gap-x-5 gap-y-2 text-sm" aria-label="Unique inventory counts">
      {[["Servers", data.stats.total_servers], ["Packages", data.stats.total_packages], ["Tools", data.stats.total_tools],
        ["Credential slots", data.stats.total_credentials], ["Advisories", data.stats.total_vulnerabilities]].map(([label, count]) =>
        <span key={label}><strong>{count ?? 0}</strong> {label}</span>)}
    </div>
    <div className="flex flex-wrap items-center gap-2" aria-label="Inventory view">
      {([["servers", "Server connections"], ["packages", "Packages and advisories"], ["tools", "Tools and credentials"]] as const).map(([key, label]) =>
        <button key={key} type="button" aria-pressed={view === key} className={`graph-page-action ${view === key ? "bg-surface-elevated ring-1 ring-outline" : ""}`} onClick={() => setView(key)}>{label}</button>)}
      {view !== "servers" && <label className="flex min-w-0 max-w-full items-center gap-2 text-sm">Server
        <select aria-label="Inventory server" className="min-w-0 max-w-full rounded border border-outline bg-surface p-2"
          value={selectedServer} onChange={event => setServerId(event.target.value)}>
          {servers.map(server => <option key={server.id} value={server.id}>{server.label}{servers.filter(item => item.label === server.label).length > 1 ? ` · ${server.id.slice(-8)}` : ""}</option>)}
        </select>
      </label>}
    </div>
    {visible && <p className="text-xs text-muted" role="status">Showing {visible.nodes.length} of {data.graph!.nodes.length} loaded entities. Choose a view and server to inspect their recorded relationships; export includes the complete inventory.</p>}
    {visible ? <SecurityGraphInvestigation key={`${view}:${selectedServer}`} graph={visible} attackPath={null} focusMode={false}
      onFocusModeChange={() => {}} fullGraphHref="/graph" embedded /> :
      <PageEmptyState title="Lifecycle evidence unavailable" detail="Refresh this view against a server that provides the shared inventory graph." />}
  </div>;
}

export function AgentLifecycle({ agentName }: { agentName: string }) {
  const [data, setData] = useState<AgentLifecycleResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api
      .getAgentLifecycle(agentName)
      .then(setData)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [agentName]);

  if (loading) {
    return (
      <div className="h-screen bg-[color:var(--surface)] flex items-center justify-center">
        <Loader2 className="w-8 h-8 animate-spin text-[color:var(--text-tertiary)]" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="h-screen bg-[color:var(--surface)] p-8">
        <Link href="/agents" className="agents-back-link">
          <ArrowLeft className="w-4 h-4" /> Back to agents
        </Link>
        <div className="agents-error-panel">
          {error || "Agent not found"}
        </div>
      </div>
    );
  }

  return (
    <div className="h-[calc(100dvh-6rem)] w-full bg-[color:var(--surface)]">
      <LifecycleFlow data={data} agentName={agentName} />
    </div>
  );
}
