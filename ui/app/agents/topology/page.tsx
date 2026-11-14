"use client";

/**
 * Agent trust mesh — MCP topology for engineers.
 * Kept off Overview (exec briefing); linked from Agents and Overview CTAs.
 */

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";

import { api, type Agent } from "@/lib/api";
import { AgentTopology } from "@/components/agent-topology";
import { useAuthState } from "@/components/auth-provider";
import { PageEmptyState, PageErrorState, PageLoadingState } from "@/components/states/page-state";
import { TOPOLOGY_AGENT_LIMIT } from "../agents-list-state";

export default function AgentTopologyPage() {
  const { session } = useAuthState();
  const [agents, setAgents] = useState<Agent[] | null>(null);
  const [sourceScope, setSourceScope] = useState<string>();
  const [total, setTotal] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    api
      .listAgents({ limit: TOPOLOGY_AGENT_LIMIT }, controller.signal)
      .then((res) => {
        if (controller.signal.aborted) return;
        const page = Array.isArray(res?.agents) ? res.agents : [];
        setAgents(page);
        setTotal(typeof res?.total === "number" ? res.total : page.length);
        setSourceScope(res.scope);
      })
      .catch((err: unknown) => {
        if (!controller.signal.aborted) setError(err instanceof Error ? err.message : "Failed to load agents");
      });
    return () => controller.abort();
  }, []);

  if (error) {
    return <PageErrorState title="Could not load agent topology" detail={error} />;
  }
  if (agents == null) {
    return (
      <PageLoadingState
        title="Loading agent topology"
        detail="Loading configured agent-to-service relationships."
      />
    );
  }
  if (agents.length === 0) {
    return (
      <PageEmptyState
        title="No agent configurations to map"
        detail="This view reads client configuration on the API host. Scanned-estate evidence is available in Asset Inventory."
        actions={[{ label: "Open asset inventory", href: "/inventory", variant: "primary" }]}
      />
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <Link
            href="/agents"
            className="mb-2 inline-flex items-center gap-1 text-xs text-[color:var(--text-tertiary)] hover:text-[color:var(--foreground)]"
          >
            <ArrowLeft className="h-3 w-3" /> Agents
          </Link>
          <h1 className="text-lg font-semibold text-[color:var(--foreground)]">Agent topology</h1>
          <p className="mt-1 max-w-2xl text-sm text-[color:var(--text-secondary)]">
            Explore configured agent-to-service relationships, review attention signals, and inspect the underlying inventory.
          </p>
        </div>
        <Link
          href="/context"
          className="text-xs text-emerald-500 hover:text-emerald-400"
        >
          Context map →
        </Link>
      </div>
      {total != null && total > agents.length ? (
        <p
          className="rounded-lg border border-[color:var(--border-subtle)] bg-[color:var(--surface-muted)] px-3 py-2 text-xs text-[color:var(--text-secondary)]"
          data-testid="topology-truncated"
        >
          Showing {agents.length.toLocaleString()} of {total.toLocaleString()} agents in this map. Search and filter the{" "}
          <Link href="/agents" className="underline">Agents list</Link> to reach the rest.
        </p>
      ) : null}
      <AgentTopology agents={agents} session={session} sourceScope={sourceScope} />
    </div>
  );
}
