"use client";

import { Loader2 } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { lazy, Suspense } from "react";
const AgentDetail = lazy(() => import("./agent-detail").then((module) => ({ default: module.AgentDetail })));
const AgentLifecycle = lazy(() => import("./agent-lifecycle").then((module) => ({ default: module.AgentLifecycle })));
import { AgentsList } from "./agents-list";

function AgentsRouter() {
  const searchParams = useSearchParams();
  const name = searchParams.get("name") || "";
  const view = searchParams.get("view") || "";

  if (name && view === "lifecycle") {
    return <AgentLifecycle agentName={name} />;
  }

  if (name) {
    return <AgentDetail agentName={name} />;
  }

  return <AgentsList />;
}

export default function AgentsPage() {
  return (
    <Suspense fallback={<div className="flex items-center justify-center min-h-screen"><Loader2 className="w-8 h-8 animate-spin text-[color:var(--text-tertiary)]" /></div>}>
      <AgentsRouter />
    </Suspense>
  );
}


