"use client";

import { Suspense } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { ArrowLeft } from "lucide-react";

import { AgentArchitectureView } from "@/components/agent-architecture/architecture-view";
import { useAuthState } from "@/components/auth-provider";
import { PageLoadingState } from "@/components/states/page-state";
import { useAgentArchitecture } from "@/hooks/use-agent-architecture";
import { useNarrowViewport } from "@/hooks/use-narrow-viewport";

function ArchitectureContent() {
  const scanId = useSearchParams().get("scan") || undefined;
  const { state, loadingMore, loadMore, restart } = useAgentArchitecture(scanId);
  const narrow = useNarrowViewport();
  return (
    <div className="space-y-3">
      <Link href="/agents" className="inline-flex items-center gap-1 text-xs text-ink-tertiary hover:text-foreground">
        <ArrowLeft className="h-3 w-3" aria-hidden="true" /> Agents
      </Link>
      {state === null
        ? <PageLoadingState title="Loading agent architecture" detail="Reading the multi-agent harnesses declared in this estate." />
        : <AgentArchitectureView state={state} loadingMore={loadingMore} narrow={narrow} onLoadMore={loadMore} onRestart={restart} />}
    </div>
  );
}

export default function AgentArchitecturePage() {
  const { session } = useAuthState();
  return (
    <Suspense fallback={<PageLoadingState title="Loading agent architecture" detail="Preparing the view." />}>
      <ArchitectureContent key={JSON.stringify(session)} />
    </Suspense>
  );
}
