"use client";

import { GraphPathImpact } from "@/components/graph-path-impact";
import { InvestigationStepStrip, type InvestigationStep } from "@/components/investigation-step-strip";
import { PathOwnerPanel } from "@/components/path-owner-panel";
import { packageRemediationHref } from "@/lib/investigation-step-links";
import type { AttackPath, UnifiedNode } from "@/lib/graph-schema";

/**
 * The Path → Impact → Owner → Fix → Verify strip and the in-page panel for the
 * active step. Owner and Impact answer in place; Fix and Verify continue on
 * remediation, scoped to the selected path's package.
 */
export function InvestigationLifecycle({ step, onStepChange, completed, path, nodeById, scanId, tenantId, snapshotGeneration, pinnedNodeId }: {
  step: InvestigationStep;
  onStepChange: (next: InvestigationStep) => void;
  completed: Partial<Record<InvestigationStep, boolean>>;
  path: AttackPath | null;
  nodeById: Map<string, UnifiedNode>;
  scanId: string;
  tenantId: string | undefined;
  snapshotGeneration: string | null | undefined;
  pinnedNodeId: string | null;
}) {
  const nodes = path ? path.hops.map((id) => nodeById.get(id)).filter((node): node is UnifiedNode => Boolean(node)) : [];
  const packageNode = nodes.find((node) => node.entity_type === "package");
  const impactRoot = nodes.find((node) => node.entity_type === "vulnerability" || node.entity_type === "misconfiguration")
    ?? (path ? nodeById.get(path.target) : undefined);
  const cve = path?.vuln_ids[0];
  const historical = scanId && !scanId.startsWith("current-estate:") ? `?scan=${encodeURIComponent(scanId)}` : "";
  return (
    <>
      <div className="flex flex-wrap items-center justify-between gap-3 [&_nav]:relative [&_nav]:max-w-full [&_nav]:overflow-x-auto [&_ol]:flex-nowrap [&_li]:shrink-0">
        <InvestigationStepStrip
          step={step}
          onStepChange={onStepChange}
          completed={completed}
          stepHrefs={{ fix: packageRemediationHref(packageNode?.label, scanId), verify: `/remediation${historical}#verification` }}
        />
        {pinnedNodeId ? <span className="text-xs text-[color:var(--text-tertiary)]">Pinned {pinnedNodeId.slice(0, 12)}…</span> : null}
      </div>
      {step === "impact" && impactRoot && scanId && tenantId ? (
        <GraphPathImpact
          key={JSON.stringify([scanId, impactRoot.id, snapshotGeneration])}
          nodeId={impactRoot.id} label={impactRoot.label} scanId={scanId}
          tenantId={tenantId} snapshotGeneration={snapshotGeneration}
        />
      ) : null}
      {step === "owner" && path && cve ? (
        <PathOwnerPanel cve={cve} hops={path.hops} packageLabel={packageNode?.label} scanId={scanId} />
      ) : null}
      {step === "owner" && path && !cve ? (
        <p role="status" className="rounded-xl border border-outline bg-surface p-4 text-sm text-ink-secondary">This path carries no advisory, so no finding owner or SLA applies.</p>
      ) : null}
    </>
  );
}
